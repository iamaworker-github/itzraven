"""
Base Agent class for all security testing agents
"""

import asyncio
import uuid
from abc import ABC, abstractmethod
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from itzraven.core.logger import get_logger
from itzraven.core.event_bus import EventBus, get_event_bus
from itzraven.core.events import (
    AgentStartedEvent,
    AgentCompletedEvent,
    AgentFailedEvent,
    FindingDiscoveredEvent,
)
from itzraven.core.bloom_filter import get_finding_dedup
from itzraven.core.llm_deduplicator import get_llm_deduplicator, FindingRecord
from itzraven.core.telemetry import get_tracer, trace
from itzraven.core import MEMORY_SYSTEM_AVAILABLE
if MEMORY_SYSTEM_AVAILABLE:
    from itzraven.core.memory_manager import MemoryManager
    from itzraven.core.memory_models import Vulnerability, VulnerabilitySeverity
from itzraven.core.blackboard import Blackboard, FindingCategory, get_blackboard
from itzraven.core.learning_engine import get_learning_engine
from itzraven.core.budget_controller import get_budget_controller
from itzraven.core.meta_cognition import get_meta_cognition
from itzraven.core.skill_library import get_skill_library
from itzraven.core.todo_manager import get_todo_manager, TodoItem, TodoStatus, TodoPriority
from itzraven.core.thinking_chain import get_thinking_chain
from itzraven.core.agent_handoff import get_handoff_manager, HandoffContext
from itzraven.core.aci import get_aci_registry, register_default_contracts
register_default_contracts()
from itzraven.toolkit import (
    BrowserAutomation,
    HTTPProxy,
    ShellExecutor,
    PythonRuntime
)

logger = get_logger()


class AgentStatus(Enum):
    """Formal state machine for agent lifecycle.
    Transitions:
      IDLE → PLANNING → EXECUTING → COMPLETED
                        → PAUSED → EXECUTING
                        → ERROR
              PLANNING → ERROR
    """
    IDLE = "idle"
    PLANNING = "planning"
    EXECUTING = "executing"
    PAUSED = "paused"
    COMPLETED = "completed"
    ERROR = "error"
    CANCELLED = "cancelled"

    def can_transition_to(self, target: "AgentStatus") -> bool:
        VALID = {
            AgentStatus.IDLE:      {AgentStatus.PLANNING},
            AgentStatus.PLANNING:  {AgentStatus.EXECUTING, AgentStatus.ERROR, AgentStatus.CANCELLED},
            AgentStatus.EXECUTING: {AgentStatus.COMPLETED, AgentStatus.PAUSED, AgentStatus.ERROR, AgentStatus.CANCELLED},
            AgentStatus.PAUSED:    {AgentStatus.EXECUTING, AgentStatus.CANCELLED},
            AgentStatus.COMPLETED: set(),
            AgentStatus.ERROR:     {AgentStatus.PLANNING},
            AgentStatus.CANCELLED: {AgentStatus.PLANNING},
        }
        return target in VALID.get(self, set())


@dataclass
class Finding:
    """Security finding discovered by an agent"""
    title: str
    description: str
    severity: str  # critical, high, medium, low, info
    category: str  # injection, xss, auth, etc.
    evidence: str
    proof_of_concept: Optional[str] = None
    remediation: Optional[str] = None
    confidence: float = 1.0  # 0.0 to 1.0
    reproducibility_steps: Optional[List[str]] = None
    fix_hint: Optional[str] = None
    validation_status: str = "validated"
    timestamp: datetime = field(default_factory=datetime.now)
    agent_name: str = ""
    finding_id: str = ""
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    cwe_id: Optional[str] = None
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    code_snippet: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary"""
        return {
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "category": self.category,
            "evidence": self.evidence,
            "proof_of_concept": self.proof_of_concept,
            "reproducibility_steps": self.reproducibility_steps,
            "fix_hint": self.fix_hint,
            "validation_status": self.validation_status,
            "remediation": self.remediation,
            "confidence": self.confidence,
            "timestamp": self.timestamp.isoformat(),
            "agent_name": self.agent_name,
            "finding_id": self.finding_id,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "cwe_id": self.cwe_id,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "code_snippet": self.code_snippet,
            "metadata": self.metadata,
        }


@dataclass
class AgentResult:
    """Result of agent execution"""
    agent_name: str
    status: AgentStatus
    findings: List[Finding]
    execution_time: float
    error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class BaseAgent(ABC):
    """Base class for all security testing agents"""

    def __init__(
        self,
        name: str,
        target: str,
        event_bus: Optional[EventBus] = None,
        memory_manager: Optional['MemoryManager'] = None,
        scope: Optional[List[str]] = None
    ):
        self.name = name
        self.target = target
        self.scope = scope or []
        self.status = AgentStatus.IDLE
        self.findings: List[Finding] = []
        self.start_time: Optional[float] = None
        self.end_time: Optional[float] = None

        # Toolkit access
        self.browser: Optional[BrowserAutomation] = None
        self.proxy: Optional[HTTPProxy] = None
        self.shell: Optional[ShellExecutor] = None
        self.python: Optional[PythonRuntime] = None

        # Event Bus support (optional for backward compatibility)
        self.event_bus: Optional[EventBus] = event_bus
        self.correlation_id: str = str(uuid.uuid4())

        # Memory System support (optional for backward compatibility)
        self.memory_manager: Optional['MemoryManager'] = memory_manager

        # Cross-agent baton context (set by orchestrator in sequential mode)
        self.context: Dict[str, Any] = {}

        # Phase label for handoff context (set by orchestrator)
        self.phase: str = "general"

        # Auth headers/cookies for authenticated scanning (set by orchestrator)
        self.auth_headers: Dict[str, str] = {}
        self.auth_cookies: Dict[str, str] = {}

        # Blackboard for inter-agent context sharing
        self._blackboard: Blackboard = get_blackboard()
        self._learning_engine = get_learning_engine()

        # Todo Manager (Strix v0.5.0 style)
        self._todo_manager = get_todo_manager()
        self._todos: List[str] = []

        # Shared browser instance (set by orchestrator)
        self._shared_browser: Optional[BrowserAutomation] = None

        # Track pending async tasks for proper cleanup
        self._pending_tasks: List[asyncio.Task] = []

        # Cancellation support (set by orchestrator)
        self._cancelled: bool = False
        self._paused: bool = False
        self._paused_event: asyncio.Event = asyncio.Event()
        self._paused_event.set()

        # ---- Autonomous enhancements ----
        self._budget_controller = get_budget_controller()
        self._budget_controller.register_agent(self.name)
        self._meta_cognition = get_meta_cognition()
        self._meta_cognition.register_agent(self.name)
        self._skill_library = get_skill_library()
        self._current_technique: str = ""
        self._reflection_callback: Optional[callable] = None

    def cancel(self) -> None:
        """Signal the agent to stop at the next safe checkpoint."""
        self._cancelled = True
        self._paused_event.set()
        logger.info(f"{self.name}: Cancel signal received")

    def pause(self) -> None:
        """Pause the agent at the next checkpoint."""
        self._paused = True
        self._paused_event.clear()
        logger.info(f"{self.name}: Pause signal received")

    def resume(self) -> None:
        """Resume the agent from pause."""
        self._paused = False
        self._paused_event.set()
        logger.info(f"{self.name}: Resume signal received")

    @property
    def should_stop(self) -> bool:
        """Check if cancellation has been requested"""
        return self._cancelled

    def budget_tool_call(self, technique: str = "", success: bool = False, error: str = ""):
        self._budget_controller.record_call(self.name)
        if technique:
            self._current_technique = technique
        self._meta_cognition.record_step(self.name, technique=technique or self._current_technique, success=success, error=error)
        should_stop, reason = self._budget_controller.should_stop(self.name)
        if should_stop:
            logger.info(f"⏹ {self.name}: Budget stop — {reason}")
            self._cancelled = True
        insight = self._meta_cognition.check_reflection(self.name, interval=5)
        if insight and self._reflection_callback:
            self._reflection_callback(insight)
        return should_stop

    async def check_pause(self) -> None:
        """If paused, wait until resumed. Does nothing when not paused."""
        if self._paused:
            logger.debug(f"{self.name}: Paused, waiting for resume...")
            await self._paused_event.wait()
            logger.debug(f"{self.name}: Resumed")

    def format_auth_args(self) -> List[str]:
        """Format auth headers as CLI args for subprocess tools (httpx, nuclei, etc.)."""
        args: List[str] = []
        for key, value in self.auth_headers.items():
            args.extend(["-H", f"{key}: {value}"])
        if self.auth_cookies:
            cookie_str = "; ".join(f"{k}={v}" for k, v in self.auth_cookies.items())
            args.extend(["-H", f"Cookie: {cookie_str}"])
        return args

    def get_http_client_headers(self, extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        """Get dict of headers including auth, for use with httpx.AsyncClient."""
        headers = dict(self.auth_headers)
        if self.auth_cookies:
            cookie_str = "; ".join(f"{k}={v}" for k, v in self.auth_cookies.items())
            headers["Cookie"] = cookie_str
        if extra:
            headers.update(extra)
        headers.setdefault("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
        return headers

    def set_shared_browser(self, browser: BrowserAutomation) -> None:
        """Set shared browser instance (Strix v0.6.2 style)."""
        self._shared_browser = browser

    async def initialize_toolkit(self) -> None:
        """Initialize security toolkit"""
        if self._shared_browser:
            self.browser = self._shared_browser
            logger.debug(f"{self.name}: Using shared browser instance")
        else:
            self.browser = BrowserAutomation()
        self.proxy = HTTPProxy()
        self.shell = ShellExecutor()
        self.python = PythonRuntime()
        logger.debug(f"{self.name}: Toolkit initialized")

    def create_todo(self, description: str, category: str = "", priority: TodoPriority = TodoPriority.MEDIUM,
                    depends_on: Optional[List[str]] = None) -> str:
        todo = self._todo_manager.create_todo(
            description=description,
            agent_name=self.name,
            category=category or self.__class__.__name__,
            target=self.target,
            priority=priority,
            depends_on=depends_on,
        )
        self._todos.append(todo.id)
        return todo.id

    def complete_todo(self, todo_id: str, result: Optional[str] = None):
        self._todo_manager.update_status(todo_id, TodoStatus.COMPLETED, result=result)

    def fail_todo(self, todo_id: str, error: str):
        self._todo_manager.update_status(todo_id, TodoStatus.FAILED, error=error)

    def get_todos(self) -> List[dict]:
        return [self._todo_manager.get_todo(tid).to_dict() for tid in self._todos if self._todo_manager.get_todo(tid)]

    async def cleanup_toolkit(self) -> None:
        """Cleanup security toolkit"""
        if self.browser:
            await self.browser.stop()
        if self.proxy:
            await self.proxy.stop()
        logger.debug(f"{self.name}: Toolkit cleaned up")

    async def _emit_thought(self, thought: str, thought_type: str = "reasoning", phase: str = "") -> None:
        if self.event_bus:
            try:
                from itzraven.core.events import AgentThinkingEvent
                await self.event_bus.publish_event(AgentThinkingEvent(
                    agent_name=self.name,
                    thought=thought,
                    thought_type=thought_type,
                    phase=phase,
                ))
            except Exception:
                pass

    async def publish_handoff(self, result: "AgentResult") -> None:
        try:
            hm = get_handoff_manager()
            techs = self.context.get("shared_technologies", []) or []
            endpoints = self.context.get("shared_endpoints", []) or []
            finding_titles = [f.title for f in result.findings[:10]]
            summary = f"{len(result.findings)} findings: {'; '.join(finding_titles)}" if finding_titles else "No findings"
            ctx = HandoffContext(
                agent_name=self.name,
                phase=self.phase,
                target=self.target,
                findings_summary=summary,
                technologies=techs,
                endpoints=endpoints,
                blocked_paths=self.context.get("blocked_paths", []),
                recommendations=self.context.get("recommendations", []),
                metadata={
                    "findings_count": len(result.findings),
                    "execution_time": result.execution_time,
                    "result_status": result.status.value if hasattr(result.status, "value") else str(result.status),
                },
            )
            hm.publish(ctx)
            self.context["handoff_context"] = hm.build_handoff_prompt(self.target)
        except Exception as e:
            logger.debug(f"Handoff publish failed: {e}")

    @abstractmethod
    async def execute(self) -> AgentResult:
        """Execute agent's security testing logic"""
        pass

    def _transition(self, target: AgentStatus) -> bool:
        if self.status.can_transition_to(target):
            self.status = target
            return True
        logger.warning(f"{self.name}: Invalid status transition {self.status.value} → {target.value}")
        return False

    async def run(self) -> AgentResult:
        """Run the agent with formal state machine lifecycle"""
        self._transition(AgentStatus.PLANNING)
        self.start_time = asyncio.get_event_loop().time()

        # Publish agent started event (if event bus available)
        if self.event_bus:
            try:
                await self.event_bus.publish_event(AgentStartedEvent(
                    agent_name=self.name,
                    agent_type=self.__class__.__name__,
                    target=self.target,
                    mode="pentest",
                    correlation_id=self.correlation_id,
                ))
            except Exception as e:
                logger.debug(f"Failed to publish agent started event: {e}")

        # Push thinking block on start
        thinking_chain = get_thinking_chain()
        thinking_chain.add_block(
            agent_name=self.name,
            thought=f"Starting analysis of {self.target}",
            thought_type="intent",
            phase="init",
        )
        await self._emit_thought(f"Starting analysis of {self.target}", thought_type="intent", phase="init")
        # Inject prior thinking chain context into agent context
        self.context["thinking_chain"] = thinking_chain.get_context_for_agent(self.name, max_blocks=15)

        logger.info(f"🤖 {self.name} started on {self.target}")

        try:
            await self.initialize_toolkit()

            if self.should_stop:
                logger.info(f"{self.name}: Cancelled before execution")
                self._transition(AgentStatus.CANCELLED)
                self.end_time = asyncio.get_event_loop().time()
                return AgentResult(
                    agent_name=self.name,
                    status=AgentStatus.CANCELLED,
                    findings=self.findings,
                    execution_time=0,
                    error="Cancelled before execution",
                )

            self._transition(AgentStatus.EXECUTING)
            result = await self.execute()

            # Budget & meta-cognition summary
            budget_report = self._budget_controller.get_report(self.name)
            if budget_report:
                logger.debug(f"{self.name} budget: {budget_report['calls']} calls, {budget_report['findings']} findings ({budget_report['findings_per_call']}/call)")
            meta_summary = self._meta_cognition.get_summary(self.name)
            if meta_summary and meta_summary.get("reflections"):
                logger.info(f"🧠 {self.name} reflections: {' | '.join(meta_summary['reflections'][-3:])}")

            self._transition(AgentStatus.COMPLETED)
            self.end_time = asyncio.get_event_loop().time()
            result.execution_time = self.end_time - self.start_time

            # Push thinking block on completion
            thinking_chain.add_block(
                agent_name=self.name,
                thought=f"Completed: {len(result.findings)} findings, {result.execution_time:.1f}s",
                thought_type="summary",
                phase="complete",
                metadata={"findings_count": len(result.findings), "execution_time": result.execution_time},
            )
            await self._emit_thought(
                f"Completed: {len(result.findings)} findings, {result.execution_time:.1f}s",
                thought_type="summary", phase="complete",
            )
            logger.success(f"✓ {self.name} completed ({len(result.findings)} findings)")

            if self._pending_tasks:
                logger.debug(f"Waiting for {len(self._pending_tasks)} pending tasks...")
                await asyncio.gather(*self._pending_tasks, return_exceptions=True)
                self._pending_tasks.clear()

            if self.event_bus:
                try:
                    await self.event_bus.publish_event(AgentCompletedEvent(
                        agent_name=self.name,
                        agent_type=self.__class__.__name__,
                        target=self.target,
                        findings_count=len(result.findings),
                        execution_time=result.execution_time,
                        correlation_id=self.correlation_id,
                    ))
                except Exception as e:
                    logger.debug(f"Failed to publish agent completed event: {e}")

            await self.publish_handoff(result)
            return result

        except Exception as e:
            self._transition(AgentStatus.ERROR)
            self.end_time = asyncio.get_event_loop().time()
            logger.error(f"✗ {self.name} failed: {e}")

            if self.event_bus:
                try:
                    await self.event_bus.publish_event(AgentFailedEvent(
                        agent_name=self.name,
                        agent_type=self.__class__.__name__,
                        target=self.target,
                        error=str(e),
                        correlation_id=self.correlation_id,
                    ))
                except Exception as ex:
                    logger.debug(f"Failed to publish agent failed event: {ex}")

            return AgentResult(
                agent_name=self.name,
                status=AgentStatus.ERROR,
                findings=self.findings,
                execution_time=self.end_time - self.start_time if self.start_time else 0,
                error=str(e)
            )

        finally:
            await self.cleanup_toolkit()

    def get_inter_agent_context(self) -> str:
        """Get context from other agents via blackboard for prompt injection."""
        return self._blackboard.get_context_for_agent(self.name, max_entries=20)

    def _share_to_blackboard(self, finding: Finding):
        """Auto-share finding to blackboard for other agents to consume."""
        try:
            cat_map = {
                "injection": FindingCategory.CVE_MATCH,
                "xss": FindingCategory.EXPLOIT_CHAIN,
                "ssrf": FindingCategory.MISCONFIGURATION,
                "auth": FindingCategory.SESSION,
                "idor": FindingCategory.EXPLOIT_RESULT,
                "recon": FindingCategory.TECHNOLOGY,
                "default": FindingCategory.TARGET_REG,
            }
            category = cat_map.get(finding.category, cat_map["default"])
            self._blackboard.post(
                category=category,
                key=finding.finding_id,
                data={
                    "title": finding.title,
                    "severity": finding.severity,
                    "description": finding.description,
                    "evidence": finding.evidence,
                    "url": finding.proof_of_concept or self.target,
                },
                source_agent=self.name,
                pheromone=1.0 if finding.severity in ("critical", "high") else 0.5,
                tags=[finding.category, finding.severity],
            )
        except Exception as e:
            logger.debug(f"Blackboard share failed: {e}")

    def _check_learning_engine(self, task: str, target_tech: str = "") -> bool:
        """Check if LLM call can be skipped (reliable non-LLM technique exists)."""
        try:
            return self._learning_engine.should_use_llm_for_task(task, target_tech or self.target)
        except Exception:
            return True

    def add_finding(self, finding: Finding) -> None:
        """Add a security finding with Strix-style false positive reduction.

        Multi-stage validation:
        0. LLM-based semantic deduplication (Strix v0.6.0 style — merges semantically similar)
        1. Bloom filter fast-path exact deduplication
        2. Severity downgrade for critical/high without PoC
        3. Confidence-based adjustment
        4. Evidence quality assessment
        5. Reproducibility validation
        """
        finding.agent_name = self.name

        # Auto-assign CVSS score (Strix v0.8.0 style)
        try:
            from itzraven.core.cvss_scorer import score_finding
            cvss = score_finding(
                category=finding.category,
                severity=finding.severity,
                has_poc=bool((finding.proof_of_concept or "").strip()),
                evidence_length=len((finding.evidence or "").strip()),
            )
            if finding.cvss_score is None:
                finding.cvss_score = cvss.score
                finding.cvss_vector = cvss.vector
        except Exception:
            pass

        # Stage 0: LLM-based semantic deduplication
        record = FindingRecord(
            finding_id=finding.finding_id or f"{self.name}-{len(self.findings) + 1}",
            title=finding.title,
            description=finding.description,
            category=finding.category,
            severity=finding.severity,
            agent_name=self.name,
            evidence=finding.evidence,
            proof_of_concept=finding.proof_of_concept,
            remediation=finding.remediation,
        )
        llm_dedup = get_llm_deduplicator()
        dedup_result = llm_dedup.exact_match(record)
        if dedup_result:
            logger.debug(f"Dedup skipped (exact match → {dedup_result}): {finding.title}")
            return

        severity = finding.severity.lower()
        confidence = max(0.0, min(1.0, finding.confidence))

        # Stage 0b: Schedule async LLM semantic dedup check (non-blocking)
        async def _semantic_dedup_check():
            try:
                llm_dedup = get_llm_deduplicator()
                sem_result = await llm_dedup.semantic_match(record)
                if sem_result and sem_result.is_duplicate:
                    llm_dedup.merge_findings(sem_result.merged_into, record.finding_id)
                    logger.debug(f"LLM dedup merged {finding.title} → {sem_result.merged_into}")
            except Exception as e:
                logger.debug(f"Semantic dedup error: {e}")
        task = asyncio.create_task(_semantic_dedup_check())
        self._pending_tasks.append(task)

        # Stage 1: PoC-based severity downgrade
        has_poc = bool((finding.proof_of_concept or "").strip())
        if severity in {"critical", "high"} and not has_poc:
            finding.severity = "medium"
            finding.validation_status = "unvalidated_poc_missing"
            finding.description = (
                f"{finding.description} "
                "[Downgraded from high/critical: proof_of_concept missing]"
            ).strip()

        # Stage 2: Confidence-based evidence quality check
        if confidence < 0.5:
            if finding.severity in ["critical", "high"]:
                finding.severity = "medium"
            finding.validation_status = "low_confidence_requires_manual_review"
            finding.description = (
                f"{finding.description} "
                "[Low confidence finding - manual review required]"
            ).strip()
        elif confidence < 0.7:
            if finding.validation_status == "validated":
                pass
            else:
                finding.validation_status = "medium_confidence_automated_detection"

        # Stage 3: Evidence quality assessment
        evidence = (finding.evidence or "").strip()
        if len(evidence) < 10 and finding.severity != "info":
            if not has_poc:
                finding.confidence = min(finding.confidence, 0.5)
                finding.validation_status = "insufficient_evidence"

        # Stage 4: Reproducibility steps
        if not finding.reproducibility_steps:
            finding.reproducibility_steps = [
                f"Run Itzraven scan against target: {self.target}",
                f"Execute agent: {self.name}",
                "Inspect finding evidence and attempt to reproduce manually",
            ]

        if not finding.fix_hint and finding.remediation:
            finding.fix_hint = finding.remediation

        # Stage 5a: Safety rules check (src-hunter style)
        try:
            from itzraven.core.safety_rules import SafetyRules
            safety = SafetyRules(scope=self.scope)
            title_text = f"{finding.title} {finding.description} {finding.category}"
            violations = safety.check_text(title_text, context=finding.title)
            if violations:
                for v in violations:
                    logger.warning(f"Safety: {v.severity} - {v.message}")
                if safety.blocked:
                    logger.warning(f"Safety blocked finding: {finding.title}")
        except Exception as e:
            logger.debug(f"Safety rules check error: {e}")

        # Stage 5b: RAG prior art injection into metadata
        try:
            from itzraven.core.rag_search import get_rag_search
            rag = get_rag_search()
            prior_context = rag.build_context(
                f"{finding.title} {finding.description}",
                technique=finding.category,
                k=3,
            )
            if prior_context:
                finding.metadata["prior_art"] = prior_context
        except Exception as e:
            logger.debug(f"RAG search error: {e}")

        # Stage 5c: CBH-style 7-Question Triage Gate
        try:
            from itzraven.core.triage_gate import get_triage_gate
            gate = get_triage_gate()
            triage = gate.evaluate(finding)
            if triage.verdict.value == "KILL":
                logger.debug(f"Triage KILL: {finding.title} | {triage.summary}")
            elif triage.verdict.value in ("DOWNGRADE", "CHAIN"):
                logger.info(f"Triage {triage.verdict.value}: {finding.title} | {triage.summary}")
            elif triage.verdict.value == "PASS":
                logger.debug(f"Triage PASS: {finding.title}")
            finding.metadata = getattr(finding, 'metadata', {}) or {}
            finding.metadata["triage"] = triage.to_dict()
        except Exception as e:
            logger.debug(f"Triage gate error: {e}")

        finding.finding_id = f"{self.name}-{len(self.findings) + 1}"
        self.findings.append(finding)
        logger.warning(f"🔍 {self.name}: {finding.severity.upper()} - {finding.title}")

        # Store in Memory System (if available)
        if self.memory_manager and MEMORY_SYSTEM_AVAILABLE:
            try:
                # Convert Finding to Vulnerability
                severity_map = {
                    "critical": VulnerabilitySeverity.CRITICAL,
                    "high": VulnerabilitySeverity.HIGH,
                    "medium": VulnerabilitySeverity.MEDIUM,
                    "low": VulnerabilitySeverity.LOW,
                    "info": VulnerabilitySeverity.INFO,
                }

                vuln = Vulnerability(
                    id=finding.finding_id,
                    title=finding.title,
                    description=finding.description,
                    severity=severity_map.get(finding.severity.lower(), VulnerabilitySeverity.INFO),
                    category=finding.category,
                    confidence=finding.confidence,
                    evidence=finding.evidence,
                    proof_of_concept=finding.proof_of_concept,
                    remediation=finding.remediation,
                    reproducibility_steps=finding.reproducibility_steps,
                    fix_hint=finding.fix_hint,
                    validation_status=finding.validation_status,
                    poc_validated=bool(finding.proof_of_concept),
                )

                # Store asynchronously and track the task
                task = asyncio.create_task(
                    self.memory_manager.store_vulnerability(vuln, self.target)
                )
                self._pending_tasks.append(task)
                logger.debug(f"Scheduled finding storage: {vuln.id}")
            except Exception as e:
                logger.debug(f"Failed to schedule finding storage: {e}")

        # Share with blackboard for inter-agent context
        self._share_to_blackboard(finding)

        # Record technique in learning engine
        try:
            self._learning_engine.record_technique(
                technique=finding.category,
                target_tech=self.target,
                success=finding.confidence >= 0.5,
                tags=[finding.severity, finding.agent_name],
            )
        except Exception:
            pass

        # Track in budget & meta-cognition
        self._budget_controller.record_finding(self.name)
        self._meta_cognition.record_finding(self.name)

        # Auto-learn skill from high-confidence findings
        try:
            shared_techs = self.context.get("shared_technologies", []) or self.context.get("technologies", [])
            self._skill_library.learn_from_finding(finding, self.name, self.target, shared_techs)
        except Exception:
            pass

        # Publish finding discovered event (if event bus available)
        if self.event_bus:
            try:
                # Run async event publishing and track the task
                task = asyncio.create_task(self.event_bus.publish_event(FindingDiscoveredEvent(
                    finding_id=finding.finding_id,
                    title=finding.title,
                    description=finding.description,
                    severity=finding.severity,
                    category=finding.category,
                    target=self.target,
                    agent_name=self.name,
                    confidence=finding.confidence,
                    evidence=finding.evidence,
                    proof_of_concept=finding.proof_of_concept,
                    remediation=finding.remediation,
                    correlation_id=self.correlation_id,
                )))
                self._pending_tasks.append(task)
            except Exception as e:
                logger.debug(f"Failed to publish finding discovered event: {e}")

    def get_test_urls(self) -> List[str]:
        """Get URLs to test - combines target, scope, and shared endpoints from other agents."""
        urls: List[str] = []
        base = self.target.rstrip("/")

        if self.target.startswith("http://") or self.target.startswith("https://"):
            base_url = self.target
        else:
            base_url = f"http://{self.target}"
        urls.append(base_url)

        if self.scope:
            for scoped_path in self.scope:
                path = scoped_path if scoped_path.startswith("/") else f"/{scoped_path}"
                urls.append(f"{base_url.rstrip('/')}{path}")

        shared = self.context.get("shared_endpoints", [])
        if isinstance(shared, list):
            for ep in shared:
                ep_str = ep if isinstance(ep, str) else (ep.get("url", "") if isinstance(ep, dict) else str(ep))
                if ep_str and ep_str not in urls:
                    if ep_str.startswith("http"):
                        urls.append(ep_str)
                    else:
                        urls.append(f"{base_url.rstrip('/')}{ep_str}")
        return urls

    def get_findings(self) -> List[Finding]:
        """Get all findings"""
        return self.findings.copy()

    async def _run_nuclei_tags(self, tags: List[str], severity: str = "info") -> None:
        """Run nuclei with specific tags relevant to this agent.

        Each agent calls this with vulnerability-specific nuclei tags
        so only relevant templates run (not all 1000s of nuclei templates).
        """
        try:
            import subprocess
            from pathlib import Path
            import json

            result = subprocess.run(["which", "nuclei"], capture_output=True, text=True)
            if result.returncode != 0:
                logger.debug("nuclei not available for tag scan")
                return

            urls = self.get_test_urls()
            if not urls:
                return

            urls_file = f"/tmp/nuclei_urls_{self.name.lower().replace(' ', '_')}.txt"
            output_file = f"/tmp/nuclei_results_{self.name.lower().replace(' ', '_')}.jsonl"

            with open(urls_file, "w") as f:
                for url in urls[:50]:
                    f.write(url + "\n")

            tag_str = ",".join(tags)
            cmd = [
                "nuclei", "-l", urls_file,
                "-tags", tag_str,
                "-jsonl", "-o", output_file,
                "-silent", "-timeout", "8",
                "-severity", severity,
            ]
            logger.info(f"{self.name}: Running nuclei with tags: {tag_str}")

            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            try:
                await asyncio.wait_for(proc.communicate(), timeout=90)
            except asyncio.TimeoutError:
                proc.kill()

            if Path(output_file).exists() and Path(output_file).stat().st_size > 0:
                with open(output_file) as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            entry = json.loads(line)
                            self._add_finding_from_nuclei_entry(entry)
                        except json.JSONDecodeError:
                            continue
                Path(output_file).unlink(missing_ok=True)

            Path(urls_file).unlink(missing_ok=True)

        except Exception as e:
            logger.debug(f"{self.name}: nuclei tag scan failed: {e}")

    def _add_finding_from_nuclei_entry(self, entry: dict) -> None:
        severity_map = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "info": "info"}
        sev = severity_map.get(entry.get("info", {}).get("severity", "").lower(), "info")
        name = entry.get("info", {}).get("name", entry.get("template-id", "unknown"))
        matched = entry.get("matched-at", entry.get("host", self.target))
        extract = entry.get("extracted-results", [])
        ext_str = ", ".join(extract[:3]) if extract else ""
        desc = entry.get("info", {}).get("description", "")
        template_id = entry.get("template-id", "")
        cve = ""
        if "classification" in entry.get("info", {}):
            cve = ", ".join(entry["info"]["classification"].get("cve-id", []))
        self.add_finding(Finding(
            title=f"[Nuclei:{self.name}] {name}" + (f" ({cve})" if cve else ""),
            description=desc or f"Nuclei template {template_id} matched on {matched}",
            severity=sev, category="nuclei",
            evidence=f"URL: {matched}\nExtracted: {ext_str}\nTemplate: {template_id}",
            confidence=0.85,
        ))
