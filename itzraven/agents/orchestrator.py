"""
Agent orchestrator for coordinating multiple security agents
"""

import asyncio
import uuid
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime
from itzraven.agents.base_agent import BaseAgent, AgentResult, Finding, AgentStatus
from itzraven.agents.sql_injection_agent import SQLInjectionAgent
from itzraven.agents.xss_agent import XSSAgent
from itzraven.agents.ssrf_agent import SSRFAgent
from itzraven.agents.recon_agent import ReconAgent
from itzraven.agents.command_injection_agent import CommandInjectionAgent
from itzraven.agents.authentication_agent import AuthenticationAgent
from itzraven.agents.idor_agent import IDORAgent
from itzraven.agents.ctf_agent import CTFAgent
from itzraven.agents.advanced_ctf_agent import AdvancedCTFAgent
from itzraven.agents.autonomous_agent import AutonomousSecurityAgent
from itzraven.agents.strix_pentest_agent import StrixPentestAgent
from itzraven.agents.poc_validator_agent import PoCValidatorAgent
from itzraven.agents.remediation_agent import RemediationAgent
from itzraven.agents.gating import GatingEvaluator
from itzraven.core.logger import get_logger
from itzraven.core.config import get_config
from itzraven.core.event_bus import EventBus, get_event_bus
from itzraven.core.events import ScanStartedEvent, ScanCompletedEvent
from itzraven.core.blackboard import Blackboard, FindingCategory, get_blackboard, set_blackboard
from itzraven.core.bloom_filter import get_finding_dedup
from itzraven.core.llm_deduplicator import get_llm_deduplicator, FindingRecord, LLMDeduplicator
from itzraven.core.todo_manager import get_todo_manager, TodoStatus, TodoPriority
from itzraven.core.adaptive_concurrency import get_adaptive_concurrency
from itzraven.toolkit import BrowserAutomation
from itzraven.core.telemetry import get_tracer, trace
from itzraven.core import MEMORY_SYSTEM_AVAILABLE
from itzraven.core.chain_executor import get_chain_executor
if MEMORY_SYSTEM_AVAILABLE:
    from itzraven.core.memory_manager import MemoryManager

logger = get_logger()
config = get_config()


@dataclass
class ScanResult:
    """Complete scan result from all agents"""
    target: str
    start_time: datetime
    end_time: datetime
    total_findings: int
    findings_by_severity: Dict[str, int]
    agent_results: List[AgentResult]
    all_findings: List[Finding]
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def duration(self) -> float:
        """Get scan duration in seconds"""
        return (self.end_time - self.start_time).total_seconds()

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "target": self.target,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat(),
            "duration": self.duration,
            "total_findings": self.total_findings,
            "findings_by_severity": self.findings_by_severity,
            "agent_results": [
                {
                    "agent_name": r.agent_name,
                    "status": r.status.value,
                    "findings_count": len(r.findings),
                    "execution_time": r.execution_time,
                }
                for r in self.agent_results
            ],
            "findings": [f.to_dict() for f in self.all_findings],
            "metadata": self.metadata,
        }


class AgentOrchestrator:
    """Orchestrates multiple security testing agents"""

    def __init__(
        self,
        target: str,
        mode: str = "pentest",
        event_bus: Optional[EventBus] = None,
        memory_manager: Optional['MemoryManager'] = None,
        scope: Optional[List[str]] = None,
        gating_mode: str = "shadow",
        scan_depth: str = "deep",
        instruction: Optional[str] = None,
        sub_mode: Optional[str] = None,
    ):
        self.target = target
        self.mode = mode
        self.scope = scope or []
        self.scan_depth = scan_depth
        self.sub_mode = sub_mode
        self.instruction = instruction
        normalized_gating_mode = (gating_mode or "shadow").lower()
        self.gating_mode = normalized_gating_mode if normalized_gating_mode in {"off", "shadow", "enforced"} else "shadow"
        self.agents: List[BaseAgent] = []
        self.results: List[AgentResult] = []
        self.all_findings: List[Finding] = []

        # Event Bus support (optional for backward compatibility)
        self.event_bus: Optional[EventBus] = event_bus
        self.scan_id: str = str(uuid.uuid4())

        # Memory System support (optional for backward compatibility)
        self.memory_manager: Optional['MemoryManager'] = memory_manager

        # Task tracking for cancellation
        self._running_tasks: Dict[str, asyncio.Task] = {}
        self._scan_task: Optional[asyncio.Task] = None

    def cancel_agent(self, agent_name: str) -> None:
        """Cancel a running agent by name. Sets its cancel flag and cancels the task."""
        task = self._running_tasks.get(agent_name)
        if task and not task.done():
            task.cancel()
            logger.info(f"Task cancelled for agent: {agent_name}")
        for agent in self.agents:
            if agent.name == agent_name:
                agent.cancel()
                break

    def cancel_all(self) -> None:
        """Cancel all running agents."""
        for name in list(self._running_tasks.keys()):
            self.cancel_agent(name)

    def pause_agent(self, agent_name: str) -> None:
        """Pause a running agent."""
        for agent in self.agents:
            if agent.name == agent_name:
                agent.pause()
                break

    def resume_agent(self, agent_name: str) -> None:
        """Resume a paused agent."""
        for agent in self.agents:
            if agent.name == agent_name:
                agent.resume()
                break

    def add_agent(self, agent: BaseAgent) -> None:
        """Add an agent to the orchestrator"""
        if self.scope:
            agent.scope = self.scope
        self.agents.append(agent)
        logger.debug(f"Added agent: {agent.name}")

    def add_autonomous_agent(self, max_iterations: int = 5, instruction: Optional[str] = None) -> None:
        """Add the autonomous security agent (opt-in mode)."""
        if self.mode == "pentest":
            self.add_agent(StrixPentestAgent(
                self.target,
                event_bus=self.event_bus,
                memory_manager=self.memory_manager,
                scope=self.scope,
                scan_depth=self.scan_depth,
                scan_mode=self.mode,
                instruction=instruction or self.instruction,
            ))
            logger.info(f"Added Strix pentest agent (depth={self.scan_depth})")
        else:
            self.add_agent(AutonomousSecurityAgent(
                self.target,
                event_bus=self.event_bus,
                memory_manager=self.memory_manager,
                max_iterations=max_iterations,
                scope=self.scope,
                instruction=instruction,
            ))
            logger.info(f"Added autonomous security agent (max_iterations={max_iterations})")

    def add_remediation_agent(self) -> None:
        """Add remediation suggestion agent (opt-in mode)."""
        self.add_agent(RemediationAgent(
            self.target,
            event_bus=self.event_bus,
            memory_manager=self.memory_manager,
            scope=self.scope,
        ))
        logger.info("Added remediation suggestion agent")

    def add_default_agents(self, use_advanced_ctf: bool = True, remediation: bool = False) -> None:
        """Add default set of security agents based on mode

        Args:
            use_advanced_ctf: If True, use AdvancedCTFAgent with 100+ skills (default)
                            If False, use basic CTFAgent
        """
        if self.mode == "ctf":
            # CTF mode: Use specialized CTF agent for autonomous solving
            if use_advanced_ctf:
                self.add_agent(AdvancedCTFAgent(
                    self.target,
                    event_bus=self.event_bus,
                    memory_manager=self.memory_manager
                ))
                logger.info(f"Added Advanced CTF agent with 100+ skills for autonomous challenge solving")
            else:
                self.add_agent(CTFAgent(
                    self.target,
                    event_bus=self.event_bus,
                    memory_manager=self.memory_manager
                ))
                logger.info(f"Added CTF agent for autonomous challenge solving")
        elif self.mode == "osint":
            # OSINT mode: Focus on reconnaissance
            self.add_agent(ReconAgent(
                self.target,
                event_bus=self.event_bus,
                memory_manager=self.memory_manager,
                mode=self.mode  # Pass mode for subdomain enumeration
            ))
            logger.info(f"Added OSINT agents")
        elif self.mode == "bugbounty":
            # Bug Bounty mode: Comprehensive testing
            self.add_agent(ReconAgent(
                self.target,
                event_bus=self.event_bus,
                memory_manager=self.memory_manager,
                mode=self.mode  # Pass mode for subdomain enumeration
            ))
            self.add_agent(SQLInjectionAgent(
                self.target,
                event_bus=self.event_bus,
                memory_manager=self.memory_manager
            ))
            self.add_agent(XSSAgent(
                self.target,
                event_bus=self.event_bus,
                memory_manager=self.memory_manager
            ))
            self.add_agent(SSRFAgent(
                self.target,
                event_bus=self.event_bus,
                memory_manager=self.memory_manager
            ))
            self.add_agent(CommandInjectionAgent(
                self.target,
                event_bus=self.event_bus,
                memory_manager=self.memory_manager
            ))
            self.add_agent(AuthenticationAgent(
                self.target,
                event_bus=self.event_bus,
                memory_manager=self.memory_manager
            ))
            self.add_agent(IDORAgent(
                self.target,
                event_bus=self.event_bus,
                memory_manager=self.memory_manager
            ))
            self.add_agent(PoCValidatorAgent(
                self.target,
                event_bus=self.event_bus,
                memory_manager=self.memory_manager
            ))
            logger.info(f"Added {len(self.agents)} bug bounty agents (including PoC validator)")
        else:
            # Pentest mode (default): Strix-style AI-driven penetration testing
            self.add_agent(StrixPentestAgent(
                self.target,
                event_bus=self.event_bus,
                memory_manager=self.memory_manager,
                scope=self.scope,
                scan_depth=self.scan_depth,
                scan_mode=self.mode,
                instruction=self.instruction,
            ))
            logger.info(f"Added Strix pentest agent (depth={self.scan_depth})")
            strict_poc = "strict" if self.scan_depth == "deep" else "shadow"
            require_all = self.scan_depth == "deep"
            self.add_agent(PoCValidatorAgent(
                self.target,
                event_bus=self.event_bus,
                memory_manager=self.memory_manager,
                strict_poc_mode=strict_poc,
                require_poc_for_all=require_all,
            ))
            logger.info(f"Added PoC validator agent (strict_poc={strict_poc}, require_all={require_all})")

        if remediation:
            self.add_remediation_agent()

    async def run_sequential(self) -> ScanResult:
        """Run agents sequentially"""
        start_time = datetime.now()
        logger.info(f"🚀 Starting sequential scan of {self.target}")

        # Publish scan started event (if event bus available)
        if self.event_bus:
            try:
                await self.event_bus.publish_event(ScanStartedEvent(
                    scan_id=self.scan_id,
                    target=self.target,
                    mode=self.mode,
                    agent_count=len(self.agents),
                ))
            except Exception as e:
                logger.debug(f"Failed to publish scan started event: {e}")

        # Initialize checkpointing for workspace resume
        from itzraven.core.checkpoint_manager import get_checkpoint_manager
        checkpoint_mgr = get_checkpoint_manager(
            scan_id=self.scan_id, target=self.target, mode=self.mode,
            use_git=bool(self.scope and "git" in str(self.scope)),
        )

        # Inject deep scan config if in deep mode
        if self.scan_depth == "deep":
            from itzraven.core.deep_scan_config import DeepScanConfig
            deep_config = DeepScanConfig.deep()
        elif self.scan_depth == "quick":
            from itzraven.core.deep_scan_config import DeepScanConfig
            deep_config = DeepScanConfig.quick()
        else:
            deep_config = None

        # Run source-sink analysis if whitebox sub-mode
        if self.sub_mode == "whitebox":
            try:
                from itzraven.core.source_sink_analyzer import get_source_sink_analyzer
                analyzer = get_source_sink_analyzer(scan_path=self.target)
                traces = analyzer.scan()
                unsanitized = analyzer.get_unsanitized_traces(min_confidence=0.5)
                if unsanitized:
                    logger.info(f"Source-sink: {len(unsanitized)} unsanitized data flows found")
                    for trace in unsanitized[:5]:
                        from itzraven.agents.base_agent import Finding
                        finding_dict = trace.to_finding_dict(self.target)
                        self.all_findings.append(Finding(
                            title=finding_dict["title"],
                            description=finding_dict["description"],
                            severity=finding_dict["severity"],
                            category=finding_dict["category"],
                            evidence=finding_dict["evidence"],
                            remediation=finding_dict["remediation"],
                            confidence=finding_dict["confidence"],
                            file_path=finding_dict["file_path"],
                            line_number=finding_dict["line_number"],
                        ))
            except Exception as e:
                logger.debug(f"Source-sink analysis skipped: {e}")

        baton_context: Dict[str, Any] = {
            "scan_id": self.scan_id,
            "target": self.target,
            "scope": self.scope,
            "deep_config": deep_config.to_dict() if deep_config else None,
        }

        agent_count = len(self.agents)
        for idx, agent in enumerate(self.agents):
            # Skip if checkpoint says this agent is already done
            if checkpoint_mgr.is_agent_completed(agent.name):
                logger.info(f"⏭ Resuming: {agent.name} already completed (checkpoint)")
                continue

            agent.context = dict(baton_context)
            if deep_config:
                agent.context["deep_config"] = deep_config.to_dict()
            # Inject inter-agent context from blackboard
            try:
                bb_context = self._get_blackboard_context(agent.name)
                if bb_context:
                    agent.context["inter_agent_context"] = bb_context
            except Exception:
                pass

            if isinstance(agent, PoCValidatorAgent):
                agent.set_findings_to_validate(self.all_findings)
            if isinstance(agent, RemediationAgent):
                agent.set_findings_to_remediate(self.all_findings)

            if self._is_phase2_enforced_agent(agent) and self._should_skip_enforced_agent(agent.name):
                logger.info(f"⏭ Skipping {agent.name} (gating_mode=enforced)")
                result = AgentResult(
                    agent_name=agent.name,
                    status=AgentStatus.COMPLETED,
                    findings=[],
                    execution_time=0.0,
                    metadata={
                        "gating_enforced_skipped": True,
                        "gating_reason": "Insufficient prerequisite signals in current evidence.",
                    },
                )
            else:
                logger.info(f"▶ Running {agent.name}...")
                async def _run_agent(a):
                    return await a.run()
                task = asyncio.create_task(_run_agent(agent))
                self._running_tasks[agent.name] = task
                try:
                    result = await task
                except asyncio.CancelledError:
                    logger.info(f"{agent.name} was cancelled")
                    result = AgentResult(
                        agent_name=agent.name,
                        status=AgentStatus.FAILED,
                        findings=agent.findings,
                        execution_time=0,
                        error="Cancelled",
                    )
                finally:
                    self._running_tasks.pop(agent.name, None)

            self.results.append(result)
            self.all_findings.extend(result.findings)
            baton_update = self._build_baton_from_result(result)
            baton_context = self._merge_baton_context(baton_context, baton_update, agent.name)

            # Save checkpoint after each agent
            completed_pct = ((idx + 1) / agent_count) * 100
            checkpoint_mgr.save(
                agent_name=agent.name,
                findings=result.findings,
                result=result,
                completed_pct=completed_pct,
            )

        end_time = datetime.now()
        scan_result = self._create_scan_result(start_time, end_time)

        # Publish scan completed event (if event bus available)
        if self.event_bus:
            try:
                await self.event_bus.publish_event(ScanCompletedEvent(
                    scan_id=self.scan_id,
                    target=self.target,
                    mode=self.mode,
                    total_findings=scan_result.total_findings,
                    duration=scan_result.duration,
                    success=True,
                ))
            except Exception as e:
                logger.debug(f"Failed to publish scan completed event: {e}")

        return scan_result

    def _build_baton_from_result(self, result: AgentResult) -> Dict[str, Any]:
        """Build compact baton update from a completed agent result."""
        metadata = result.metadata if isinstance(result.metadata, dict) else {}
        top_findings = [
            {
                "title": finding.title,
                "severity": finding.severity,
                "category": finding.category,
            }
            for finding in result.findings[:5]
        ]
        baton: Dict[str, Any] = {
            "last_agent": result.agent_name,
            "last_findings_count": len(result.findings),
        }
        if top_findings:
            baton["top_findings"] = top_findings
        if metadata:
            baton["metadata"] = metadata
        return baton

    def _merge_baton_context(self, current: Dict[str, Any], update: Dict[str, Any], agent_name: str) -> Dict[str, Any]:
        """Merge baton updates while preserving stable scan context."""
        merged = dict(current)
        if "last_agent" in update:
            merged["last_agent"] = update["last_agent"]
        if "last_findings_count" in update:
            merged["last_findings_count"] = update["last_findings_count"]
        if "top_findings" in update:
            merged["top_findings"] = update["top_findings"]

        if isinstance(update.get("metadata"), dict):
            existing_metadata = merged.get("agent_metadata", {})
            if not isinstance(existing_metadata, dict):
                existing_metadata = {}
            existing_metadata[agent_name] = update["metadata"]
            merged["agent_metadata"] = existing_metadata

        return merged

    _ENFORCED_GATING_DECISION_MAP = {
        "SQL Injection Agent": "SQLi Agent",
        "XSS Agent": "XSS Agent",
        "SSRF Agent": "SSRF Agent",
        "Authentication Agent": "Auth/Session Agent",
        "IDOR Agent": "IDOR Agent",
    }

    @staticmethod
    def _get_blackboard_context(agent_name: str) -> str:
        """Get inter-agent context from blackboard for prompt injection."""
        try:
            bb = get_blackboard()
            return bb.get_context_for_agent(agent_name, max_entries=15)
        except Exception:
            return ""

    def _is_phase2_enforced_agent(self, agent: BaseAgent) -> bool:
        if self.gating_mode != "enforced":
            return False
        return agent.name in self._ENFORCED_GATING_DECISION_MAP

    def _should_skip_enforced_agent(self, agent_name: str) -> bool:
        if self.gating_mode != "enforced":
            return False

        decision_agent_name = self._ENFORCED_GATING_DECISION_MAP.get(agent_name)
        if not decision_agent_name:
            return False

        decisions = GatingEvaluator().evaluate(self.all_findings)
        matched = next((item for item in decisions if item.get("agent_name") == decision_agent_name), None)
        if not matched:
            return True

        return str(matched.get("decision", "skip")).lower() != "run"

    async def run_parallel(self) -> ScanResult:
        """Run agents in parallel with adaptive concurrency and dedup"""
        start_time = datetime.now()
        logger.info(f"Starting parallel scan of {self.target}")

        # Publish scan started event (if event bus available)
        if self.event_bus:
            try:
                await self.event_bus.publish_event(ScanStartedEvent(
                    scan_id=self.scan_id,
                    target=self.target,
                    mode=self.mode,
                    agent_count=len(self.agents),
                ))
            except Exception as e:
                logger.debug(f"Failed to publish scan started event: {e}")

        # Adaptive concurrency
        adaptive = get_adaptive_concurrency()
        await adaptive.start()
        dedup = get_finding_dedup()
        tracer = get_tracer()

        target_key = self.target.replace("https://", "").replace("http://", "").split("/")[0]

        async def run_with_adaptive(agent: BaseAgent) -> AgentResult:
            await adaptive.acquire(target_key)
            try:
                if self._is_phase2_enforced_agent(agent) and self._should_skip_enforced_agent(agent.name):
                    logger.info(f"⏭ Skipping {agent.name} (gating_mode=enforced)")
                    return AgentResult(
                        agent_name=agent.name,
                        status=AgentStatus.COMPLETED,
                        findings=[],
                        execution_time=0.0,
                        metadata={
                            "gating_enforced_skipped": True,
                            "gating_reason": "Insufficient prerequisite signals in current evidence.",
                        },
                    )
                with trace(f"agent:{agent.name}", target=self.target):
                    logger.info(f"▶ Running {agent.name}...")
                    # Register task for cancellation support
                    task = asyncio.current_task()
                    if task:
                        self._running_tasks[agent.name] = task
                    try:
                        result = await agent.run()
                        return result
                    except asyncio.CancelledError:
                        logger.info(f"{agent.name} was cancelled")
                        return AgentResult(
                            agent_name=agent.name,
                            status=AgentStatus.FAILED,
                            findings=agent.findings,
                            execution_time=0.0,
                            error="Cancelled",
                        )
                    finally:
                        self._running_tasks.pop(agent.name, None)
            except Exception as e:
                logger.error(f"Agent {agent.name} failed: {e}")
                return AgentResult(
                    agent_name=agent.name,
                    status=AgentStatus.FAILED,
                    findings=[],
                    execution_time=0.0,
                    error=str(e),
                )
            finally:
                adaptive.release(target_key, success=True)

        # Inject existing blackboard context into each agent before parallel run
        for agent in self.agents:
            try:
                bb_context = self._get_blackboard_context(agent.name)
                if bb_context:
                    agent.context["inter_agent_context"] = bb_context
            except Exception:
                pass

        regular_agents = [
            a for a in self.agents if not isinstance(a, (PoCValidatorAgent, RemediationAgent))
        ]
        post_processing_agents = [
            a for a in self.agents if isinstance(a, (PoCValidatorAgent, RemediationAgent))
        ]

        # Run non-post-processing agents in parallel
        tasks = [run_with_adaptive(agent) for agent in regular_agents]
        run_results = await asyncio.gather(*tasks, return_exceptions=True) if tasks else []

        # Filter out exceptions and collect findings (with bloom dedup)
        valid_results = []
        for result in run_results:
            if isinstance(result, AgentResult):
                valid_results.append(result)
                for f in result.findings:
                    if not dedup.is_duplicate(f.title, f.agent_name, f.evidence):
                        self.all_findings.append(f)
                    else:
                        logger.debug(f"Dedup skipped: {f.title} from {f.agent_name}")
            else:
                logger.error(f"Agent failed with exception: {result}")

        # Chain executor: auto-detect attack chains from findings
        if len(self.all_findings) >= 2:
            chain_ex = get_chain_executor(self.target)
            chain_results = await chain_ex.suggest_and_execute(self.all_findings, max_chains=2)
            if chain_results:
                for cr in chain_results:
                    logger.info(f"Chain '{cr.chain_name}': {cr.steps_completed}/{cr.total_steps} steps")

        # Run post-processing agents after findings are collected
        for processor in post_processing_agents:
            if isinstance(processor, PoCValidatorAgent):
                processor.set_findings_to_validate(self.all_findings)
            if isinstance(processor, RemediationAgent):
                processor.set_findings_to_remediate(self.all_findings)
            logger.info(f"▶ Running {processor.name}...")
            with trace(f"post:{processor.name}", target=self.target):
                result = await processor.run()
            valid_results.append(result)
            self.all_findings.extend(result.findings)

        self.results = valid_results
        end_time = datetime.now()
        scan_result = self._create_scan_result(start_time, end_time)

        await adaptive.stop()

        # Publish scan completed event (if event bus available)
        if self.event_bus:
            try:
                await self.event_bus.publish_event(ScanCompletedEvent(
                    scan_id=self.scan_id,
                    target=self.target,
                    mode=self.mode,
                    total_findings=scan_result.total_findings,
                    duration=scan_result.duration,
                    success=True,
                ))
            except Exception as e:
                logger.debug(f"Failed to publish scan completed event: {e}")

        return scan_result

    def _create_scan_result(self, start_time: datetime, end_time: datetime) -> ScanResult:
        """Create scan result summary"""
        # Count findings by severity
        findings_by_severity = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }

        for finding in self.all_findings:
            severity = finding.severity.lower()
            if severity in findings_by_severity:
                findings_by_severity[severity] += 1

        poc_validation = {
            "processed": 0,
            "validated": 0,
            "failed": 0,
            "skipped": 0,
        }
        remediation_summary = {
            "processed": 0,
            "suggested": 0,
            "skipped": 0,
            "suggestions": [],
        }
        for agent_result in self.results:
            meta = agent_result.metadata or {}
            if "processed_count" in meta:
                poc_validation["processed"] += int(meta.get("processed_count", 0))
                poc_validation["validated"] += int(meta.get("validated_count", 0))
                poc_validation["failed"] += int(meta.get("failed_count", 0))
                poc_validation["skipped"] += int(meta.get("skipped_count", 0))
            if "remediation_processed_count" in meta:
                remediation_summary["processed"] += int(meta.get("remediation_processed_count", 0))
                remediation_summary["suggested"] += int(meta.get("remediation_suggested_count", 0))
                remediation_summary["skipped"] += int(meta.get("remediation_skipped_count", 0))
                suggestions = meta.get("remediation_suggestions", [])
                if isinstance(suggestions, list):
                    remediation_summary["suggestions"].extend(suggestions)

        scan_metadata: Dict[str, Any] = {}
        if poc_validation["processed"] > 0:
            scan_metadata["poc_validation"] = poc_validation
        if remediation_summary["processed"] > 0:
            remediation_summary["suggestions"] = remediation_summary["suggestions"][:20]
            scan_metadata["remediation"] = remediation_summary
        if self.all_findings and self.gating_mode in {"shadow", "enforced"}:
            gating_decisions = GatingEvaluator().evaluate(self.all_findings)
            if self.gating_mode == "shadow":
                scan_metadata["gating_shadow_decisions"] = gating_decisions
            else:
                scan_metadata["gating_enforced_decisions"] = gating_decisions
                enforced_skips = [
                    {
                        "agent_name": r.agent_name,
                        "reason": (r.metadata or {}).get("gating_reason", "Insufficient prerequisite signals in current evidence."),
                    }
                    for r in self.results
                    if isinstance(r.metadata, dict) and r.metadata.get("gating_enforced_skipped")
                ]
                if enforced_skips:
                    scan_metadata["gating_enforced_skips"] = enforced_skips

        # LLM dedup stats
        try:
            llm_dedup = get_llm_deduplicator()
            scan_metadata["llm_dedup_stats"] = llm_dedup.get_stats()
        except Exception:
            pass

        # Create result
        result = ScanResult(
            target=self.target,
            start_time=start_time,
            end_time=end_time,
            total_findings=len(self.all_findings),
            findings_by_severity=findings_by_severity,
            agent_results=self.results,
            all_findings=self.all_findings,
            metadata=scan_metadata,
        )

        # Log summary
        logger.info(f"✓ Scan completed in {result.duration:.2f}s")
        logger.info(f"📊 Total findings: {result.total_findings}")
        if result.total_findings > 0:
            logger.info(f"   Critical: {findings_by_severity['critical']}")
            logger.info(f"   High: {findings_by_severity['high']}")
            logger.info(f"   Medium: {findings_by_severity['medium']}")
            logger.info(f"   Low: {findings_by_severity['low']}")
            logger.info(f"   Info: {findings_by_severity['info']}")
        if "poc_validation" in result.metadata:
            logger.info(
                "   PoC Validation: "
                f"processed={result.metadata['poc_validation']['processed']}, "
                f"validated={result.metadata['poc_validation']['validated']}, "
                f"failed={result.metadata['poc_validation']['failed']}, "
                f"skipped={result.metadata['poc_validation']['skipped']}"
            )

        # Persist thinking chain
        try:
            from itzraven.core.thinking_chain import get_thinking_chain
            think_path = Path(config.get("output_dir", "./itzraven_results")) / f"thinking_{self.scan_id[:8]}.json"
            get_thinking_chain().persist(str(think_path))
            logger.debug(f"Thinking chain saved to {think_path}")
        except Exception as e:
            logger.debug(f"Could not persist thinking chain: {e}")

        # Auto-generate PR if critical or high findings exist
        try:
            critical_high = [f for f in self.all_findings if f.severity in ("critical", "high")]
            if critical_high:
                from itzraven.core.pr_generator import get_pr_generator
                repo_root_path = Path(__file__).resolve().parent.parent.parent
                pr_gen = get_pr_generator(repo_path=str(repo_root_path))
                for f in critical_high[:5]:
                    pr_gen.add_suggestion(f.to_dict())
                pr_body = pr_gen.generate_pr_description(repo_name=self.target)
                meta_path = Path(config.get("output_dir", "./itzraven_results")) / f"pr_{self.scan_id[:8]}.md"
                meta_path.write_text(pr_body)
                scan_metadata["pr_suggestion_file"] = str(meta_path)
                logger.info(f"Auto-fix PR description saved to {meta_path}")
        except Exception as e:
            logger.debug(f"Could not generate PR: {e}")

        return result

    def get_findings_by_severity(self, severity: str) -> List[Finding]:
        """Get findings filtered by severity"""
        return [f for f in self.all_findings if f.severity.lower() == severity.lower()]

    def get_findings_by_category(self, category: str) -> List[Finding]:
        """Get findings filtered by category"""
        return [f for f in self.all_findings if f.category.lower() == category.lower()]
