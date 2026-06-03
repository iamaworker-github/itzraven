import asyncio
import uuid
import random
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional, Type
from dataclasses import dataclass, field
from datetime import datetime

from itzraven.agents.base_agent import BaseAgent, AgentResult, Finding, AgentStatus
from itzraven.agents.gating import GatingEvaluator
from itzraven.agents.orchestrator import AgentOrchestrator, ScanResult
from itzraven.core.logger import get_logger
from itzraven.core.config import get_config
from itzraven.core.event_bus import EventBus, get_event_bus
from itzraven.core.events import ScanStartedEvent, ScanCompletedEvent, AgentProgressEvent
from itzraven.core.blackboard import Blackboard, FindingCategory, get_blackboard
from itzraven.core.todo_manager import get_todo_manager, TodoStatus, TodoPriority
from itzraven.core import MEMORY_SYSTEM_AVAILABLE
if MEMORY_SYSTEM_AVAILABLE:
    from itzraven.core.memory_manager import MemoryManager

logger = get_logger()
config = get_config()


class ModeOrchestrator(ABC):
    mode_name: str = "base"

    def __init__(
        self,
        target: str,
        event_bus: Optional[EventBus] = None,
        memory_manager: Optional['MemoryManager'] = None,
        scope: Optional[List[str]] = None,
        gating_mode: str = "shadow",
        scan_depth: str = "deep",
        instruction: Optional[str] = None,
        sub_mode: Optional[str] = None,
    ):
        self.target = target
        self.scope = scope or []
        self.scan_depth = scan_depth
        self.instruction = instruction
        self.sub_mode = sub_mode
        normalized_gating_mode = (gating_mode or "shadow").lower()
        self.gating_mode = normalized_gating_mode if normalized_gating_mode in {"off", "shadow", "enforced"} else "shadow"
        self.agents: List[BaseAgent] = []
        self.results: List[AgentResult] = []
        self.all_findings: List[Finding] = []

        self.event_bus: Optional[EventBus] = event_bus
        self.scan_id: str = str(uuid.uuid4())

        self.memory_manager: Optional['MemoryManager'] = memory_manager
        self.blackboard: Blackboard = get_blackboard()

    def add_agent(self, agent: BaseAgent) -> None:
        if self.scope:
            agent.scope = self.scope
        self.agents.append(agent)
        logger.debug(f"[{self.mode_name}] Added agent: {agent.name}")

    @abstractmethod
    def load_agents(self) -> None:
        pass

    def get_report_template(self) -> str:
        return "default"

    def get_output_subdir(self) -> str:
        return self.mode_name

    async def run_sequential(self) -> ScanResult:
        start_time = datetime.now()
        logger.info(f"[{self.mode_name}] Starting sequential scan of {self.target}")

        if self.event_bus:
            try:
                await self.event_bus.publish_event(ScanStartedEvent(
                    scan_id=self.scan_id, target=self.target, mode=self.mode_name, agent_count=len(self.agents),
                ))
            except Exception as e:
                logger.debug(f"Failed to publish scan started event: {e}")

        # Shared data that flows between agents
        shared_endpoints: List[str] = []
        shared_technologies: List[str] = []
        shared_subdomains: List[str] = []

        # Create shared browser instance (Strix v0.6.2 style)
        shared_browser = None
        try:
            from itzraven.toolkit import BrowserAutomation
            shared_browser = BrowserAutomation()
            for agent in self.agents:
                agent.set_shared_browser(shared_browser)
            logger.info(f"[{self.mode_name}] Shared browser instance created for {len(self.agents)} agents")
        except Exception:
            pass

        # Create scan-level todos
        todo_mgr = get_todo_manager()
        scan_todo = todo_mgr.create_todo(
            description=f"Scan {self.target} ({self.mode_name})",
            agent_name="orchestrator",
            category="scan",
            target=self.target,
            priority=TodoPriority.HIGH,
        )

        from pathlib import Path
        output_dir = Path(config.get("output_dir", "./itzraven_results"))
        realtime_file = output_dir / f"realtime_{self.scan_id[:8]}.jsonl"

        for agent in self.agents:
            agent.context = {
                "scan_id": self.scan_id,
                "target": self.target,
                "scope": self.scope,
                "mode": self.mode_name,
                "shared_endpoints": shared_endpoints,
                "shared_technologies": shared_technologies,
                "shared_subdomains": shared_subdomains,
                "realtime_file": str(realtime_file),
            }
            if hasattr(agent, 'set_findings_to_validate'):
                agent.set_findings_to_validate(self.all_findings)
            # Create agent-level todo
            agent_todo = agent.create_todo(f"Run {agent.name} on {self.target}", category=self.mode_name)
            if hasattr(agent, 'set_findings_to_remediate'):
                agent.set_findings_to_remediate(self.all_findings)

            # === THINKING PHASE (lightweight - no artificial delays) ===
            if self.event_bus:
                try:
                    from itzraven.core.events import AgentProgressEvent
                    await self.event_bus.publish_event(AgentProgressEvent(
                        agent_name=agent.name,
                        progress=30.0,
                        current_phase="thinking",
                        message=f"🧠 Analyzing target {self.target}...",
                        correlation_id=self.scan_id,
                    ))
                except Exception:
                    pass
            # === END THINKING PHASE ===

            logger.info(f"  ▶ Running {agent.name}...")
            result = await agent.run()
            self.results.append(result)
            self.all_findings.extend(result.findings)

            # Real-time results persistence (Strix v0.4.0 style)
            if result.findings:
                try:
                    import json
                    from pathlib import Path
                    output_dir = Path(config.get("output_dir", "./itzraven_results"))
                    output_dir.mkdir(parents=True, exist_ok=True)
                    realtime_file = output_dir / f"realtime_{self.scan_id[:8]}.jsonl"
                    for finding in result.findings:
                        entry = {"event": "finding", "scan_id": self.scan_id, "agent": agent.name, "finding": finding.to_dict()}
                        with open(realtime_file, "a") as rf:
                            rf.write(json.dumps(entry) + "\n")
                    logger.debug(f"Real-time: {len(result.findings)} findings appended to {realtime_file}")
                except Exception as e:
                    logger.debug(f"Real-time persistence failed: {e}")

        end_time = datetime.now()
        scan_result = self._create_scan_result(start_time, end_time)

        if self.event_bus:
            try:
                await self.event_bus.publish_event(ScanCompletedEvent(
                    scan_id=self.scan_id, target=self.target, mode=self.mode_name,
                    total_findings=scan_result.total_findings, duration=scan_result.duration, success=True,
                ))
            except Exception as e:
                logger.debug(f"Failed to publish scan completed event: {e}")

        return scan_result

    async def run_parallel(self) -> ScanResult:
        start_time = datetime.now()
        logger.info(f"[{self.mode_name}] Starting parallel scan of {self.target}")

        if self.event_bus:
            try:
                await self.event_bus.publish_event(ScanStartedEvent(
                    scan_id=self.scan_id, target=self.target, mode=self.mode_name, agent_count=len(self.agents),
                ))
            except Exception as e:
                logger.debug(f"Failed to publish scan started event: {e}")

        semaphore = asyncio.Semaphore(config.max_concurrent_agents)

        async def run_with_semaphore(agent: BaseAgent) -> AgentResult:
            async with semaphore:
                logger.info(f"  ▶ Running {agent.name}...")
                return await agent.run()

        tasks = [run_with_semaphore(agent) for agent in self.agents]
        run_results = await asyncio.gather(*tasks, return_exceptions=True) if tasks else []

        for result in run_results:
            if isinstance(result, AgentResult):
                self.results.append(result)
                self.all_findings.extend(result.findings)
                for f in result.findings:
                    self.blackboard.post(
                        category=FindingCategory.CVE_MATCH,
                        key=f"{result.agent_name}:{f.finding_id}",
                        data={"title": f.title, "severity": f.severity},
                        source_agent=result.agent_name,
                    )
            else:
                logger.error(f"Agent failed with exception: {result}")

        end_time = datetime.now()
        scan_result = self._create_scan_result(start_time, end_time)

        if self.event_bus:
            try:
                await self.event_bus.publish_event(ScanCompletedEvent(
                    scan_id=self.scan_id, target=self.target, mode=self.mode_name,
                    total_findings=scan_result.total_findings, duration=scan_result.duration, success=True,
                ))
            except Exception as e:
                logger.debug(f"Failed to publish scan completed event: {e}")

        return scan_result

    def _create_scan_result(self, start_time: datetime, end_time: datetime) -> ScanResult:
        findings_by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for finding in self.all_findings:
            s = finding.severity.lower()
            if s in findings_by_severity:
                findings_by_severity[s] += 1

        return ScanResult(
            target=self.target,
            start_time=start_time,
            end_time=end_time,
            total_findings=len(self.all_findings),
            findings_by_severity=findings_by_severity,
            agent_results=self.results,
            all_findings=self.all_findings,
            metadata={"mode": self.mode_name, "scan_depth": self.scan_depth},
        )
