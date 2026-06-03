"""
Validation Gate Agent — runs the 7-Question Validation Gate on all findings
collected by other agents during a scan. Supports /validate command for
on-demand re-validation.
"""

import asyncio
from typing import Dict, List, Any, Optional

from itzraven.agents.base_agent import BaseAgent, AgentResult, AgentStatus, Finding
from itzraven.agents.gating import GatingEvaluator
from itzraven.core.logger import get_logger

logger = get_logger()


class ValidationGateAgent(BaseAgent):
    """Validates all findings through the 7-Question Validation Gate."""

    def __init__(
        self,
        target: str,
        event_bus=None,
        memory_manager=None,
        scope=None,
        findings: Optional[List[Finding]] = None,
    ):
        super().__init__(
            name="Validation Gate Agent",
            target=target,
            event_bus=event_bus,
            memory_manager=memory_manager,
            scope=scope,
        )
        self._findings_to_validate: List[Finding] = findings or []
        self.evaluator = GatingEvaluator()
        self.validation_results: List[Dict[str, Any]] = []

    def set_findings(self, findings: List[Finding]) -> None:
        """Set the list of findings to validate."""
        self._findings_to_validate = findings

    async def execute(self) -> AgentResult:
        """Run the 7-Question Validation Gate against all loaded findings."""
        start = asyncio.get_event_loop().time()

        passed = 0
        killed = 0
        downgraded = 0
        chained = 0

        for finding in self._findings_to_validate:
            result = self.evaluator.validate_finding(finding)
            self.validation_results.append(result)

            if result["q_scores"]:
                finding.validation_status = result["overall"].lower()
            else:
                finding.validation_status = "killed_by_never_submit"

            status = result["overall"]
            if status == "PASS":
                passed += 1
            elif status == "KILL":
                killed += 1
            elif status == "DOWNGRADE":
                downgraded += 1
            elif status == "CHAIN":
                chained += 1

            logger.info(
                f"[{finding.finding_id}] 7-Q Gate: {status} | "
                f"{finding.title[:60]}"
            )

        end = asyncio.get_event_loop().time()
        total = len(self._findings_to_validate)

        return AgentResult(
            agent_name=self.name,
            status=AgentStatus.COMPLETED,
            findings=[],
            execution_time=end - start,
            metadata={
                "validated_count": total,
                "passed": passed,
                "killed": killed,
                "downgraded": downgraded,
                "chained": chained,
                "validation_results": self.validation_results,
            },
        )

    async def handle_command(self, command: str, args: Optional[List[str]] = None) -> str:
        """Handle interactive commands such as /validate."""
        if command == "/validate":
            if not self._findings_to_validate:
                return "No findings loaded for validation."

            results = []
            for finding in self._findings_to_validate:
                r = self.evaluator.validate_finding(finding)
                results.append(r)

            lines = [
                f"[{r['finding_id']}] overall={r['overall']} | {r['summary']}"
                for r in results
            ]
            return "\n".join(lines)

        return f"Unknown command: {command}"
