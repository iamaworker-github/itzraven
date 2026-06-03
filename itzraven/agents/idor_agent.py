"""
IDOR (Insecure Direct Object Reference) detection agent
"""

import re
from urllib.parse import urljoin

import httpx
from itzraven.agents.base_agent import BaseAgent, AgentResult, Finding
from itzraven.core.logger import get_logger

logger = get_logger()


class IDORAgent(BaseAgent):
    """Agent for detecting potential IDOR vulnerabilities."""

    def __init__(self, target: str, event_bus=None, memory_manager=None):
        super().__init__("IDOR Agent", target, event_bus=event_bus, memory_manager=memory_manager)
        self._id_candidates = ["id", "user_id", "account_id", "order_id", "profile_id"]

    async def execute(self) -> AgentResult:
        """Execute lightweight IDOR surface checks."""
        logger.info(f"{self.name}: Testing {self.target}")

        await self._probe_object_reference_surfaces()
        await self._run_nuclei_tags(tags=["idor", "insecure-direct-object-reference", "authorization"], severity="high")

        return AgentResult(
            agent_name=self.name,
            status=self.status,
            findings=self.findings,
            execution_time=0,
        )

    async def _probe_object_reference_surfaces(self) -> None:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            try:
                response = await client.get(self.target)
            except Exception as exc:
                logger.debug(f"{self.name}: failed to fetch target: {exc}")
                return

            text = response.text or ""
            lower_text = text.lower()
            path_match = re.search(r"/(users|accounts|orders|profiles)/[0-9]+", lower_text)

            if path_match:
                self.add_finding(
                    Finding(
                        title="Potential IDOR object-reference surface detected",
                        description="Object-style route with direct identifier was discovered in application responses.",
                        severity="medium",
                        category="idor",
                        evidence=f"Matched pattern: {path_match.group(0)}",
                        proof_of_concept=f"GET {urljoin(self.target, path_match.group(0))}",
                        remediation="Enforce per-object authorization checks on every resource access.",
                        confidence=0.6,
                    )
                )
                return

            if any(f"{candidate}=" in lower_text for candidate in self._id_candidates):
                self.add_finding(
                    Finding(
                        title="Potential IDOR parameter surface detected",
                        description="Identifier-like parameters were detected and should be authorization-checked per resource.",
                        severity="low",
                        category="idor",
                        evidence="Detected one or more identifier-like query parameter patterns in response content.",
                        proof_of_concept=f"GET {self.target}?id=2",
                        remediation="Validate ownership/authorization for object identifiers at the server side.",
                        confidence=0.5,
                    )
                )