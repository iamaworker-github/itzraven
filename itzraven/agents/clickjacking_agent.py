"""
Clickjacking / UI Redress detection agent
"""

import asyncio
from typing import List
import httpx
from itzraven.agents.base_agent import BaseAgent, AgentResult, Finding, AgentStatus
from itzraven.core.logger import get_logger

logger = get_logger()


class ClickjackingAgent(BaseAgent):
    """Agent for detecting clickjacking / UI redress vulnerabilities"""

    def __init__(self, target: str, event_bus=None, memory_manager=None):
        super().__init__("Clickjacking Agent", target, event_bus=event_bus, memory_manager=memory_manager)
        self.test_pages = ["/", "/login", "/admin", "/dashboard", "/account", "/settings", "/api"]

    async def execute(self) -> AgentResult:
        logger.info(f"{self.name}: Testing {self.target}")
        await self._test_frame_options()
        await self._test_csp_frame_ancestors()
        await self._run_nuclei_tags(tags=["clickjacking", "click-jacking", "missing-header"], severity="medium")

        return AgentResult(
            agent_name=self.name,
            status=self.status,
            findings=self.findings,
            execution_time=0,
        )

    async def _test_frame_options(self) -> None:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True, verify=False) as client:
            test_urls = self.get_test_urls()
            for url in test_urls:
                try:
                    response = await client.get(url)
                    xfo = response.headers.get("x-frame-options", "").lower()
                    csp = response.headers.get("content-security-policy", "")

                    if not xfo and "frame-ancestors" not in csp:
                        self.add_finding(Finding(
                            title="Missing Clickjacking Protection",
                            description=f"No X-Frame-Options or CSP frame-ancestors header on {url}",
                            severity="medium",
                            category="misconfiguration",
                            evidence=f"X-Frame-Options: {xfo or 'NOT SET'} | CSP: {'SET' if csp else 'NOT SET'}",
                            proof_of_concept=f"<iframe src='{url}' width='800' height='600'></iframe>",
                            remediation="Set X-Frame-Options: DENY or SAMEORIGIN. Add frame-ancestors to CSP.",
                            confidence=0.95,
                        ))
                        break
                    elif xfo and xfo not in ("deny", "sameorigin"):
                        self.add_finding(Finding(
                            title="Weak X-Frame-Options Setting",
                            description=f"X-Frame-Options is '{xfo}' which may be too permissive",
                            severity="low",
                            category="misconfiguration",
                            evidence=f"X-Frame-Options: {xfo}",
                            remediation="Use X-Frame-Options: DENY or SAMEORIGIN",
                            confidence=0.8,
                        ))
                except Exception as e:
                    logger.debug(f"Error testing frame options: {e}")

    async def _test_csp_frame_ancestors(self) -> None:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True, verify=False) as client:
            test_urls = self.get_test_urls()
            for url in test_urls:
                try:
                    response = await client.get(url)
                    csp = response.headers.get("content-security-policy", "")

                    if "frame-ancestors" in csp:
                        if "'none'" in csp:
                            continue
                        if "'self'" not in csp and "*" in csp:
                            self.add_finding(Finding(
                                title="Overly Permissive CSP frame-ancestors",
                                description="CSP frame-ancestors allows all domains via wildcard",
                                severity="high",
                                category="misconfiguration",
                                evidence=f"CSP: {csp}",
                                remediation="Restrict frame-ancestors to specific origins: frame-ancestors 'self'",
                                confidence=0.9,
                            ))
                except Exception as e:
                    logger.debug(f"Error testing CSP frame-ancestors: {e}")
