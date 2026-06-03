"""
LDAP Injection detection agent
"""

import asyncio
import httpx
from typing import List
from urllib.parse import urlparse

from itzraven.agents.base_agent import BaseAgent, AgentResult
from itzraven.core.logger import get_logger

logger = get_logger()


class LDAPInjectionAgent(BaseAgent):
    """Agent for detecting LDAP injection vulnerabilities."""

    def __init__(self, target: str, event_bus=None, memory_manager=None):
        super().__init__("LDAP Injection Agent", target, event_bus=event_bus, memory_manager=memory_manager)
        self.payloads = [
            "*)(uid=*))(|(uid=*",
            "*)(|(cn=*))",
            "*)(|(password=*))",
            "admin*)(uid=*))(|(uid=*",
            "*/*",
            "admin)(&)",
        ]

    async def execute(self) -> AgentResult:
        logger.info(f"{self.name}: Testing {self.target}")
        await self._test_ldap_injection()
        await self._run_nuclei_tags(tags=["ldap-injection"], severity="high")
        return AgentResult(
            agent_name=self.name,
            status=self.status,
            findings=self.findings,
            execution_time=0,
        )

    async def _test_ldap_injection(self) -> None:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            params = ["user", "username", "uid", "cn", "search", "q", "filter", "dc"]
            for payload in self.payloads:
                for param in params:
                    try:
                        if "?" in self.target:
                            test_url = f"{self.target}&{param}={payload}"
                        else:
                            test_url = f"{self.target}?{param}={payload}"
                        r = await client.get(test_url)
                        if self._is_ldap_success(r.text):
                            self.add_finding(
                                title=f"LDAP Injection via {param}",
                                description=f"Parameter '{param}' appears injectable with payload: {payload}",
                                severity="high", category="ldap_injection",
                                evidence=f"Param: {param}, Payload: {payload}",
                            )
                    except Exception:
                        pass

    def _is_ldap_success(self, text: str) -> bool:
        indicators = ["LDAP", "ldap", "protocol error", "malformed filter", "search error"]
        exit_indicators = ["login failed", "invalid credentials", "not found", "404"]
        return any(i in text for i in indicators) and not any(i in text.lower() for i in exit_indicators)
