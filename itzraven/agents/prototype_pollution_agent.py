"""
Prototype Pollution detection agent
"""

import asyncio
import json
import httpx
from typing import List
from urllib.parse import urlparse, urlencode, parse_qs

from itzraven.agents.base_agent import BaseAgent, AgentResult, Finding
from itzraven.core.logger import get_logger

logger = get_logger()


class PrototypePollutionAgent(BaseAgent):
    """Agent for detecting client-side prototype pollution vulnerabilities."""

    def __init__(self, target: str, event_bus=None, memory_manager=None):
        super().__init__("Prototype Pollution Agent", target, event_bus=event_bus, memory_manager=memory_manager)
        self.sinks = [
            "https://cdnjs.cloudflare.com/ajax/libs/lodash.js/",
            "https://code.jquery.com/jquery-",
            "https://cdn.jsdelivr.net/npm/lodash@",
        ]
        self.pp_payloads = [
            '{"__proto__":{"test":"polluted"}}',
            '{"constructor":{"prototype":{"test":"polluted"}}}',
            "__proto__[test]=polluted",
            "constructor[prototype][test]=polluted",
        ]

    async def execute(self) -> AgentResult:
        logger.info(f"{self.name}: Testing {self.target}")
        await self._check_client_libraries()
        await self._test_url_sinks()
        await self._run_nuclei_tags(tags=["prototype-pollution"], severity="high")
        return AgentResult(
            agent_name=self.name,
            status=self.status,
            findings=self.findings,
            execution_time=0,
        )

    async def _check_client_libraries(self) -> None:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            for sink in self.sinks:
                try:
                    r = await client.get(self.target)
                    if sink.split("//")[1].split("/")[0] in r.text:
                        lib = sink.split("/")[3].split(".")[0]
                        self.add_finding(
                            title=f"Prototype Pollution Sink: {lib}",
                            description=f"Client-side library {lib} detected — potential prototype pollution via URL/JSON.parse sinks",
                            severity="medium", category="prototype_pollution",
                            evidence=f"Library {lib} loaded from {sink}",
                        )
                except Exception:
                    pass

    async def _test_url_sinks(self) -> None:
        parsed = urlparse(self.target)
        for payload in self.pp_payloads:
            if "?" in self.target:
                test_url = f"{self.target}&{payload}"
            else:
                test_url = f"{self.target}?{payload}"
            try:
                async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
                    r = await client.get(test_url)
                    if "polluted" in r.text and self._parse_domain(parsed.hostname or "") in r.text:
                        self.add_finding(
                            title="Prototype Pollution via URL params",
                            description=f"URL parameter-based prototype pollution detected with payload: {payload}",
                            severity="high", category="prototype_pollution",
                            evidence=f"Payload: {payload}, Response: {r.text[:200]}",
                        )
            except Exception:
                pass

    def _parse_domain(self, url: str) -> str:
        return url.replace("https://", "").replace("http://", "").split("/")[0]
