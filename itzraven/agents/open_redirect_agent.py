"""
Open Redirect detection agent
"""

import asyncio
import re
from typing import List, Dict
import httpx
from urllib.parse import urlparse, urljoin
from itzraven.agents.base_agent import BaseAgent, AgentResult, Finding, AgentStatus
from itzraven.core.logger import get_logger

logger = get_logger()


class OpenRedirectAgent(BaseAgent):
    """Agent for detecting open redirect vulnerabilities"""

    def __init__(self, target: str, event_bus=None, memory_manager=None):
        super().__init__("Open Redirect Agent", target, event_bus=event_bus, memory_manager=memory_manager)
        self.redirect_params = [
            "url", "redirect", "redirect_uri", "redirect_url", "return",
            "return_to", "return_url", "next", "next_url", "target",
            "dest", "destination", "go", "continue", "view", "image_url",
            "link", "file", "load", "path", "out", "callback", "ref",
        ]
        self.redirect_payloads = [
            "https://evil.com",
            "//evil.com",
            "/\\evil.com",
            "https://evil.com/",
            "http://evil.com",
            "//evil.com/",
            "https:evil.com",
            "///evil.com",
            ";@evil.com",
            "https://evil.com%23",
            "https://evil.com%00",
            "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
            "file:///etc/passwd",
        ]
        self.redirect_domains = [
            "evil.com",
            "malicious.net",
            "attacker.io",
            "evil.com:8080",
            "evil.com\\@target.com",
        ]

    async def execute(self) -> AgentResult:
        logger.info(f"{self.name}: Testing {self.target}")
        await self._test_redirect_parameters()
        await self._test_header_injection_redirect()
        await self._run_nuclei_tags(tags=["redirect", "open-redirect", "url-redirect"], severity="medium")

        return AgentResult(
            agent_name=self.name,
            status=self.status,
            findings=self.findings,
            execution_time=0,
        )

    async def _test_redirect_parameters(self) -> None:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=False, verify=False) as client:
            test_urls = self.get_test_urls()
            for url in test_urls:
                for param in self.redirect_params:
                    for payload in self.redirect_payloads:
                        try:
                            params = {param: payload}
                            response = await client.get(url, params=params)
                            if self._detect_open_redirect(response, payload):
                                self.add_finding(Finding(
                                    title=f"Open Redirect via {param} parameter",
                                    description=f"Open redirect detected. Parameter '{param}' redirects to external domain with payload: {payload}",
                                    severity="medium",
                                    category="redirect",
                                    evidence=f"HTTP {response.status_code} → Location: {response.headers.get('location', 'N/A')}",
                                    proof_of_concept=f"GET {url}?{param}={payload}",
                                    remediation="Maintain an allowlist of valid redirect URLs. Do not accept user-controlled URLs.",
                                    confidence=0.8,
                                ))
                                break
                        except httpx.HTTPStatusError:
                            pass
                        except Exception as e:
                            logger.debug(f"Error testing redirect: {e}")

    async def _test_header_injection_redirect(self) -> None:
        host = urlparse(self.target).netloc or self.target.split("/")[0]
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=False, verify=False) as client:
            for domain in self.redirect_domains:
                try:
                    headers = {"Host": f"{host}:{domain}"}
                    response = await client.get(self.target, headers=headers)
                    location = response.headers.get("location", "")
                    if domain in location or "evil" in location:
                        self.add_finding(Finding(
                            title="Open Redirect via Host Header Injection",
                            description=f"Host header injection leads to redirect: {location}",
                            severity="high",
                            category="redirect",
                            evidence=f"Host: {domain} → Location: {location}",
                            proof_of_concept=f"GET {self.target} with Host: {host}:{domain}",
                            remediation="Validate Host header against whitelist. Do not use Host header in redirect logic.",
                            confidence=0.75,
                        ))
                        break
                except Exception as e:
                    logger.debug(f"Error testing header redirect: {e}")

    def _detect_open_redirect(self, response: httpx.Response, payload: str) -> bool:
        location = response.headers.get("location", "")
        if not location:
            return False
        location_lower = location.lower()
        known_bad = ["evil.com", "malicious.net", "attacker.io", "javascript:", "data:"]
        return any(bad in location_lower for bad in known_bad) or payload.lower() in location_lower
