"""
Host Header Injection & Password Reset Poisoning detection agent
"""

import asyncio
from typing import List, Dict, Any
import httpx
from urllib.parse import urlparse
from itzraven.agents.base_agent import BaseAgent, AgentResult, Finding, AgentStatus
from itzraven.core.logger import get_logger

logger = get_logger()


class HostHeaderInjectionAgent(BaseAgent):
    """Agent for detecting Host Header Injection and password reset poisoning"""

    def __init__(self, target: str, event_bus=None, memory_manager=None):
        super().__init__("Host Header Injection Agent", target, event_bus=event_bus, memory_manager=memory_manager)
        self.test_hosts = [
            "evil.com",
            "attacker.com",
            "evil.com:443",
            "localhost",
            "127.0.0.1",
            "0.0.0.0",
        ]
        self.test_headers = [
            ("X-Forwarded-Host", "evil.com"),
            ("X-Forwarded-Host", "attacker.com"),
            ("X-Host", "evil.com"),
            ("X-Forwarded-Server", "evil.com"),
            ("X-HTTP-Host-Override", "evil.com"),
            ("Forwarded", "host=evil.com"),
            ("X-Original-URL", "evil.com"),
            ("X-Rewrite-URL", "evil.com"),
        ]

    async def execute(self) -> AgentResult:
        logger.info(f"{self.name}: Testing {self.target}")
        await self._test_host_header_injection()
        await self._test_forwarded_host()
        await self._test_password_reset_poisoning()
        await self._run_nuclei_tags(tags=["host-header", "host-header-injection", "hhi"], severity="high")

        return AgentResult(
            agent_name=self.name,
            status=self.status,
            findings=self.findings,
            execution_time=0,
        )

    def _get_base_domain(self) -> str:
        parsed = urlparse(self.target)
        return parsed.netloc or self.target.split("/")[0]

    async def _test_host_header_injection(self) -> None:
        base_domain = self._get_base_domain()
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=False, verify=False) as client:
            for malicious_host in self.test_hosts:
                try:
                    headers = {"Host": f"{base_domain}:{malicious_host}"}
                    response = await client.get(self.target, headers=headers)
                    body = response.text.lower()
                    location = response.headers.get("location", "")

                    if malicious_host in body or malicious_host in location:
                        self.add_finding(Finding(
                            title="Host Header Injection",
                            description=f"Host header injection: Host set to '{malicious_host}' is reflected in response/redirect",
                            severity="high",
                            category="injection",
                            evidence=f"Host: {base_domain}:{malicious_host} → reflected in response",
                            proof_of_concept=f"GET {self.target} with Host: {base_domain}:{malicious_host}",
                            remediation="Do not trust Host header. Use a whitelist of allowed Host values. Use SERVER_NAME instead.",
                            confidence=0.85,
                        ))
                        break
                except Exception as e:
                    logger.debug(f"Error testing host header: {e}")

    async def _test_forwarded_host(self) -> None:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=False, verify=False) as client:
            for header_name, header_value in self.test_headers:
                try:
                    headers = {header_name: header_value}
                    response = await client.get(self.target, headers=headers)
                    body = response.text.lower()
                    location = response.headers.get("location", "")

                    if header_value in body or header_value in location:
                        self.add_finding(Finding(
                            title=f"Forwarded Host Injection via {header_name}",
                            description=f"Server reflects {header_name}: {header_value} in response",
                            severity="high",
                            category="injection",
                            evidence=f"{header_name}: {header_value} reflected in response body/redirect",
                            proof_of_concept=f"GET {self.target} with {header_name}: {header_value}",
                            remediation="Do not trust X-Forwarded-Host and similar headers. Use whitelist validation.",
                            confidence=0.8,
                        ))
                        break
                except Exception as e:
                    logger.debug(f"Error testing {header_name}: {e}")

    async def _test_password_reset_poisoning(self) -> None:
        reset_paths = ["/reset", "/forgot-password", "/password-reset",
                       "/api/reset", "/api/forgot-password", "/api/password-reset"]

        async with httpx.AsyncClient(timeout=10.0, follow_redirects=False, verify=False) as client:
            base_domain = self._get_base_domain()

            for path in reset_paths:
                url = self.target.rstrip("/") + path
                for header_name, header_value in self.test_headers[:4]:
                    try:
                        headers = {"Host": base_domain, header_name: header_value}
                        response = await client.post(url, headers=headers,
                                                     data={"email": "test@test.com"})

                        body = response.text.lower()
                        if header_value in body:
                            self.add_finding(Finding(
                                title="Password Reset Poisoning",
                                description=f"Password reset link can be poisoned via {header_name}. Host reflected: {header_value}",
                                severity="critical",
                                category="injection",
                                evidence=f"POST {url} with {header_name}: {header_value} → reflected in response",
                                proof_of_concept=f"POST {url} with {header_name}: {header_value}",
                                remediation="Generate password reset URLs using SERVER_NAME or a fixed base URL, not Host header.",
                                confidence=0.9,
                            ))
                            break
                    except Exception as e:
                        logger.debug(f"Error testing reset poisoning: {e}")
