"""
CORS (Cross-Origin Resource Sharing) misconfiguration detection agent
"""

import asyncio
from typing import List
import httpx
from itzraven.agents.base_agent import BaseAgent, AgentResult, Finding, AgentStatus
from itzraven.core.logger import get_logger

logger = get_logger()


class CORSAgent(BaseAgent):
    """Agent for detecting CORS misconfigurations"""

    def __init__(self, target: str, event_bus=None, memory_manager=None):
        super().__init__("CORS Agent", target, event_bus=event_bus, memory_manager=memory_manager)
        self.test_origins = [
            "https://evil.com",
            "null",
            "https://evil.com/",
            "https://evil.com.evil.com",
            "https://evilevil.com",
            "http://evil.com",
            "https://evil.com:8080",
        ]

    async def execute(self) -> AgentResult:
        logger.info(f"{self.name}: Testing {self.target}")
        await self._test_origin_reflection()
        await self._test_wildcard_origin()
        await self._test_preflight_bypass()
        await self._run_nuclei_tags(tags=["cors", "misconfiguration-cors", "cors-misconfig"], severity="medium")

        return AgentResult(
            agent_name=self.name,
            status=self.status,
            findings=self.findings,
            execution_time=0,
        )

    async def _test_origin_reflection(self) -> None:
        async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
            test_urls = self.get_test_urls()
            for url in test_urls:
                for origin in self.test_origins:
                    try:
                        headers = {"Origin": origin}
                        response = await client.get(url, headers=headers)
                        acao = response.headers.get("access-control-allow-origin", "")
                        acac = response.headers.get("access-control-allow-credentials", "")

                        if origin in acao or acao == "*" or acao == "null":
                            confidence = 0.9 if origin == "null" else 0.8 if acao == "*" else 0.7
                            severity = "critical" if (acao == "*" or origin == "null") and acac.lower() == "true" else "high"

                            self.add_finding(Finding(
                                title="CORS Misconfiguration - Origin Reflection",
                                description=f"CORS allows origin '{origin}' via 'Access-Control-Allow-Origin: {acao}'. Credentials: {acac}",
                                severity=severity,
                                category="misconfiguration",
                                evidence=f"ACAO: {acao}, ACAC: {acac}, Origin sent: {origin}",
                                proof_of_concept=f"GET {url} with Origin: {origin}",
                                remediation="Whitelist specific trusted origins. Never reflect Origin header or use 'null' or wildcard with credentials.",
                                confidence=confidence,
                            ))
                            break
                    except Exception as e:
                        logger.debug(f"Error testing CORS: {e}")

    async def _test_wildcard_origin(self) -> None:
        async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
            test_urls = self.get_test_urls()
            for url in test_urls:
                try:
                    response = await client.get(url)
                    acao = response.headers.get("access-control-allow-origin", "")
                    acac = response.headers.get("access-control-allow-credentials", "")

                    if acao == "*":
                        severity = "critical" if acac.lower() == "true" else "high"
                        self.add_finding(Finding(
                            title="CORS Wildcard Origin",
                            description=f"CORS configured with wildcard origin '*' allowing any site (credentials: {acac})",
                            severity=severity,
                            category="misconfiguration",
                            evidence=f"ACAO: {acao}, ACAC: {acac}",
                            remediation="Use specific origins instead of wildcard. Wildcard + credentials is insecure.",
                            confidence=0.95,
                        ))
                except Exception as e:
                    logger.debug(f"Error testing wildcard CORS: {e}")

    async def _test_preflight_bypass(self) -> None:
        async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
            test_urls = self.get_test_urls()
            for url in test_urls:
                for origin in self.test_origins:
                    try:
                        headers = {
                            "Origin": origin,
                            "Access-Control-Request-Method": "GET",
                            "Access-Control-Request-Headers": "X-Custom-Header",
                        }
                        response = await client.options(url, headers=headers)
                        acao = response.headers.get("access-control-allow-origin", "")
                        acam = response.headers.get("access-control-allow-methods", "")
                        acah = response.headers.get("access-control-allow-headers", "")

                        if origin in acao or acao == "*":
                            self.add_finding(Finding(
                                title="CORS - Preflight Request Bypass",
                                description=f"CORS preflight allows arbitrary origin. Methods: {acam}, Headers: {acah}",
                                severity="high",
                                category="misconfiguration",
                                evidence=f"OPTIONS {url} → ACAO: {acao}, ACAM: {acam}, ACAH: {acah}",
                                proof_of_concept=f"OPTIONS {url} with Origin: {origin}",
                                remediation="Restrict CORS preflight to specific origins, methods, and headers.",
                                confidence=0.8,
                            ))
                            break
                    except Exception as e:
                        logger.debug(f"Error testing preflight: {e}")
