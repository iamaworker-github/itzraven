"""
Command Injection detection agent
"""

import asyncio
from typing import List
import httpx
from itzraven.agents.base_agent import BaseAgent, AgentResult, Finding, AgentStatus
from itzraven.core.logger import get_logger

logger = get_logger()


class CommandInjectionAgent(BaseAgent):
    """Agent for detecting command injection vulnerabilities"""

    def __init__(self, target: str, event_bus=None, memory_manager=None):
        super().__init__("Command Injection Agent", target, event_bus=event_bus, memory_manager=memory_manager)
        self.payloads = [
            "; ls",
            "| ls",
            "& ls",
            "`ls`",
            "$(ls)",
            "; whoami",
            "| whoami",
            "& whoami",
            "; sleep 5",
            "| sleep 5",
            "; ping -c 3 127.0.0.1",
            "| ping -c 3 127.0.0.1",
        ]

    async def execute(self) -> AgentResult:
        """Execute command injection testing"""
        logger.info(f"{self.name}: Testing {self.target}")

        await self._test_parameters()
        await self._test_time_based()
        await self._run_nuclei_tags(tags=["command-injection", "cmd-injection", "rce"], severity="critical")

        return AgentResult(
            agent_name=self.name,
            status=self.status,
            findings=self.findings,
            execution_time=0,
        )

    async def _test_parameters(self) -> None:
        """Test parameters for command injection"""
        async with httpx.AsyncClient(timeout=10.0) as client:
            for payload in self.payloads[:6]:  # Test first 6 payloads
                try:
                    params = {
                        "cmd": payload,
                        "command": payload,
                        "exec": payload,
                        "ping": f"127.0.0.1{payload}",
                    }

                    response = await client.get(self.target, params=params)

                    # Check for command output in response
                    if self._detect_command_output(response.text):
                        self.add_finding(Finding(
                            title="Command Injection vulnerability",
                            description=f"Command injection detected with payload: {payload}",
                            severity="critical",
                            category="injection",
                            evidence="Response contains command execution output",
                            proof_of_concept=f"GET {self.target}?cmd={payload}",
                            remediation="Never pass user input directly to system commands. Use safe APIs instead.",
                            confidence=0.9,
                        ))
                        break

                except Exception as e:
                    logger.debug(f"Error testing command injection: {e}")

    async def _test_time_based(self) -> None:
        """Test time-based command injection"""
        async with httpx.AsyncClient(timeout=15.0) as client:
            # Test with sleep command
            sleep_payload = "; sleep 5"

            try:
                import time
                start = time.time()

                params = {"cmd": sleep_payload, "command": sleep_payload}
                response = await client.get(self.target, params=params)

                elapsed = time.time() - start

                # If response took significantly longer, might be vulnerable
                if elapsed >= 4.5:  # Allow some margin
                    self.add_finding(Finding(
                        title="Time-based Command Injection",
                        description="Server execution delayed by injected sleep command",
                        severity="critical",
                        category="injection",
                        evidence=f"Response delayed by {elapsed:.2f}s (expected ~5s)",
                        proof_of_concept=f"GET {self.target}?cmd={sleep_payload}",
                        remediation="Validate and sanitize all user input before system execution",
                        confidence=0.85,
                    ))

            except asyncio.TimeoutError:
                # Timeout might indicate successful sleep injection
                logger.debug("Timeout during time-based test (possible vulnerability)")
            except Exception as e:
                logger.debug(f"Error in time-based test: {e}")

    def _detect_command_output(self, response_text: str) -> bool:
        """Detect command execution output in response"""
        command_indicators = [
            "root:",
            "bin/",
            "usr/",
            "etc/",
            "total ",
            "drwx",
            "-rw-",
            "uid=",
            "gid=",
        ]

        response_lower = response_text.lower()
        return any(indicator.lower() in response_lower for indicator in command_indicators)
