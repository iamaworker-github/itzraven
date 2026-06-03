"""
XSS (Cross-Site Scripting) detection agent
"""

import asyncio
from typing import List, Optional
import httpx
from itzraven.agents.base_agent import BaseAgent, AgentResult, Finding, AgentStatus
from itzraven.core.logger import get_logger

logger = get_logger()


class XSSAgent(BaseAgent):
    """Agent for detecting XSS vulnerabilities"""

    def __init__(self, target: str, event_bus=None, memory_manager=None):
        super().__init__("XSS Agent", target, event_bus=event_bus, memory_manager=memory_manager)
        self.payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src=javascript:alert('XSS')>",
            "<body onload=alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>",
            "'-alert('XSS')-'",
            "\"><script>alert('XSS')</script>",
            "<scr<script>ipt>alert('XSS')</scr</script>ipt>",
        ]

    async def execute(self) -> AgentResult:
        """Execute XSS testing"""
        logger.info(f"{self.name}: Testing {self.target}")

        # Test reflected XSS
        await self._test_reflected_xss()

        # Test DOM-based XSS (requires browser)
        if self.browser:
            await self._test_dom_xss()

        await self._run_nuclei_tags(tags=["xss", "reflected-xss", "stored-xss"], severity="high")

        return AgentResult(
            agent_name=self.name,
            status=self.status,
            findings=self.findings,
            execution_time=0,
        )

    async def _test_reflected_xss(self) -> None:
        """Test for reflected XSS"""
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            for payload in self.payloads:
                try:
                    # Test in URL parameters
                    params = {"q": payload, "search": payload, "name": payload}
                    response = await client.get(self.target, params=params)

                    # Check if payload is reflected in response
                    if payload in response.text:
                        # Check if it's in a dangerous context
                        if self._is_dangerous_context(response.text, payload):
                            self.add_finding(Finding(
                                title="Reflected XSS vulnerability",
                                description=f"XSS payload reflected in response: {payload}",
                                severity="high",
                                category="xss",
                                evidence=f"Payload found in response without proper encoding",
                                proof_of_concept=f"GET {self.target}?q={payload}",
                                remediation="Encode all user input before rendering in HTML context",
                                confidence=0.85,
                            ))
                            break

                except Exception as e:
                    logger.debug(f"Error testing reflected XSS: {e}")

    async def _test_dom_xss(self) -> None:
        """Test for DOM-based XSS using browser"""
        try:
            await self.browser.start()

            for payload in self.payloads[:5]:  # Test fewer payloads with browser
                try:
                    # Create page with payload in URL fragment
                    url = f"{self.target}#{payload}"
                    page = await self.browser.new_page(url)

                    # Wait a bit for JavaScript to execute
                    await asyncio.sleep(1)

                    # Check if alert was triggered
                    if await self.browser.find_xss(page, payload):
                        self.add_finding(Finding(
                            title="DOM-based XSS vulnerability",
                            description=f"DOM XSS detected with payload: {payload}",
                            severity="high",
                            category="xss",
                            evidence="JavaScript alert was triggered",
                            proof_of_concept=f"Visit: {url}",
                            remediation="Sanitize data from URL fragments and use safe DOM APIs",
                            confidence=0.95,
                        ))
                        await self.browser.close_page(page)
                        break

                    await self.browser.close_page(page)

                except Exception as e:
                    logger.debug(f"Error testing DOM XSS: {e}")

        except Exception as e:
            logger.error(f"Browser automation failed: {e}")

    def _is_dangerous_context(self, html: str, payload: str) -> bool:
        """Check if payload is in a dangerous HTML context"""
        # Find payload position
        idx = html.find(payload)
        if idx == -1:
            return False

        # Check context around payload (simplified check)
        context = html[max(0, idx-50):min(len(html), idx+len(payload)+50)]

        # Dangerous if not properly encoded
        dangerous_patterns = [
            "<script",
            "onerror=",
            "onload=",
            "javascript:",
            "<iframe",
            "<img",
            "<svg",
        ]

        return any(pattern in context.lower() for pattern in dangerous_patterns)
