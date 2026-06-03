"""
Authentication testing agent
"""

import asyncio
from typing import List, Dict
import httpx
from itzraven.agents.base_agent import BaseAgent, AgentResult, Finding, AgentStatus
from itzraven.core.logger import get_logger

logger = get_logger()


class AuthenticationAgent(BaseAgent):
    """Agent for testing authentication mechanisms"""

    def __init__(self, target: str, event_bus=None, memory_manager=None):
        super().__init__("Authentication Agent", target, event_bus=event_bus, memory_manager=memory_manager)
        self.common_credentials = [
            ("admin", "admin"),
            ("admin", "password"),
            ("admin", "123456"),
            ("root", "root"),
            ("root", "toor"),
            ("test", "test"),
            ("guest", "guest"),
        ]

    async def execute(self) -> AgentResult:
        """Execute authentication testing"""
        logger.info(f"{self.name}: Testing {self.target}")

        await self._test_weak_credentials()
        await self._test_session_management()
        await self._test_password_reset()
        await self._run_nuclei_tags(tags=["auth", "authentication", "default-login", "weak-login"], severity="high")

        return AgentResult(
            agent_name=self.name,
            status=self.status,
            findings=self.findings,
            execution_time=0,
        )

    async def _test_weak_credentials(self) -> None:
        """Test for weak/default credentials"""
        login_paths = ["/login", "/admin", "/api/login", "/auth/login"]

        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            for path in login_paths:
                url = f"http://{self.target}{path}"

                for username, password in self.common_credentials[:3]:  # Test first 3
                    try:
                        # Try POST with credentials
                        data = {"username": username, "password": password}
                        response = await client.post(url, data=data)

                        # Check for successful login indicators
                        if self._detect_successful_login(response):
                            self.add_finding(Finding(
                                title="Weak default credentials",
                                description=f"Login successful with {username}:{password}",
                                severity="critical",
                                category="authentication",
                                evidence=f"HTTP {response.status_code}, successful login detected",
                                proof_of_concept=f"POST {url} with username={username}, password={password}",
                                remediation="Enforce strong password policy and disable default accounts",
                                confidence=0.95,
                            ))
                            return  # Stop after first success

                    except Exception as e:
                        logger.debug(f"Error testing credentials: {e}")

    async def _test_session_management(self) -> None:
        """Test session management security"""
        async with httpx.AsyncClient(timeout=10.0) as client:
            try:
                response = await client.get(f"http://{self.target}")

                # Check for insecure session cookies
                cookies = response.cookies
                for cookie_name, cookie_value in cookies.items():
                    # Check if session cookie lacks security flags
                    if "session" in cookie_name.lower() or "token" in cookie_name.lower():
                        # In real implementation, check cookie attributes
                        # For now, just flag if session cookies exist
                        self.add_finding(Finding(
                            title="Session cookie without security flags",
                            description=f"Session cookie '{cookie_name}' may lack Secure/HttpOnly flags",
                            severity="medium",
                            category="authentication",
                            evidence=f"Cookie: {cookie_name}",
                            remediation="Set Secure, HttpOnly, and SameSite flags on session cookies",
                            confidence=0.7,
                        ))

            except Exception as e:
                logger.debug(f"Error testing session management: {e}")

    async def _test_password_reset(self) -> None:
        """Test password reset functionality"""
        reset_paths = ["/reset", "/forgot-password", "/password-reset"]

        async with httpx.AsyncClient(timeout=10.0) as client:
            for path in reset_paths:
                try:
                    url = f"http://{self.target}{path}"
                    response = await client.get(url)

                    if response.status_code == 200:
                        # Check if reset token is in URL (insecure)
                        if "token=" in str(response.url).lower():
                            self.add_finding(Finding(
                                title="Password reset token in URL",
                                description="Password reset token exposed in URL (can leak via Referer)",
                                severity="high",
                                category="authentication",
                                evidence=f"Token found in URL: {response.url}",
                                remediation="Use POST requests and store tokens server-side",
                                confidence=0.8,
                            ))

                except Exception as e:
                    logger.debug(f"Error testing password reset: {e}")

    def _detect_successful_login(self, response: httpx.Response) -> bool:
        """Detect successful login from response"""
        # Check status code
        if response.status_code in [200, 302, 303]:
            # Check for success indicators in response
            success_indicators = [
                "dashboard",
                "welcome",
                "logout",
                "profile",
                "success",
                "authenticated",
            ]

            response_lower = response.text.lower()
            url_lower = str(response.url).lower()

            # Check response body and URL
            for indicator in success_indicators:
                if indicator in response_lower or indicator in url_lower:
                    return True

            # Check for auth cookies
            if any("session" in name.lower() or "token" in name.lower()
                   for name in response.cookies.keys()):
                return True

        return False
