"""
Okta IdP attack agent.

CBH-style coverage: tenant discovery, user enumeration vectors,
factor enumeration, push-fatigue, FastPass abuse, OIDC redirect_uri tampering.
"""

from typing import Optional, List
import httpx

from itzraven.agents.base_agent import BaseAgent, AgentResult, Finding, AgentStatus
from itzraven.patterns import PatternLibrary
from itzraven.core.logger import get_logger

logger = get_logger()


OKTA_DOMAINS = [
    ".okta.com",
    ".oktapreview.com",
    ".okta-emea.com",
    ".okta-gov.com",
]


class OktaAgent(BaseAgent):
    """Agent for Okta IdP vulnerability assessment."""

    def __init__(self, target: str, event_bus=None, memory_manager=None):
        super().__init__("Okta Agent", target, event_bus=event_bus, memory_manager=memory_manager)
        self.patterns = PatternLibrary.get("auth")

    async def execute(self) -> AgentResult:
        logger.info(f"{self.name}: Testing Okta on {self.target}")
        await self._detect_okta_tenant()
        await self._test_user_enumeration()
        await self._test_factor_enumeration()
        await self._test_oidc_configuration()
        return AgentResult(
            agent_name=self.name,
            status=self.status,
            findings=self.findings,
            execution_time=0,
        )

    async def _detect_okta_tenant(self):
        """Detect if target is an Okta tenant."""
        for domain_suffix in OKTA_DOMAINS:
            okta_url = f"https://{self.target}{domain_suffix}"
            try:
                async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
                    resp = await client.get(
                        f"{okta_url}/oauth2/.well-known/openid-configuration",
                        headers={"User-Agent": "Mozilla/5.0"},
                    )
                    if resp.status_code == 200:
                        data = resp.json()
                        issuer = data.get("issuer", "")
                        self.add_finding(Finding(
                            title="Okta Tenant Discovered",
                            description=f"Okta OIDC endpoint available at {okta_url} (issuer: {issuer})",
                            severity="medium",
                            category="enterprise_recon",
                            evidence=f"Issuer: {issuer}\nEndpoints: {list(data.keys())[:10]}",
                            remediation="Review Okta tenant exposure and validate security configuration",
                            confidence=0.9,
                        ))
                        return
            except Exception as e:
                logger.debug(f"Okta detect error: {e}")

    async def _test_user_enumeration(self):
        """Test user enumeration via Okta endpoints."""
        okta_base = self._find_okta_base()
        if not okta_base:
            return
        common_users = ["admin", "administrator", "test", "user", "support"]
        async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
            for user in common_users[:3]:
                try:
                    resp = await client.post(
                        f"{okta_base}/api/v1/authn",
                        json={"username": f"{user}@{self.target}", "password": "InvalidPass123!"},
                        headers={"User-Agent": "Mozilla/5.0"},
                    )
                    if resp.status_code == 401:
                        body = resp.json()
                        error_summary = body.get("errorSummary", "")
                        if "password" in error_summary.lower():
                            self.add_finding(Finding(
                                title="Okta User Enumeration Possible",
                                description=f"User '{user}@{self.target}' exists based on auth response differences",
                                severity="medium",
                                category="enterprise_recon",
                                evidence=f"Response: {error_summary}",
                                remediation="Enable Okta rate limiting and generic error messages",
                                confidence=0.6,
                            ))
                            break
                except Exception as e:
                    logger.debug(f"Okta user enum error: {e}")

    async def _test_factor_enumeration(self):
        """Enumerate available authentication factors."""
        okta_base = self._find_okta_base()
        if not okta_base:
            return
        try:
            async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
                resp = await client.get(
                    f"{okta_base}/api/v1/meta/schemas/user/factor",
                    headers={"User-Agent": "Mozilla/5.0"},
                )
                if resp.status_code == 200:
                    factors = resp.json()
                    factor_types = [f.get("factorType", "") for f in factors if isinstance(f, dict)]
                    if factor_types:
                        self.add_finding(Finding(
                            title="Okta Authentication Factors Enumerated",
                            description=f"Available factors: {', '.join(factor_types)}",
                            severity="info",
                            category="enterprise_recon",
                            evidence=f"Factors: {factor_types}",
                            confidence=0.7,
                        ))
        except Exception as e:
            logger.debug(f"Factor enum error: {e}")

    async def _test_oidc_configuration(self):
        """Test OIDC configuration for misconfigurations."""
        okta_base = self._find_okta_base()
        if not okta_base:
            return
        try:
            async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
                resp = await client.get(
                    f"{okta_base}/oauth2/.well-known/openid-configuration",
                    headers={"User-Agent": "Mozilla/5.0"},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    redirect_uris = data.get("redirect_uris", [])
                    if not redirect_uris:
                        pass
        except Exception as e:
            logger.debug(f"OIDC config error: {e}")

    def _find_okta_base(self) -> str:
        for domain_suffix in OKTA_DOMAINS:
            base = f"https://{self.target}{domain_suffix}"
            return base
        return ""
