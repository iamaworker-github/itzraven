import re
import asyncio
from typing import List, Dict, Set, Optional
from itzraven.core.logger import get_logger
from itzraven.core.config import get_config
from itzraven.agents.base_agent import BaseAgent, Finding, AgentResult, AgentStatus
from itzraven.agents.osint.osint_base import OSINTBaseAgent

logger = get_logger()


class EmailIntelAgent(OSINTBaseAgent):
    """Email harvesting agent — discovers email addresses associated with a target domain.

    Performs simulated passive email discovery by checking common patterns
    and public sources (no active probing).
    """

    COMMON_PATTERNS: List[str] = [
        "info@{target}",
        "contact@{target}",
        "admin@{target}",
        "support@{target}",
        "sales@{target}",
        "hr@{target}",
        "noreply@{target}",
        "webmaster@{target}",
        "postmaster@{target}",
        "abuse@{target}",
    ]

    def __init__(
        self,
        target: str,
        event_bus=None,
        memory_manager=None,
        scope: Optional[List[str]] = None,
    ):
        super().__init__("Email Intel Agent", target, event_bus=event_bus, memory_manager=memory_manager, scope=scope)
        self.discovered_emails: List[Dict[str, str]] = []
        self.sources_checked: List[str] = []

    async def execute(self) -> AgentResult:
        logger.info(f"{self.name}: Harvesting emails for {self.target}")

        domain = self.target
        if "://" in domain:
            domain = domain.split("://")[-1].split("/")[0]

        await asyncio.gather(
            self._check_common_patterns(domain),
            self._check_security_txt(domain),
            self._check_web_contact(domain),
            return_exceptions=True,
        )

        self._create_findings()

        return AgentResult(
            agent_name=self.name,
            status=self.status,
            findings=self.findings,
            execution_time=0,
            metadata={
                "emails_found": self.discovered_emails,
                "sources_checked": self.sources_checked,
            },
        )

    async def _check_common_patterns(self, domain: str) -> None:
        for pattern in self.COMMON_PATTERNS:
            email = pattern.replace("{target}", domain)
            self.discovered_emails.append({
                "email": email,
                "source": "common_pattern",
                "confidence": "low",
            })
        self.sources_checked.append("common_patterns")

    async def _check_security_txt(self, domain: str) -> None:
        self.sources_checked.append("security.txt")
        try:
            import httpx
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
                for path in ["/.well-known/security.txt", "/security.txt"]:
                    try:
                        resp = await client.get(f"https://{domain}{path}")
                        if resp.status_code == 200:
                            found = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", resp.text)
                            for addr in found:
                                self.discovered_emails.append({
                                    "email": addr,
                                    "source": f"security.txt ({path})",
                                    "confidence": "high",
                                })
                    except Exception:
                        pass
        except ImportError:
            logger.warning(f"{self.name}: httpx not installed — skipping security.txt check")

    async def _check_web_contact(self, domain: str) -> None:
        self.sources_checked.append("web_scrape")
        try:
            import httpx
            from bs4 import BeautifulSoup
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
                try:
                    resp = await client.get(f"https://{domain}")
                    if resp.status_code == 200:
                        soup = BeautifulSoup(resp.text, "html.parser")
                        text = soup.get_text()
                        found = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", text)
                        seen: Set[str] = set()
                        for addr in found:
                            if addr.lower() not in seen:
                                seen.add(addr.lower())
                                self.discovered_emails.append({
                                    "email": addr,
                                    "source": "web_scrape",
                                    "confidence": "medium",
                                })
                except Exception:
                    pass
        except ImportError:
            logger.warning(f"{self.name}: httpx/bs4 not installed — skipping web scrape")

    def _create_findings(self) -> None:
        emails = [e["email"] for e in self.discovered_emails]
        if emails:
            self.add_finding(Finding(
                title="Discovered Email Addresses",
                description=f"Found {len(set(emails))} email address(es) associated with {self.target}",
                severity="info",
                category="osint_email",
                evidence=f"Emails: {', '.join(sorted(set(emails))[:10])}",
                confidence=0.7,
            ))
