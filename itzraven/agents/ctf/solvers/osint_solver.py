import os
import re
import json
from typing import List, Optional

from itzraven.core.logger import get_logger
from itzraven.agents.base_agent import BaseAgent, Finding, AgentResult, AgentStatus
from itzraven.agents.ctf.flag_extractor import FlagExtractor

logger = get_logger()


USERNAME_PATTERNS = re.compile(
    r"(?:@|user(?:name)?[=: ]|login[=: ]|handle[=: ])\s*([a-zA-Z][a-zA-Z0-9_.-]{2,30})",
    re.IGNORECASE,
)
EMAIL_PATTERN = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
URL_PATTERN = re.compile(r"https?://[^\s<>\"']+|www\.[^\s<>\"']+")
PHONE_PATTERN = re.compile(r"\+?\d{1,3}[-.\s]?\(?\d{1,4}?\)?[-.\s]?\d{1,4}[-.\s]?\d{1,9}")


class OSINTSolverAgent(BaseAgent):
    def __init__(self, target: str, event_bus=None, memory_manager=None):
        super().__init__(name="OSINT Solver", target=target, event_bus=event_bus, memory_manager=memory_manager)
        self.flag_extractor = FlagExtractor()

    async def execute(self) -> AgentResult:
        logger.info(f"{self.name}: Performing OSINT analysis on {self.target}")

        findings = []
        target_text = self.target

        try:
            if os.path.isfile(target_text):
                with open(target_text, "r", errors="replace") as f:
                    target_text = f.read()

            findings.extend(self._search_emails(target_text))
            findings.extend(self._search_urls(target_text))
            findings.extend(self._search_usernames(target_text))
            findings.extend(self._search_phones(target_text))
            findings.extend(self._search_metadata(target_text))
            findings.extend(self._search_location(target_text))

            flags = self.flag_extractor.extract(target_text)
            for flag in flags:
                f = Finding(
                    title="Flag Found in OSINT Data",
                    description="Extracted flag from OSINT analysis",
                    severity="critical",
                    category="CTF",
                    evidence=flag,
                    confidence=1.0,
                )
                self.add_finding(f)
                findings.append(f)

        except Exception as e:
            logger.error(f"{self.name} error: {e}")
            f = Finding(
                title="OSINT Analysis Error",
                description=str(e),
                severity="info",
                category="CTF",
                evidence=str(e),
            )
            self.add_finding(f)
            findings.append(f)

        return AgentResult(
            agent_name=self.name,
            status=self.status,
            findings=self.findings,
            execution_time=0,
        )

    def _search_emails(self, text: str) -> List[Finding]:
        results = []
        emails = set(EMAIL_PATTERN.findall(text))
        for email in emails:
            f = Finding(
                title="Email Address Found",
                description=f"Email: {email}",
                severity="low",
                category="CTF",
                evidence=email,
                confidence=0.9,
            )
            self.add_finding(f)
            results.append(f)
        return results

    def _search_urls(self, text: str) -> List[Finding]:
        results = []
        urls = set(URL_PATTERN.findall(text))
        for url in urls:
            f = Finding(
                title="URL Found",
                description=f"URL: {url}",
                severity="low",
                category="CTF",
                evidence=url,
                confidence=0.9,
            )
            self.add_finding(f)
            results.append(f)
        return results

    def _search_usernames(self, text: str) -> List[Finding]:
        results = []
        usernames = set(USERNAME_PATTERNS.findall(text))
        for username in usernames:
            if len(username) >= 3:
                f = Finding(
                    title="Username/Handle Found",
                    description=f"Potential username/handle: {username}",
                    severity="low",
                    category="CTF",
                    evidence=username,
                    confidence=0.6,
                )
                self.add_finding(f)
                results.append(f)
        return results

    def _search_phones(self, text: str) -> List[Finding]:
        results = []
        phones = set(PHONE_PATTERN.findall(text))
        for phone in phones:
            if len(phone) >= 7:
                f = Finding(
                    title="Phone Number Found",
                    description=f"Potential phone number: {phone}",
                    severity="low",
                    category="CTF",
                    evidence=phone,
                    confidence=0.7,
                )
                self.add_finding(f)
                results.append(f)
        return results

    def _search_metadata(self, text: str) -> List[Finding]:
        results = []
        patterns = [
            (r"(?:GPS|GPSPosition|Latitude|Longitude)[=: ].{4,}", "GPS coordinate"),
            (r"(?:Instagram|Twitter|Facebook|LinkedIn)[=: ]\S+", "Social media profile"),
            (r"(?:IP|ip)[=: ]\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", "IP address"),
        ]
        for pattern, label in patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches[:5]:
                f = Finding(
                    title=f"Metadata Found: {label}",
                    description=f"Extracted {label}: {match[:200]}",
                    severity="low",
                    category="CTF",
                    evidence=match[:200],
                    confidence=0.5,
                )
                self.add_finding(f)
                results.append(f)
        return results

    def _search_location(self, text: str) -> List[Finding]:
        results = []
        location_patterns = [
            (r"[-+]?\d{1,3}\.\d{4,},\s*[-+]?\d{1,3}\.\d{4,}", "GPS coordinates"),
            (r"(?:lat|latitude)[=: ]\s*([-+]?\d+\.\d+)", "Latitude"),
            (r"(?:lon|lng|longitude)[=: ]\s*([-+]?\d+\.\d+)", "Longitude"),
        ]
        for pattern, label in location_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches[:3]:
                val = match if isinstance(match, str) else match[0]
                f = Finding(
                    title=f"Location Data Found: {label}",
                    description=f"Extracted {label}: {val}",
                    severity="low",
                    category="CTF",
                    evidence=val,
                    confidence=0.6,
                )
                self.add_finding(f)
                results.append(f)
        return results
