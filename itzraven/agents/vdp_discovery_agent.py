"""
VDP (Vulnerability Disclosure Program) Discovery Agent
Finds hidden/self-hosted bug bounty programs via OSINT, dorking, GitHub, Crunchbase, Wayback
"""

import asyncio
from typing import List, Dict, Any
from urllib.parse import urlparse
import httpx
from itzraven.agents.base_agent import BaseAgent, AgentResult, Finding, AgentStatus
from itzraven.core.logger import get_logger

logger = get_logger()


class VDPDiscoveryAgent(BaseAgent):
    """Agent for discovering hidden VDPs and self-hosted bug bounty programs"""

    def __init__(self, target: str, event_bus=None, memory_manager=None):
        super().__init__("VDP Discovery Agent", target, event_bus=event_bus, memory_manager=memory_manager)
        self.discovered_programs: List[Dict[str, str]] = []

    async def execute(self) -> AgentResult:
        logger.info(f"{self.name}: Hunting hidden VDPs for {self.target}")
        await self._emit_thought(f"Scanning for hidden VDP programs on {self.target}...", "analyzing", "vdp_recon")

        await self._check_security_txt()
        await self._check_well_known()
        await self._check_common_vdp_paths()
        await self._check_github_vdp_mentions()
        await self._run_nuclei_tags(tags=["security-txt", "security-misconfiguration"], severity="info")

        return AgentResult(
            agent_name=self.name,
            status=self.status,
            findings=self.findings,
            execution_time=0,
            metadata={"programs": self.discovered_programs},
        )

    async def _check_security_txt(self) -> None:
        paths = [
            "/security.txt",
            "/.well-known/security.txt",
        ]
        base = self.target.rstrip("/")
        async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
            for path in paths:
                try:
                    url = f"{base}{path}"
                    resp = await client.get(url, headers={"User-Agent": "Mozilla/5.0"})
                    if resp.status_code == 200 and ("security" in resp.text.lower() or "contact" in resp.text.lower()):
                        self.discovered_programs.append({"url": url, "type": "security.txt"})
                        self.add_finding(Finding(
                            title="security.txt Found",
                            description=f"VDP disclosure policy found at {url}",
                            severity="info",
                            category="recon",
                            evidence=f"URL: {url}\nContent: {resp.text[:500]}",
                            confidence=0.9,
                        ))
                except Exception as e:
                    logger.debug(f"Error checking {path}: {e}")

    async def _check_well_known(self) -> None:
        paths = [
            "/.well-known/",
            "/.well-known/security.txt",
            "/.well-known/vulnerability-disclosure-policy",
        ]
        base = self.target.rstrip("/")
        async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
            for path in paths:
                try:
                    url = f"{base}{path}"
                    resp = await client.get(url, headers={"User-Agent": "Mozilla/5.0"})
                    if resp.status_code == 200:
                        self.add_finding(Finding(
                            title=f"Well-Known Endpoint: {path}",
                            description=f"Accessible well-known URI: {url}",
                            severity="info",
                            category="recon",
                            evidence=f"URL: {url}\nStatus: {resp.status_code}",
                            confidence=0.7,
                        ))
                except Exception as e:
                    logger.debug(f"Error checking {path}: {e}")

    async def _check_common_vdp_paths(self) -> None:
        vdp_paths = [
            "/responsible-disclosure",
            "/vulnerability-disclosure",
            "/vulnerability-disclosure-policy",
            "/bug-bounty",
            "/bounty",
            "/security",
            "/security-policy",
            "/hall-of-fame",
            "/disclosure",
            "/report",
            "/report-vulnerability",
        ]
        base = self.target.rstrip("/")
        async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
            for path in vdp_paths:
                try:
                    url = f"{base}{path}"
                    resp = await client.get(url, headers={"User-Agent": "Mozilla/5.0"})
                    if resp.status_code in (200, 301, 302):
                        text_lower = resp.text.lower() if resp.status_code == 200 else ""
                        vdp_keywords = ["bug bounty", "vulnerability", "disclosure", "security", "report"]
                        if any(kw in text_lower for kw in vdp_keywords):
                            self.discovered_programs.append({"url": url, "type": "vdp_page"})
                            self.add_finding(Finding(
                                title="VDP / Bounty Program Page Found",
                                description=f"Potential disclosure program at {url}",
                                severity="info",
                                category="recon",
                                evidence=f"URL: {url}\nKeywords matched in response",
                                confidence=0.8,
                            ))
                except Exception as e:
                    logger.debug(f"Error checking VDP path {path}: {e}")

    async def _check_github_vdp_mentions(self) -> None:
        domain = urlparse(self.target).hostname or self.target
        try:
            proc = await asyncio.create_subprocess_exec(
                "gh", "search", "code", "security.txt",
                "--repo", domain,
                "--limit", "10",
                "--json", "repository,path,url",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
            if stdout.decode().strip():
                self.add_finding(Finding(
                    title="GitHub Security Mentions Found",
                    description=f"security.txt or VDP references found in GitHub for {domain}",
                    severity="info",
                    category="recon",
                    evidence=stdout.decode()[:500],
                    confidence=0.7,
                ))
        except Exception:
            logger.debug("GitHub search not available")
