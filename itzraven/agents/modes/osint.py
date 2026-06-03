"""
OSINTOrchestrator — Comprehensive passive intelligence gathering.
Integrates: GitHub OSINT, Domain/DNS, Email, Username, Social Media,
Public Records, Dark Web, Certificate Transparency, Breach Data.
All operations are PASSIVE — no active scanning.
"""
import asyncio
import json
import os
import uuid
from pathlib import Path
from typing import Optional, List, Dict, Any
from urllib.parse import urlparse

from itzraven.agents.modes.base import ModeOrchestrator
from itzraven.agents.base_agent import Finding, AgentResult, AgentStatus
from itzraven.agents.recon_agent import ReconAgent
from itzraven.agents.osint.domain_intel import DomainIntelAgent
from itzraven.agents.osint.email_intel import EmailIntelAgent
from itzraven.agents.osint.tech_intel import TechIntelAgent
from itzraven.agents.osint.visual_intel import VisualIntelAgent
from itzraven.agents.osint.google_dork_agent import GoogleDorkingAgent
from itzraven.toolkit.osint import (
    GitHubOSINT, DomainOSINT, UsernameOSINT,
    EmailOSINT, SocialMediaOSINT, PublicRecordsOSINT,
)
from itzraven.core.logger import get_logger
from itzraven.core.event_bus import EventBus
from itzraven.core import MEMORY_SYSTEM_AVAILABLE

logger = get_logger()
if MEMORY_SYSTEM_AVAILABLE:
    from itzraven.core.memory_manager import MemoryManager


class OSINTOrchestrator(ModeOrchestrator):
    mode_name = "osint"

    def __init__(
        self,
        target: str,
        event_bus: Optional[EventBus] = None,
        memory_manager: Optional['MemoryManager'] = None,
        scope: Optional[List[str]] = None,
        scan_depth: str = "deep",
    ):
        super().__init__(target, event_bus, memory_manager, scope, scan_depth=scan_depth)
        self._session_id: str = str(uuid.uuid4())[:8]
        gh_token = os.getenv("ITZRAVEN_GITHUB_TOKEN", os.getenv("GITHUB_TOKEN", ""))
        st_key = os.getenv("ITZRAVEN_SECURITYTRAILS_KEY", "")
        hibp_key = os.getenv("ITZRAVEN_HIBP_KEY", "")
        self.github = GitHubOSINT(token=gh_token)
        self.domain_osint = DomainOSINT()
        self.username_osint = UsernameOSINT()
        self.email_osint = EmailOSINT()
        self.social = SocialMediaOSINT()
        self.records = PublicRecordsOSINT()
        self._raw_target = target

    def load_agents(self) -> None:
        self.add_agent(ReconAgent(
            self.target, event_bus=self.event_bus, memory_manager=self.memory_manager, mode="osint"
        ))
        self.add_agent(DomainIntelAgent(
            self.target, event_bus=self.event_bus, memory_manager=self.memory_manager
        ))
        self.add_agent(EmailIntelAgent(
            self.target, event_bus=self.event_bus, memory_manager=self.memory_manager
        ))
        self.add_agent(TechIntelAgent(
            self.target, event_bus=self.event_bus, memory_manager=self.memory_manager
        ))
        self.add_agent(VisualIntelAgent(
            self.target, event_bus=self.event_bus, memory_manager=self.memory_manager
        ))
        self.add_agent(GoogleDorkingAgent(
            self.target, event_bus=self.event_bus, memory_manager=self.memory_manager
        ))
        logger.info(f"[OSINT] Loaded standard agents + advanced OSINT toolkit")

    def _extract_github(self) -> tuple:
        t = self._raw_target.lower().strip()
        if "github.com/" in t:
            parts = t.split("github.com/")[1].split("/")
            if len(parts) >= 2:
                return parts[0], parts[1]
            return parts[0], ""
        if t.startswith("gh:"):
            return t[3:].strip(), ""
        return "", ""

    def _extract_email(self) -> str:
        if "@" in self._raw_target and not self._raw_target.startswith(("http", "gh:", "u:")):
            return self._raw_target.strip()
        return ""

    def _extract_username(self) -> str:
        if self._raw_target.lower().startswith("u:") or self._raw_target.lower().startswith("user:"):
            return self._raw_target.split(":", 1)[1].strip()
        return ""

    def _extract_domain(self) -> str:
        if self._extract_github()[0] or self._extract_email() or self._extract_username():
            return ""
        t = self._raw_target.lower().strip()
        if "://" in t:
            t = t.split("://")[1]
        t = t.split("/")[0].split(":")[0]
        return t

    async def _run_github_osint(self, username: str, repo: str = "") -> List[Finding]:
        findings = []
        try:
            info = await self.github.user_info(username)
            if info and "login" in info:
                created = info.get("created_at", "unknown")
                company = info.get("company", "N/A")
                location = info.get("location", "N/A")
                public_repos = info.get("public_repos", 0)

                findings.append(Finding(
                    title=f"GitHub User: {username}",
                    severity="info", category="osint",
                    description=f"Created: {created}, Company: {company}, Location: {location}, Repos: {public_repos}",
                    evidence=json.dumps({k: info.get(k) for k in ("login", "name", "company", "location", "created_at", "public_repos", "followers", "following", "bio", "email", "blog", "twitter_username") if info.get(k)}, indent=2)[:500],
                    confidence=0.95,
                ))

                if repo:
                    emails = await self.github.commit_emails(username, repo)
                    if emails:
                        findings.append(Finding(
                            title=f"GitHub Emails: {len(emails)} from {username}/{repo}",
                            severity="medium" if len(emails) > 1 else "info",
                            category="osint",
                            description=f"Extracted {len(emails)} emails from commit metadata",
                            evidence="\n".join(sorted(emails)),
                            confidence=0.9,
                        ))

                if not repo:
                    repos = await self.github.user_repos(username, 2)
                    if repos:
                        lang_counts = {}
                        for r in repos:
                            lang = r.get("language", "unknown") or "unknown"
                            lang_counts[lang] = lang_counts.get(lang, 0) + 1
                        top_langs = sorted(lang_counts.items(), key=lambda x: -x[1])[:5]
                        findings.append(Finding(
                            title=f"GitHub Repos: {len(repos)} ({', '.join(f'{l}({c})' for l,c in top_langs)})",
                            severity="info", category="osint",
                            description=f"Top languages: {top_langs}",
                            evidence=json.dumps([{"name": r["name"], "lang": r.get("language", ""), "stars": r.get("stargazers_count", 0), "desc": r.get("description", "")[:100]} for r in repos[:5]], indent=2),
                            confidence=0.95,
                        ))
        except Exception as e:
            logger.debug(f"GitHub OSINT failed: {e}")
        return findings

    async def _run_domain_osint(self, domain: str) -> List[Finding]:
        findings = []
        try:
            result = await self.domain_osint.full_recon(domain)
            subs = result.get("subdomains", [])
            dns = result.get("dns", {})

            if subs:
                findings.append(Finding(
                    title=f"Subdomains: {len(subs)} discovered",
                    severity="info", category="osint",
                    description=f"Certificate Transparency + SecurityTrails",
                    evidence="\n".join(subs[:30]),
                    confidence=0.85,
                ))

            # URLScan
            urlscan = await self.domain_osint.urlscan_domain(domain)
            if urlscan and "results" in urlscan:
                findings.append(Finding(
                    title=f"URLScan: {len(urlscan['results'])} results",
                    severity="info", category="osint",
                    description=f"URLScan.io found {len(urlscan['results'])} pages",
                    evidence=json.dumps([r.get("page", {}).get("url", "") for r in urlscan["results"][:5]], indent=2),
                    confidence=0.8,
                ))

            # Wayback Machine
            wayback = await self.records.wayback_pages(domain, 20)
            if wayback:
                findings.append(Finding(
                    title=f"Wayback: {len(wayback)} historical pages",
                    severity="info", category="osint",
                    description=f"Wayback Machine has {len(wayback)} snapshots",
                    evidence="\n".join(wayback[:10]),
                    confidence=0.95,
                ))
        except Exception as e:
            logger.debug(f"Domain OSINT failed: {e}")
        return findings

    async def _run_email_osint(self, email: str) -> List[Finding]:
        findings = []
        try:
            rep = await self.email_osint.emailrep(email)
            if rep and "email" in rep:
                reputation = rep.get("reputation", "unknown")
                suspicious = rep.get("suspicious", False)
                details = rep.get("details", {})
                findings.append(Finding(
                    title=f"EmailRep: {email} (rep: {reputation})",
                    severity="medium" if suspicious else "info",
                    category="osint",
                    description=f"Suspicious: {suspicious}, Details: {json.dumps(details, default=str)[:200]}",
                    evidence=json.dumps(rep, indent=2)[:500],
                    confidence=0.85,
                ))
        except Exception as e:
            logger.debug(f"Email OSINT failed: {e}")
        return findings

    async def _run_username_osint(self, username: str) -> List[Finding]:
        findings = []
        try:
            results = await self.username_osint.check(username)
            if results:
                findings.append(Finding(
                    title=f"Username '{username}' found on {len(results)} platforms",
                    severity="info", category="osint",
                    description=f"Username exists on: {', '.join(r['site'] for r in results[:10])}",
                    evidence=json.dumps(results[:15], indent=2)[:500],
                    confidence=0.9,
                ))
        except Exception as e:
            logger.debug(f"Username OSINT failed: {e}")
        return findings

    async def run_sequential(self):
        logger.info(f"🎯 OSINT Mode — {self._raw_target}")
        logger.info(f"  Gathering passive intelligence from 15+ sources...")

        result = await super().run_sequential()

        domain = self._extract_domain()
        email = self._extract_email()
        username = self._extract_username()
        gh_user, gh_repo = self._extract_github()

        tasks = []

        if gh_user:
            tasks.append(self._run_github_osint(gh_user, gh_repo))
        elif domain and not email:
            tasks.append(self._run_github_osint(domain))

        if domain:
            tasks.append(self._run_domain_osint(domain))

        if email:
            tasks.append(self._run_email_osint(email))

        if username:
            tasks.append(self._run_username_osint(username))

        if tasks:
            all_osint = await asyncio.gather(*tasks, return_exceptions=True)
            for osint_findings in all_osint:
                if isinstance(osint_findings, list):
                    for f in osint_findings:
                        self.all_findings.append(f)

        result.metadata["osint_mode"] = True
        logger.info(f"✅ OSINT complete: {result.total_findings} total intelligence findings")
        return result

    def get_report_template(self) -> str:
        return "osint_report"

    def get_output_subdir(self) -> str:
        return "osint"
