"""
Social Media & People Intelligence Agent — HackTricks + IppSec methodology.

Performs:
1. LinkedIn company/employee enumeration
2. Twitter/X profile analysis
3. GitHub organization/repository discovery
4. Social media presence mapping
5. Job posting analysis (tech stack leakage via job descriptions)
6. News and press release monitoring
7. Organizational structure mapping
"""

import asyncio
import json
import re
from typing import List, Optional, Dict, Any

from itzraven.agents.osint.osint_base import OSINTBaseAgent
from itzraven.core.logger import get_logger
from itzraven.agents.base_agent import AgentResult

logger = get_logger()


class SocialIntelAgent(OSINTBaseAgent):
    """Gathers intelligence from social media and public profiles."""

    def __init__(self, target: str, **kwargs):
        super().__init__("SocialIntel", target, **kwargs)
        self.domain = self._extract_domain(target)
        self.org_name = self._guess_org_name()
        self._employees: set = set()
        self._social_accounts: dict = {}
        self._repos: list = []

    def _extract_domain(self, target: str) -> str:
        from urllib.parse import urlparse
        parsed = urlparse(target)
        return (parsed.hostname or target).lower().strip()

    def _guess_org_name(self) -> str:
        return self.domain.split(".")[0].capitalize()

    async def execute(self) -> AgentResult:
        logger.info(f"SocialIntelAgent: Starting social recon on {self.org_name}")

        await asyncio.gather(
            self._github_recon(),
            self._linkedin_recon(),
            self._job_posting_analysis(),
            self._news_monitoring(),
            self._pastebin_monitoring(),
            return_exceptions=True,
        )

        return AgentResult(
            agent_name=self.name,
            status="completed",
            findings=self._findings,
            execution_time=0,
            metadata={
                "org_name": self.org_name,
                "employees_found": len(self._employees),
                "repos_found": len(self._repos),
            },
        )

    async def _github_recon(self):
        logger.info(f"  GitHub recon: {self.org_name}")
        # Search GitHub for org
        data = await self.http_get(f"https://api.github.com/search/users?q={self.org_name}+type:org")
        if data and data["status"] == 200:
            try:
                result = json.loads(data["text"])
                for item in result.get("items", [])[:5]:
                    login = item.get("login", "")
                    repos_data = await self.http_get(f"https://api.github.com/orgs/{login}/repos?per_page=10")
                    if repos_data and repos_data["status"] == 200:
                        try:
                            repos = json.loads(repos_data["text"])
                            self._repos.extend(repos)
                            repo_names = [r.get("name", "") for r in repos]
                            self.add_finding(
                                title=f"GitHub Org: {login}",
                                description=f"Organization: {login}, Public repos: {len(repos)}",
                                category="osint_github",
                                evidence=f"Repos: {repo_names}",
                            )
                        except Exception:
                            pass
            except Exception:
                pass

        # Search GitHub for domain-related code leaks (passive)
        search_data = await self.http_get(f"https://api.github.com/search/code?q={self.domain}")
        if search_data and search_data["status"] == 200:
            try:
                result = json.loads(search_data["text"])
                count = result.get("total_count", 0)
                if count > 0:
                    self.add_finding(
                        title=f"GitHub Code Mentions: {count}",
                        description=f"Domain {self.domain} mentioned in {count} GitHub code results",
                        category="osint_github", severity="low",
                    )
            except Exception:
                pass

    async def _linkedin_recon(self):
        logger.info(f"  LinkedIn recon: {self.org_name}")
        data = await self.http_get(f"https://www.linkedin.com/company/{self.org_name}")
        if data and data["status"] == 200:
            text = data["text"]
            emp_match = re.search(r'(\d[\d,]*)\s*employees', text, re.IGNORECASE)
            if emp_match:
                self.add_finding(
                    title=f"LinkedIn: {self.org_name}",
                    description=f"Company found with ~{emp_match.group(1)} employees",
                    category="osint_linkedin",
                    evidence=f"Company: {self.org_name}, Size: {emp_match.group(1)}",
                )

    async def _job_posting_analysis(self):
        """Extract tech stack from job postings (HackTricks methodology)."""
        logger.info(f"  Job posting analysis: {self.org_name}")
        data = await self.http_get(
            f"https://api.careers.com/search?q={self.org_name}&fields=description"
        )
        if data and data["status"] == 200:
            text = data["text"].lower()
            tech_stack = set()
            tech_keywords = [
                "python", "java", "javascript", "golang", "rust", "c++", "c#",
                "aws", "gcp", "azure", "kubernetes", "docker", "terraform",
                "react", "angular", "vue", "node.js", "django", "flask",
                "postgresql", "mysql", "mongodb", "redis", "elasticsearch",
                "machine learning", "ai", "llm", "blockchain", "smart contract",
            ]
            for keyword in tech_keywords:
                if keyword in text:
                    tech_stack.add(keyword)
            if tech_stack:
                self.add_finding(
                    title=f"Tech Stack via Jobs: {self.org_name}",
                    description=f"Technology keywords found in job postings: {', '.join(sorted(tech_stack))}",
                    category="osint_tech_stack",
                    evidence=f"Technologies: {tech_stack}",
                )

    async def _news_monitoring(self):
        logger.info(f"  News monitoring: {self.org_name}")
        data = await self.http_get(f"https://news.google.com/rss/search?q={self.org_name}")
        if data and data["status"] == 200:
            titles = re.findall(r'<title>(.*?)</title>', data["text"])[1:6]
            if titles:
                self.add_finding(
                    title=f"Recent News: {self.org_name}",
                    description=f"Found {len(titles)} recent news articles",
                    category="osint_news",
                    evidence=f"Headlines: {titles}",
                )

    async def _pastebin_monitoring(self):
        logger.info(f"  Pastebin monitoring: {self.org_name}")
        data = await self.http_get(f"https://psbdmp.ws/api/search/{self.domain}")
        if data and data["status"] == 200:
            try:
                dumps = json.loads(data["text"])
                if isinstance(dumps, list) and dumps:
                    self.add_finding(
                        title=f"Pastebin Dumps: {len(dumps)} found",
                        description=f"Domain {self.domain} appears in {len(dumps)} paste dumps",
                        category="osint_paste", severity="medium",
                    )
            except Exception:
                pass
