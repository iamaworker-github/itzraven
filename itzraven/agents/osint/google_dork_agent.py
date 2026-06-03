"""
Google Dorking Agent — automated Google dork queries via gdork-engine Docker.

Discovers exposed data, vulnerable apps, misconfigurations, and sensitive
information indexed by Google using curated dork queries.
"""

import asyncio
import json
import shlex
from typing import List, Optional

from itzraven.agents.osint.osint_base import OSINTBaseAgent
from itzraven.agents.base_agent import AgentResult
from itzraven.core.logger import get_logger
from itzraven.core.tool_runner import ToolRunner

logger = get_logger()

DEFAULT_DORKS = [
    'site:{target} intitle:"index of"',
    'site:{target} inurl:admin',
    'site:{target} ext:sql | ext:db | ext:bak',
    'site:{target} "password" | "credentials" | "api_key"',
    'site:{target} inurl:wp-content | inurl:wp-admin',
    'site:{target} inurl:config.php | inurl:env | inurl:.env',
    'site:{target} ext:log | ext:dump',
    'site:{target} "s3.amazonaws.com" | "storage.googleapis.com"',
    'site:{target} intitle:"phpinfo" | intitle:"php information"',
    'site:{target} inurl:gitlab | inurl:jenkins | inurl:grafana',
]


class GoogleDorkingAgent(OSINTBaseAgent):
    """Automated Google dorking via gdork-engine Docker container."""

    def __init__(self, target: str, **kwargs):
        super().__init__("GoogleDorking", target, **kwargs)
        self.domain = self._extract_domain(target)
        self._runner = ToolRunner()
        self._results: List[dict] = []

    def _extract_domain(self, target: str) -> str:
        from urllib.parse import urlparse
        parsed = urlparse(target)
        return (parsed.hostname or target).lower().strip()

    async def execute(self) -> AgentResult:
        logger.info(f"GoogleDorkingAgent: Starting dorking on {self.domain}")

        for dork in DEFAULT_DORKS:
            query = dork.format(target=self.domain)
            try:
                await self._run_dork(query)
            except Exception as e:
                logger.warning(f"Dork failed: {query[:60]}... — {e}")

        if self._results:
            self.add_finding(
                title=f"Google Dorking: {len(self._results)} hits on {self.domain}",
                description=f"Found {len(self._results)} dork results for {self.domain}",
                category="osint_dorking",
                severity="medium",
                evidence=json.dumps(self._results[:20], indent=2),
            )

        return AgentResult(
            agent_name=self.name,
            status="completed",
            findings=self._findings,
            execution_time=0,
            metadata={"dork_hits": len(self._results), "domain": self.domain},
        )

    async def _run_dork(self, query: str) -> None:
        output = await self._runner.execute(
            "osint_google_dork.GDorkEngine",
            args=["--query", query],
            use_docker=True,
        )
        if output and output.stdout:
            lines = output.stdout.strip().split("\n")
            for line in lines:
                line = line.strip()
                if line and line.startswith("http"):
                    self._results.append({"url": line, "dork": query})
                    self.add_finding(
                        title=f"Dork Hit: {line[:80]}",
                        description=f"Google dork result\nQuery: {query}",
                        category="osint_dorking",
                        severity="info",
                        evidence=line,
                    )
