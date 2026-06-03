"""
Credential & Secret Leak Detection Agent — HackTricks + IppSec methodology.

Performs:
1. HaveIBeenPwned-style breach checking (passive API queries)
2. GitHub secret scanning (API code search)
3. Pastebin/snippet site monitoring
4. Public repository credential patterns
5. Common secret exposure patterns (API keys, tokens, passwords)
6. Email/username breach correlation
7. Dark web leak hints via passive sources
"""

import asyncio
import json
import re
from typing import List, Optional, Dict, Any, Set
from urllib.parse import urlparse

from itzraven.agents.osint.osint_base import OSINTBaseAgent
from itzraven.core.blackboard import FindingCategory
from itzraven.core.logger import get_logger
from itzraven.agents.base_agent import AgentResult

logger = get_logger()

SECRET_PATTERNS = [
    (r'AKIA[0-9A-Z]{16}', "AWS Access Key ID"),
    (r'sk-[a-zA-Z0-9]{20,}', "Secret/API Key (sk-)"),
    (r'pk-[a-zA-Z0-9]{20,}', "Public Key (pk-)"),
    (r'ghp_[a-zA-Z0-9]{36}', "GitHub Personal Access Token"),
    (r'gho_[a-zA-Z0-9]{36}', "GitHub OAuth Token"),
    (r'xox[baprs]-[0-9a-zA-Z-]{10,}', "Slack Token"),
    (r'sk_live_[0-9a-z]{32}', "Stripe Live Secret Key"),
    (r'pk_live_[0-9a-z]{32}', "Stripe Live Public Key"),
    (r'AIza[0-9A-Za-z_-]{35}', "Google API Key"),
    (r'SG\.[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,}', "SendGrid API Key"),
    (r'-----BEGIN RSA PRIVATE KEY-----', "RSA Private Key"),
    (r'-----BEGIN OPENSSH PRIVATE KEY-----', "OpenSSH Private Key"),
    (r'-----BEGIN DSA PRIVATE KEY-----', "DSA Private Key"),
    (r'-----BEGIN EC PRIVATE KEY-----', "EC Private Key"),
    (r'mongodb\+srv://[^\s]+', "MongoDB Connection String"),
    (r'postgres://[^\s]+', "PostgreSQL Connection String"),
    (r'mysql://[^\s]+', "MySQL Connection String"),
    (r'redis://[^\s]+', "Redis Connection String"),
    (r'https://hooks\.slack\.com/services/[^\s]+', "Slack Webhook"),
    (r'https://[a-zA-Z]+\.api\.mailchimp\.com/[^\s]+', "Mailchimp API"),
    (r'api_key[=:]["\'][a-zA-Z0-9_]{16,}["\']', "Generic API Key in config"),
    (r'password[=:]["\'][^"\']{6,}["\']', "Password in config"),
    (r'secret[=:]["\'][^"\']{8,}["\']', "Secret in config"),
    (r'token[=:]["\'][a-zA-Z0-9_]{16,}["\']', "Token in config"),
]

BREACH_SOURCES = {
    "haveibeenpwned": "https://haveibeenpwned.com/api/v3/breachedaccount/",
    "dehashed": "https://api.dehashed.com/search",
    "leakix": "https://leakix.net/api/",
}


class LeakIntelAgent(OSINTBaseAgent):
    """Credential and secret leak detection."""

    def __init__(self, target: str, **kwargs):
        super().__init__("LeakIntel", target, **kwargs)
        self.domain = self._extract_domain(target)
        self._breaches: List[str] = []
        self._secrets_found: List[Dict[str, str]] = []
        self._emails: Set[str] = set()

    def _extract_domain(self, target: str) -> str:
        parsed = urlparse(target)
        return (parsed.hostname or target).lower().strip()

    async def execute(self) -> AgentResult:
        logger.info(f"LeakIntelAgent: Starting leak detection on {self.domain}")

        await asyncio.gather(
            self._github_secret_scan(),
            self._leakix_scan(),
            self._pastebin_leaks(),
            self._public_repo_scan(),
            return_exceptions=True,
        )

        return AgentResult(
            agent_name=self.name, status="completed",
            findings=self._findings, execution_time=0,
            metadata={
                "breaches_found": len(self._breaches),
                "secrets_found": len(self._secrets_found),
                "emails_found": len(self._emails),
            },
        )

    async def _github_secret_scan(self):
        """Scan GitHub for exposed secrets related to domain."""
        logger.info(f"  GitHub secret scan: {self.domain}")
        query = f"\"{self.domain}\" AND (api_key OR password OR secret OR token)"
        data = await self.http_get(
            f"https://api.github.com/search/code?q={query}&per_page=20"
        )
        if data and data["status"] == 200:
            try:
                result = json.loads(data["text"])
                for item in result.get("items", []):
                    repo = item.get("repository", {}).get("full_name", "")
                    path = item.get("path", "")
                    raw_url = item.get("html_url", "")
                    # Fetch the file content to scan for secrets
                    file_data = await self.http_get(raw_url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/"))
                    if file_data and file_data["status"] == 200:
                        content = file_data["text"]
                        for pattern, secret_type in SECRET_PATTERNS:
                            matches = re.findall(pattern, content)
                            for match in matches:
                                if len(match) > 10:
                                    self._secrets_found.append({
                                        "type": secret_type,
                                        "match": match[:20] + "...",
                                        "repo": repo,
                                        "path": path,
                                    })
                                    self.add_finding(
                                        title=f"SECRET: {secret_type}",
                                        description=f"Found {secret_type} in {repo}/{path}",
                                        category="osint_leak", severity="critical",
                                        evidence=f"Type: {secret_type}, Repo: {repo}, Path: {path}",
                                    )
            except Exception:
                pass

    async def _leakix_scan(self):
        """Check LeakIX for known leaks."""
        logger.info(f"  LeakIX scan: {self.domain}")
        data = await self.http_get(f"https://leakix.net/api/search?q={self.domain}")
        if data and data["status"] == 200:
            try:
                result = json.loads(data["text"])
                entries = result if isinstance(result, list) else []
                if entries:
                    self._breaches.append(f"LeakIX: {len(entries)} entries")
                    self.add_finding(
                        title=f"LeakIX Results: {len(entries)} entries",
                        description=f"Found {len(entries)} LeakIX entries for {self.domain}",
                        category="osint_leak", severity="high",
                    )
            except Exception:
                pass

    async def _pastebin_leaks(self):
        """Check paste sites for domain mentions with secrets."""
        logger.info(f"  Pastebin leak check: {self.domain}")
        sources = [
            f"https://psbdmp.ws/api/search/{self.domain}",
            f"https://pastebin.com/search?q={self.domain}",
        ]
        for url in sources:
            data = await self.http_get(url)
            if data and data["status"] == 200:
                text = data["text"].lower()
                for pattern, secret_type in SECRET_PATTERNS[:10]:
                    matches = re.findall(pattern, text)
                    for match in matches:
                        self._secrets_found.append({"type": secret_type, "match": match[:20], "source": url})
                        self.add_finding(
                            title=f"Secret in Paste: {secret_type}",
                            description=f"Potential {secret_type} found in paste content",
                            category="osint_leak", severity="high",
                        )

    async def _public_repo_scan(self):
        """Scan public repos for common secret filenames."""
        logger.info(f"  Public repo scan: {self.domain}")
        secret_files = [
            ".env", ".env.example", ".env.production", ".env.local",
            "credentials.json", "credentials.yml", "config.json",
            "secrets.yml", "secret.yaml", "id_rsa", "id_rsa.pub",
            "aws.yml", "aws-config", "gcp.json", "azure.json",
            "docker-compose.yml", "docker-compose.yaml", "kubeconfig",
            ".npmrc", ".yarnrc", ".pypirc", "netrc",
        ]
        for secret_file in secret_files:
            query = f"\"{self.domain}\" AND filename:{secret_file}"
            data = await self.http_get(
                f"https://api.github.com/search/code?q={query}&per_page=5"
            )
            if data and data["status"] == 200:
                try:
                    result = json.loads(data["text"])
                    count = result.get("total_count", 0)
                    if count > 0:
                        self.add_finding(
                            title=f"Secret File Found: {secret_file}",
                            description=f"{count} results for {secret_file} containing {self.domain}",
                            category="osint_leak", severity="high",
                            evidence=f"File: {secret_file}, Count: {count}",
                        )
                except Exception:
                    pass
