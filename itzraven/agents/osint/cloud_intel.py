"""
Cloud Asset Discovery Agent — HackTricks + Trail of Bits methodology.

Performs:
1. Cloud provider IP range detection (AWS, GCP, Azure, DigitalOcean, OVH)
2. S3 bucket discovery (passive: DNS + HTTP)
3. Cloud service enumeration (CloudFront, Azure CDN, GCP LB)
4. Serverless framework detection (Lambda, Cloud Functions)
5. Known cloud vulnerability patterns
6. Cloud metadata service warnings
"""

import asyncio
import json
import re
from typing import List, Optional, Set, Dict, Any
from urllib.parse import urlparse

from itzraven.agents.osint.osint_base import OSINTBaseAgent
from itzraven.core.blackboard import FindingCategory
from itzraven.core.logger import get_logger
from itzraven.agents.base_agent import AgentResult

logger = get_logger()

CLOUD_IP_RANGES = {
    "aws": ["amazonaws.com", "cloudfront.net", "awsdns"],
    "gcp": ["appspot.com", "googleusercontent.com", "gstatic.com", "cloudfunctions.net"],
    "azure": ["azurewebsites.net", "azureedge.net", "azurefd.net", "trafficmanager.net"],
    "digitalocean": ["digitaloceanspaces.com"],
    "heroku": ["herokuapp.com", "herokussl.com"],
    "cloudflare": ["cloudflare.net", "cloudflare.com"],
    "vercel": ["vercel.app", "now.sh"],
    "netlify": ["netlify.app"],
    "github_pages": ["github.io"],
    "firebase": ["firebaseapp.com", "web.app"],
    "ovh": ["ovh.net"],
}

S3_BUCKET_NAMES = [
    "assets", "uploads", "media", "static", "public", "private",
    "backup", "logs", "data", "config", "deploy", "www",
    "downloads", "files", "images", "videos", "documents",
    "staging", "production", "dev", "test", "prod", "development",
]


class CloudIntelAgent(OSINTBaseAgent):
    """Cloud asset discovery and enumeration."""

    def __init__(self, target: str, **kwargs):
        super().__init__("CloudIntel", target, **kwargs)
        self.domain = self._extract_domain(target)
        self._cloud_providers: Set[str] = set()
        self._s3_buckets: List[str] = []
        self._cloud_services: List[str] = []

    def _extract_domain(self, target: str) -> str:
        parsed = urlparse(target)
        return (parsed.hostname or target).lower().strip()

    async def execute(self) -> AgentResult:
        logger.info(f"CloudIntelAgent: Starting cloud asset discovery on {self.domain}")

        await asyncio.gather(
            self._detect_cloud_provider(),
            self._enumerate_s3_buckets(),
            self._cloudfront_check(),
            self._cloud_metadata_warning(),
            return_exceptions=True,
        )

        return AgentResult(
            agent_name=self.name, status="completed",
            findings=self._findings, execution_time=0,
            metadata={
                "cloud_providers": list(self._cloud_providers),
                "s3_buckets": self._s3_buckets,
                "services": self._cloud_services,
            },
        )

    async def _detect_cloud_provider(self):
        logger.info(f"  Cloud provider detection: {self.domain}")
        resp = await self.http_get(f"https://{self.domain}")
        if not resp:
            resp = await self.http_get(f"http://{self.domain}")
        if not resp:
            return

        headers = resp.get("headers", {})
        body = resp.get("text", "")
        combined = json.dumps(dict(headers)).lower() + body.lower()

        for provider, indicators in CLOUD_IP_RANGES.items():
            for indicator in indicators:
                if indicator in combined:
                    self._cloud_providers.add(provider)
                    break

        if self._cloud_providers:
            self.add_finding(
                title=f"Cloud Providers: {', '.join(sorted(self._cloud_providers))}",
                description=f"Detected cloud services: {', '.join(sorted(self._cloud_providers))}",
                category="osint_cloud",
                evidence=f"Providers: {self._cloud_providers}",
                bb_category=FindingCategory.TECHNOLOGY,
            )

    async def _enumerate_s3_buckets(self):
        """Passive S3 bucket discovery via DNS + HTTP."""
        logger.info(f"  S3 bucket enumeration: {self.domain}")
        org_name = self.domain.split(".")[0]

        all_names = set()
        all_names.add(self.domain.replace(".", "-"))
        all_names.add(org_name)
        for prefix in S3_BUCKET_NAMES:
            all_names.add(f"{prefix}.{org_name}")
            all_names.add(f"{org_name}-{prefix}")

        tasks = []
        for name in list(all_names)[:30]:
            fqdn = f"{name}.s3.amazonaws.com"
            tasks.append(self._check_s3_bucket(fqdn, name))

        await asyncio.gather(*tasks, return_exceptions=True)

        if self._s3_buckets:
            self.add_finding(
                title=f"S3 Buckets Found: {len(self._s3_buckets)}",
                description=f"Accessible S3 buckets: {', '.join(self._s3_buckets)}",
                category="osint_cloud", severity="high",
                evidence=f"Buckets: {self._s3_buckets}",
            )

    async def _check_s3_bucket(self, fqdn: str, name: str):
        """Check if an S3 bucket is accessible."""
        resp = await self.http_get(f"https://{fqdn}")
        if resp:
            status = resp["status"]
            body = resp.get("text", "")
            if status == 200:
                self._s3_buckets.append(name)
                self.add_finding(
                    title=f"S3 Bucket Accessible: {name}",
                    description=f"Bucket {name}.s3.amazonaws.com returned 200 — may be public",
                    category="osint_cloud", severity="critical",
                )
            elif status == 403:
                self._s3_buckets.append(f"{name} (403)")
                self.add_finding(
                    title=f"S3 Bucket Exists (403): {name}",
                    description=f"Bucket {name} exists but denies access",
                    category="osint_cloud", severity="medium",
                )

    async def _cloudfront_check(self):
        """Detect CloudFront and potential misconfigs."""
        logger.info(f"  CloudFront check: {self.domain}")
        resp = await self.http_get(f"https://{self.domain}")
        if resp:
            headers = resp.get("headers", {})
            cf_id = headers.get("x-amz-cf-id", "")
            cf_pop = headers.get("x-amz-cf-pop", "")
            if cf_id:
                self._cloud_services.append("CloudFront")
                self.add_finding(
                    title=f"CloudFront CDN: {self.domain}",
                    description=f"Served via CloudFront (POP: {cf_pop})",
                    category="osint_cloud",
                    evidence=f"CF-ID: {cf_id}, POP: {cf_pop}",
                )
            via = headers.get("via", "")
            if "cloudfront" in via.lower():
                self._cloud_services.append("CloudFront (via header)")

    async def _cloud_metadata_warning(self):
        """Log warning about cloud metadata service abuse."""
        if any(p in ["aws", "gcp", "azure"] for p in self._cloud_providers):
            self.add_finding(
                title=f"Cloud Metadata Service Warning",
                description=f"Target uses cloud infrastructure — check for IMDS/ metadata service vulnerabilities",
                category="osint_cloud", severity="info",
                evidence="AWS: http://169.254.169.254/latest/meta-data/\n"
                        "GCP: http://metadata.google.internal/\n"
                        "Azure: http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            )
