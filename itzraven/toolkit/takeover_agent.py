"""
SubdomainTakeoverAgent — Checks discovered subdomains for potential takeover.
Detects dangling CNAME records pointing to unclaimed services.
"""
import asyncio
import json
import socket
from pathlib import Path
from typing import Dict, List, Optional, Any, Set, Tuple

import httpx

from itzraven.agents.base_agent import BaseAgent, AgentResult, Finding, AgentStatus
from itzraven.core.logger import get_logger

logger = get_logger()

# Known takeover signatures: service → (fingerprint, CNAME pattern)
TAKEOVER_SIGNATURES: Dict[str, List[Dict]] = {
    "aws-s3": [
        {"cname": ".s3.amazonaws.com", "fingerprint": "NoSuchBucket"},
        {"cname": ".s3-website", "fingerprint": "NoSuchBucket"},
    ],
    "github-pages": [
        {"cname": ".github.io", "fingerprint": "There isn't a GitHub Pages site here"},
    ],
    "heroku": [
        {"cname": ".herokuapp.com", "fingerprint": "No such app"},
    ],
    "cloudfront": [
        {"cname": ".cloudfront.net", "fingerprint": "ERROR: The request could not be satisfied"},
    ],
    "azure": [
        {"cname": ".azureedge.net", "fingerprint": "404 Not Found"},
        {"cname": ".azurewebsites.net", "fingerprint": "There is no site deployed"},
        {"cname": ".trafficmanager.net", "fingerprint": "404 Not Found"},
    ],
    "shopify": [
        {"cname": ".myshopify.com", "fingerprint": "Sorry, this shop is currently unavailable"},
    ],
    "squarespace": [
        {"cname": ".squarespace.com", "fingerprint": "No Such Site"},
    ],
    "tumblr": [
        {"cname": ".tumblr.com", "fingerprint": "There's nothing here"},
    ],
    "wordpress": [
        {"cname": ".wordpress.com", "fingerprint": "Do you want to register"},
    ],
    "unbounce": [
        {"cname": ".unbouncepages.com", "fingerprint": "The page you requested was not found"},
    ],
    "strikingly": [
        {"cname": ".strikingly.com", "fingerprint": "page not found"},
    ],
    "intercom": [
        {"cname": ".custom.intercom.io", "fingerprint": "This page is not available"},
    ],
    "freshdesk": [
        {"cname": ".freshdesk.com", "fingerprint": "The page you are looking for does not exist"},
    ],
    "helpscout": [
        {"cname": ".helpscoutdocs.com", "fingerprint": "Nothing found for"},
    ],
    "readme": [
        {"cname": ".readme.io", "fingerprint": "Project doesn't exist"},
    ],
    "bitbucket": [
        {"cname": ".bitbucket.io", "fingerprint": "Repository not found"},
    ],
    "surge": [
        {"cname": ".surge.sh", "fingerprint": "project not found"},
    ],
    "fly": [
        {"cname": ".fly.dev", "fingerprint": "404 Not Found"},
    ],
    "netlify": [
        {"cname": ".netlify.app", "fingerprint": "Not Found - Request ID"},
    ],
    "vercel": [
        {"cname": ".vercel.app", "fingerprint": "The deployment could not be found"},
    ],
    "pantheon": [
        {"cname": ".pantheonsite.io", "fingerprint": "The gods are angry"},
    ],
    "cargo": [
        {"cname": ".cargocollective.com", "fingerprint": "404 Not Found"},
    ],
    "statuspage": [
        {"cname": ".statuspage.io", "fingerprint": "Page not found"},
    ],
    "atlassian": [
        {"cname": ".atlassian.net", "fingerprint": "This site is not available"},
    ],
}


class SubdomainTakeoverAgent(BaseAgent):
    def __init__(self, target: str, event_bus=None, memory_manager=None, scope=None, subdomains: Optional[List[str]] = None):
        name = "Subdomain Takeover Agent"
        super().__init__(name, target, event_bus=event_bus, memory_manager=memory_manager, scope=scope)
        self._domain = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
        self._input_subdomains = subdomains or []

    async def execute(self) -> AgentResult:
        check_targets = self._input_subdomains[:50] if self._input_subdomains else [self._domain]

        logger.info(f"{self.name}: Checking {len(check_targets)} hosts for subdomain takeover...")

        for host in check_targets:
            try:
                cname = await self._resolve_cname(host)
                if not cname:
                    continue

                service = self._match_cname(cname)
                if not service:
                    continue

                fingerprint = await self._check_http_fingerprint(host, service)
                if fingerprint:
                    self.add_finding(Finding(
                        title=f"Subdomain Takeover: {host} ({service})",
                        severity="high", category="subdomain_takeover",
                        description=f"{host} has a dangling CNAME to {cname} ({service}). "
                                     f"This subdomain is vulnerable to takeover.",
                        evidence=f"CNAME: {cname}\nService: {service}\nFingerprint: {fingerprint}",
                        remediation=f"Remove the DNS CNAME record for {host} or claim the {service} resource.",
                        proof_of_concept=f"nslookup {host} → CNAME {cname} → vulnerable",
                        confidence=0.85,
                    ))
                    logger.warning(f"  ⚠ TAKEOVER: {host} → {cname} ({service})")
            except Exception as e:
                logger.debug(f"{self.name}: Error checking {host}: {e}")

        logger.info(f"{self.name}: Checked {len(check_targets)} hosts — {len(self.findings)} takeovers found")
        return AgentResult(
            agent_name=self.name,
            status=AgentStatus.COMPLETED,
            findings=self.findings,
            execution_time=0,
            metadata={"hosts_checked": len(check_targets), "takeovers_found": len(self.findings)},
        )

    async def _resolve_cname(self, host: str) -> Optional[str]:
        try:
            result = await asyncio.get_event_loop().run_in_executor(None, socket.gethostbyname_ex, host)
            # Try CNAME via socket
            return None
        except Exception:
            pass

        try:
            proc = await asyncio.create_subprocess_exec(
                "nslookup", host,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            output = stdout.decode(errors="ignore")
            for line in output.split("\n"):
                if "canonical name =" in line.lower() or "canonical name:" in line.lower():
                    cname = line.split("=")[-1].strip().rstrip(".")
                    if cname:
                        return cname.lower()
            return None
        except Exception:
            return None

    async def digest_resolve(self, host: str) -> Optional[str]:
        try:
            proc = await asyncio.create_subprocess_exec(
                "dig", "+short", "CNAME", host,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            cname = stdout.decode(errors="ignore").strip().rstrip(".")
            return cname.lower() if cname else None
        except Exception:
            return None

    def _match_cname(self, cname: str) -> Optional[str]:
        cname_lower = cname.lower()
        for service, signatures in TAKEOVER_SIGNATURES.items():
            for sig in signatures:
                if sig["cname"] in cname_lower:
                    return service
        return None

    async def _check_http_fingerprint(self, host: str, service: str) -> Optional[str]:
        signatures = TAKEOVER_SIGNATURES.get(service, [])
        if not signatures:
            return None

        for scheme in ("https", "http"):
            try:
                async with httpx.AsyncClient(timeout=8, follow_redirects=True, verify=False) as client:
                    r = await client.get(f"{scheme}://{host}/")
                    body = r.text.lower()
                    for sig in signatures:
                        if sig["fingerprint"].lower() in body:
                            return sig["fingerprint"]
            except Exception:
                continue
        return None
