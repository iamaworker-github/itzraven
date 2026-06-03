"""
DNS Deep Intelligence Agent — 0xdf + IppSec + HackTricks methodology.

Performs:
1. Full DNS record enumeration (all standard record types)
2. DNS zone transfer attempt (AXFR)
3. DNSSEC analysis
4. Reverse DNS (PTR) lookup
5. DNS wildcard detection
6. DNS cache snooping (passive hints)
7. Subdomain brute-force via common wordlist
8. TTL analysis for CDN/cloud detection
9. Domain takeover detection (dangling DNS)
"""

import asyncio
import json
import re
from typing import List, Optional, Set, Dict, Any
from urllib.parse import urlparse
from dataclasses import dataclass

from itzraven.agents.osint.osint_base import OSINTBaseAgent
from itzraven.core.blackboard import FindingCategory
from itzraven.core.logger import get_logger
from itzraven.agents.base_agent import AgentResult

logger = get_logger()

COMMON_SUBDOMAINS = [
    "www", "mail", "admin", "api", "dev", "staging", "blog", "cdn", "app",
    "portal", "vpn", "remote", "ssh", "git", "jenkins", "jira", "confluence",
    "grafana", "prometheus", "kibana", "elastic", "mqtt", "ws", "websocket",
    "auth", "login", "sso", "oauth", "identity", "accounts", "profile",
    "partner", "support", "help", "docs", "documentation", "wiki",
    "status", "health", "monitor", "metrics", "logs", "trace",
    "webmail", "owa", "exchange", "email", "smtp", "imap", "pop3",
    "calendar", "drive", "share", "files", "upload", "download",
    "beta", "alpha", "test", "qa", "uat", "demo", "sandbox",
    "corp", "internal", "hr", "payroll", "finance", "invoices",
    "compliance", "audit", "security", "incident",
    "lb-01", "lb-02", "web-01", "web-02", "app-01", "db-01",
    "ns1", "ns2", "ns3", "mx1", "mx2",
]

SUSPICIOUS_TXT_KEYWORDS = [
    "v=spf1", "v=dmarc", "v=ms", "google-site-verification",
    "ms-validation", "h1-", "bugcrowd", "intigriti",
    "atlassian-domain-verification", "stripe-verification",
    "apple-domain-verification", "facebook-domain-verification",
    "hubspot-developer-verification", "pardot",
    "globalsign-domain-verification", "docusign",
]


class DNSIntelAgent(OSINTBaseAgent):
    """Deep DNS intelligence and subdomain analysis."""

    def __init__(self, target: str, **kwargs):
        super().__init__("DNSIntel", target, **kwargs)
        self.domain = self._extract_domain(target)
        self._records: Dict[str, List[str]] = {}
        self._subdomains: Set[str] = set()
        self._takeover_candidates: List[str] = []

    def _extract_domain(self, target: str) -> str:
        parsed = urlparse(target)
        return (parsed.hostname or target).lower().strip()

    async def execute(self) -> AgentResult:
        logger.info(f"DNSIntelAgent: Starting deep DNS enumeration on {self.domain}")

        await asyncio.gather(
            self._all_dns_records(),
            self._zone_transfer_check(),
            self._dnssec_check(),
            self._wildcard_detection(),
            self._subdomain_bruteforce(),
            self._domain_takeover_check(),
            self._reverse_dns(),
            return_exceptions=True,
        )

        return AgentResult(
            agent_name=self.name, status="completed",
            findings=self._findings, execution_time=0,
            metadata={
                "domain": self.domain,
                "record_types": list(self._records.keys()),
                "subdomains": len(self._subdomains),
                "takeover_candidates": self._takeover_candidates,
            },
        )

    async def _all_dns_records(self):
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "SRV", "CAA", "PTR", "HINFO", "RP"]
        for rtype in record_types:
            try:
                records = await self.dns_lookup(self.domain, rtype)
                if records:
                    self._records[rtype] = records
                    self.add_finding(
                        title=f"DNS {rtype}: {self.domain}",
                        description=f"{rtype} records: {', '.join(records[:5])}",
                        category="osint_dns",
                        evidence=f"Type={rtype}, Count={len(records)}, Values={records[:10]}",
                        bb_category=FindingCategory.TARGET_REG,
                    )

                    # Check TXT for security/verification entries
                    if rtype == "TXT":
                        for record in records:
                            for keyword in SUSPICIOUS_TXT_KEYWORDS:
                                if keyword in record.lower():
                                    self.add_finding(
                                        title=f"TXT Verification: {keyword}",
                                        description=f"Domain verification/security record found: {record[:200]}",
                                        category="osint_dns", severity="low",
                                        evidence=f"TXT: {record[:300]}",
                                    )
                                    break
            except Exception:
                pass

    async def _zone_transfer_check(self):
        logger.info(f"  Zone transfer check: {self.domain}")
        ns_records = self._records.get("NS", [])
        for ns in ns_records[:3]:
            try:
                import dns.zone
                import dns.query
                zone = await asyncio.get_event_loop().run_in_executor(
                    None, lambda: dns.zone.from_xfr(dns.query.xfr(ns, self.domain, timeout=5))
                )
                if zone:
                    names = [str(n) for n in zone.nodes.keys()]
                    self.add_finding(
                        title=f"Zone Transfer SUCCESS: {ns}",
                        description=f"Zone transfer from {ns} returned {len(names)} records!",
                        category="osint_dns", severity="high",
                        evidence=f"NS: {ns}, Records: {names[:50]}",
                    )
                    self._subdomains.update(n.replace(self.domain, "").strip(".") for n in names)
            except Exception:
                pass

    async def _dnssec_check(self):
        logger.info(f"  DNSSEC check: {self.domain}")
        try:
            records = await self.dns_lookup(self.domain, "DNSKEY")
            if records:
                self.add_finding(
                    title=f"DNSSEC Enabled: {self.domain}",
                    description=f"DNSSEC keys found ({len(records)} records)",
                    category="osint_dns",
                    evidence=f"DNSKEY count: {len(records)}",
                )
            else:
                self.add_finding(
                    title=f"DNSSEC Not Enabled: {self.domain}",
                    description="Domain does not have DNSSEC — vulnerable to DNS spoofing/cache poisoning",
                    category="osint_dns", severity="low",
                )
        except Exception:
            self.add_finding(
                title=f"DNSSEC Unknown: {self.domain}",
                description="Could not determine DNSSEC status",
                category="osint_dns", severity="info",
            )

    async def _wildcard_detection(self):
        logger.info(f"  Wildcard detection: {self.domain}")
        random_sub = f"xzy-{hash(self.domain) % 10000}-nonexistent.{self.domain}"
        try:
            records = await self.dns_lookup(random_sub, "A")
            if records:
                self.add_finding(
                    title=f"DNS Wildcard Detected: {self.domain}",
                    description=f"Wildcard DNS enabled — random subdomain resolves to {records}",
                    category="osint_dns", severity="medium",
                    evidence=f"Test: {random_sub} → {records}",
                )
        except Exception:
            pass

    async def _subdomain_bruteforce(self):
        """Passive subdomain brute-force — checks common names via DNS."""
        logger.info(f"  Subdomain brute-force: {self.domain}")
        tasks = []
        for sub in COMMON_SUBDOMAINS:
            fqdn = f"{sub}.{self.domain}"
            tasks.append(self._check_subdomain(fqdn))

        batch_size = 10
        for i in range(0, len(tasks), batch_size):
            batch = tasks[i:i + batch_size]
            await asyncio.gather(*batch, return_exceptions=True)

        if self._subdomains:
            self.add_finding(
                title=f"DNS Subdomains: {len(self._subdomains)}",
                description=f"Discovered {len(self._subdomains)} resolvable subdomains",
                category="osint_subdomain", severity="info",
                evidence=f"Subdomains: {sorted(self._subdomains)[:30]}",
                bb_category=FindingCategory.SUBDOMAIN,
            )

    async def _check_subdomain(self, fqdn: str):
        try:
            records = await self.dns_lookup(fqdn, "A")
            if records:
                self._subdomains.add(fqdn)
                # Check for potential takeover
                cname_records = await self.dns_lookup(fqdn, "CNAME")
                if cname_records:
                    for cname in cname_records:
                        if any(service in cname.lower() for service in [
                            "awsdns", "cloudfront", "s3-website", "github.io",
                            "herokuapp", "azurewebsites", "trafficmanager",
                            "elasticbeanstalk", "firebase", "pantheon",
                        ]):
                            self._takeover_candidates.append(fqdn)
                            self.add_finding(
                                title=f"Subdomain Takeover Candidate: {fqdn}",
                                description=f"CNAME points to {cname} — may be vulnerable to takeover",
                                category="osint_takeover", severity="high",
                                evidence=f"CNAME: {cname}",
                            )
        except Exception:
            pass

    async def _domain_takeover_check(self):
        """Check for dangling DNS / domain takeover (HackTricks)."""
        logger.info(f"  Domain takeover check: {self.domain}")
        for fdqn in self._subdomains:
            try:
                resp = await self.http_get(f"https://{fdqn}")
                if resp:
                    status = resp["status"]
                    body = resp.get("text", "").lower()
                    takeover_indicators = [
                        "no such bucket", "not found", "404", "does not exist",
                        "there is no app hosted here", "repository not found",
                        "heroku no such app", "page not found",
                        "the specified bucket does not exist",
                        "this site is not configured", "domain for sale",
                        "this page is not found", "404 page not found",
                    ]
                    if status == 404 and any(ind in body for ind in takeover_indicators):
                        self._takeover_candidates.append(fdqn)
                        self.add_finding(
                            title=f"DOMAIN TAKEOVER: {fdqn}",
                            description=f"Subdomain {fdqn} returns 404 with takeover indicator — VULNERABLE",
                            category="osint_takeover", severity="critical",
                        )
            except Exception:
                pass

    async def _reverse_dns(self):
        """PTR lookup for known IPs."""
        logger.info(f"  Reverse DNS: {self.domain}")
        a_records = self._records.get("A", [])
        for ip in a_records[:5]:
            try:
                ptr = await self.dns_lookup(ip, "PTR")
                if ptr:
                    self.add_finding(
                        title=f"PTR Record: {ip}",
                        description=f"Reverse DNS: {ptr[0]}",
                        category="osint_dns",
                        evidence=f"IP: {ip} → PTR: {ptr[0]}",
                    )
            except Exception:
                pass
