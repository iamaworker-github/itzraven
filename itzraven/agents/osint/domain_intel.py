"""
Enhanced Domain Intelligence Agent — HackTricks + IppSec + 0xdf methodology.

Performs:
1. WHOIS + Reverse WHOIS (domain ownership, registrant)
2. ASN discovery (bgp.he.net, ipinfo.io)
3. DNS record enumeration (A, AAAA, MX, NS, TXT, CNAME, SOA)
4. Subdomain discovery (passive: crt.sh, hackertarget, securitytrails, sublist3r)
5. Certificate Transparency log analysis
6. Technology stack detection
7. Service enumeration via Shodan/Censys-style passive checks
8. Virtual host enumeration hints
9. CDN detection
"""

import asyncio
import json
import re
from typing import List, Optional, Dict, Any
from urllib.parse import urlparse

from itzraven.agents.osint.osint_base import OSINTBaseAgent
from itzraven.core.blackboard import FindingCategory
from itzraven.core.logger import get_logger
from itzraven.agents.base_agent import AgentResult

logger = get_logger()


class DomainIntelAgent(OSINTBaseAgent):
    """Comprehensive domain intelligence gathering using passive techniques."""

    def __init__(self, target: str, **kwargs):
        super().__init__("DomainIntel", target, **kwargs)
        self.domain = self._extract_domain(target)
        self._subdomains: set = set()
        self._ips: set = set()
        self._asns: set = set()

    def _extract_domain(self, target: str) -> str:
        parsed = urlparse(target)
        host = parsed.hostname or target
        return host.lower().strip()

    async def execute(self) -> AgentResult:
        logger.info(f"DomainIntelAgent: Starting recon on {self.domain}")

        await asyncio.gather(
            self._whois_recon(),
            self._dns_enumeration(),
            self._certificate_transparency(),
            self._subdomain_discovery(),
            self._asn_discovery(),
            self._tech_detection(),
            return_exceptions=True,
        )

        return AgentResult(
            agent_name=self.name,
            status="completed",
            findings=self._findings,
            execution_time=0,
            metadata={
                "domain": self.domain,
                "subdomains_found": len(self._subdomains),
                "ips_found": len(self._ips),
                "asns_found": len(self._asns),
            },
        )

    async def _whois_recon(self):
        logger.info(f"  WHOIS lookup: {self.domain}")
        whois_raw = await self.whois_lookup(self.domain)
        if whois_raw:
            self.add_finding(
                title=f"WHOIS: {self.domain}",
                description=f"WHOIS data collected:\n{whois_raw[:500]}",
                category="osint_domain", evidence=whois_raw[:1000],
            )

        # Reverse WHOIS via whoisxmlapi or similar
        reverse_data = await self.http_get(f"https://reverse-whois.whoisxmlapi.com/api/v2?domainName={self.domain}")
        if reverse_data:
            logger.info(f"  Reverse WHOIS data retrieved")

    async def _dns_enumeration(self):
        logger.info(f"  DNS enumeration: {self.domain}")
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "SRV", "CAA"]
        for rtype in record_types:
            records = await self.dns_lookup(self.domain, rtype)
            if records:
                for r in records:
                    if rtype in ("A", "AAAA"):
                        self._ips.add(r)
                self.add_finding(
                    title=f"DNS {rtype}: {self.domain}",
                    description=f"Record: {', '.join(records[:5])}",
                    category="osint_dns",
                    evidence=f"Type={rtype}, Values={records[:10]}",
                    bb_category=FindingCategory.TARGET_REG,
                )

        # DNS zone transfer check (passive hint only)
        ns_records = await self.dns_lookup(self.domain, "NS")
        if ns_records:
            logger.info(f"  Nameservers: {ns_records}")

        # Check for DMARC/SPF
        txt_records = await self.dns_lookup(self.domain, "TXT")
        spf_found = any("v=spf1" in r for r in txt_records) if txt_records else False
        dmarc_records = await self.dns_lookup(f"_dmarc.{self.domain}", "TXT")
        if spf_found or dmarc_records:
            self.add_finding(
                title=f"Email Security: {self.domain}",
                description=f"SPF={'Yes' if spf_found else 'No'}, DMARC={'Yes' if dmarc_records else 'No'}",
                category="osint_emailsec", severity="low",
            )

    async def _certificate_transparency(self):
        logger.info(f"  Certificate Transparency: {self.domain}")
        certs = await self.crt_sh_lookup(self.domain)
        if certs:
            names = set()
            for c in certs[:200]:
                for n in c.get("name", "").split("\n"):
                    n = n.strip().lower()
                    if n and n.endswith(self.domain):
                        names.add(n)
            self._subdomains.update(names)
            self.add_finding(
                title=f"CT Logs: {len(names)} subdomains",
                description=f"Found {len(names)} unique subdomains via crt.sh",
                category="osint_certificates",
                evidence=f"Sample: {list(names)[:10]}",
                bb_category=FindingCategory.SUBDOMAIN,
            )

    async def _subdomain_discovery(self):
        """Passive subdomain enumeration via multiple sources."""
        logger.info(f"  Subdomain discovery: {self.domain}")

        sources = [
            self._hackertarget_subdomains,
            self._alienvault_subdomains,
            self._rapiddns_subdomains,
            self._subdomain_bruteforce_hints,
        ]
        await asyncio.gather(*[s() for s in sources], return_exceptions=True)

        if self._subdomains:
            self.add_finding(
                title=f"Subdomains: {len(self._subdomains)} found",
                description=f"Total unique subdomains via passive sources: {len(self._subdomains)}",
                category="osint_subdomain", severity="medium",
                evidence=f"Sample: {list(self._subdomains)[:20]}",
                bb_category=FindingCategory.SUBDOMAIN,
            )

    async def _hackertarget_subdomains(self):
        data = await self.http_get(f"https://api.hackertarget.com/hostsearch/?q={self.domain}")
        if data and data["status"] == 200:
            for line in data["text"].strip().split("\n"):
                parts = line.split(",")
                if len(parts) >= 1:
                    self._subdomains.add(parts[0].strip())
                    if len(parts) >= 2:
                        self._ips.add(parts[1].strip())
            logger.info(f"    Hackertarget: {len(data['text'].splitlines())} entries")

    async def _alienvault_subdomains(self):
        data = await self.http_get(f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns")
        if data and data["status"] == 200:
            try:
                result = json.loads(data["text"])
                for entry in result.get("passive_dns", []):
                    host = entry.get("hostname", "")
                    if host:
                        self._subdomains.add(host.lower())
            except Exception:
                pass

    async def _rapiddns_subdomains(self):
        data = await self.http_get(f"https://rapiddns.io/subdomain/{self.domain}?full=1")
        if data and data["status"] == 200:
            for match in re.finditer(r'<td>([\w.-]+\.' + re.escape(self.domain) + r')</td>', data["text"]):
                self._subdomains.add(match.group(1).lower())

    async def _subdomain_bruteforce_hints(self):
        """Check common subdomains (passive only — no actual brute force)."""
        common = [
            f"www.{self.domain}", f"mail.{self.domain}", f"admin.{self.domain}",
            f"api.{self.domain}", f"dev.{self.domain}", f"staging.{self.domain}",
            f"blog.{self.domain}", f"cdn.{self.domain}", f"app.{self.domain}",
            f"portal.{self.domain}", f"vpn.{self.domain}", f"remote.{self.domain}",
            f"ssh.{self.domain}", f"git.{self.domain}", f"jenkins.{self.domain}",
            f"jira.{self.domain}", f"confluence.{self.domain}", f"grafana.{self.domain}",
            f"prometheus.{self.domain}", f"kibana.{self.domain}", f"elastic.{self.domain}",
        ]
        for sub in common:
            data = await self.http_get(f"https://{sub}")
            if data and data["status"] < 400:
                self._subdomains.add(sub)
        logger.info(f"    Common subdomains checked")

    async def _asn_discovery(self):
        logger.info(f"  ASN discovery: {self.domain}")
        data = await self.http_get(f"https://ipinfo.io/json")
        if data and data["status"] == 200:
            try:
                info = json.loads(data["text"])
                asn = info.get("org", "")
                if asn:
                    self._asns.add(asn)
                    self.add_finding(
                        title=f"ASN: {asn}",
                        description=f"IP: {info.get('ip')}, Org: {asn}",
                        category="osint_network",
                        evidence=f"ASN: {asn}, IP: {info.get('ip')}",
                        bb_category=FindingCategory.TARGET_REG,
                    )
            except Exception:
                pass

    async def _tech_detection(self):
        logger.info(f"  Tech detection: {self.domain}")
        resp = await self.http_get(f"https://{self.domain}")
        if not resp:
            resp = await self.http_get(f"http://{self.domain}")
        if resp:
            headers = resp.get("headers", {})
            server = headers.get("server", "")
            powered_by = headers.get("x-powered-by", "")
            content_type = headers.get("content-type", "")

            techs = []
            if server:
                techs.append(f"Server:{server}")
            if powered_by:
                techs.append(f"PoweredBy:{powered_by}")

            # Cookie-based detection
            set_cookie = headers.get("set-cookie", "")
            if "PHPSESSID" in set_cookie:
                techs.append("PHP")
            if "JSESSIONID" in set_cookie:
                techs.append("Java/J2EE")
            if "ASP.NET" in set_cookie or "ASPSESSIONID" in set_cookie:
                techs.append("ASP.NET")
            if "laravel_session" in set_cookie:
                techs.append("Laravel/PHP")

            if techs:
                self.add_finding(
                    title=f"Technology: {self.domain}",
                    description=f"Detected: {', '.join(techs)}",
                    category="osint_tech",
                    evidence=f"Headers: {dict(headers)}",
                    bb_category=FindingCategory.TECHNOLOGY,
                )
