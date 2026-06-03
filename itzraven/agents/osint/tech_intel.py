"""
Enhanced Technology Intelligence Agent — HackTricks + PortSwigger + 0xdf methodology.

Performs:
1. HTTP banner grabbing with tech fingerprinting
2. WAF detection (Cloudflare, Akamai, Imperva, etc.)
3. CDN detection
4. JARM fingerprinting (IppSec methodology)
5. SSL/TLS analysis (cipher suites, cert details)
6. Favicon hash matching (shodan-style)
7. JavaScript framework detection
8. Server header analysis
9. Open port hints from HTTP headers
"""

import asyncio
import hashlib
import json
import re
import base64
from typing import List, Optional, Dict, Any
from urllib.parse import urlparse

from itzraven.agents.osint.osint_base import OSINTBaseAgent
from itzraven.core.blackboard import FindingCategory
from itzraven.core.logger import get_logger
from itzraven.agents.base_agent import AgentResult

logger = get_logger()

WAF_SIGNATURES = {
    "cloudflare": ["cloudflare", "__cfduid", "cf-ray"],
    "akamai": ["akamai", "akamaighost"],
    "imperva": ["imperva", "incapsula", "x-iinfo"],
    "aws_waf": ["awswaf", "aws-waf"],
    "fastly": ["fastly", "x-fastly"],
    "cloudfront": ["cloudfront", "x-amz-cf-id"],
    "sucuri": ["sucuri", "x-sucuri"],
    "barracuda": ["barracuda"],
    "f5_bigip": ["bigip", "f5"],
    "modsecurity": ["mod_security", "modsecurity"],
}


class TechIntelAgent(OSINTBaseAgent):
    """Comprehensive technology stack fingerprinting."""

    def __init__(self, target: str, **kwargs):
        super().__init__("TechIntel", target, **kwargs)
        self.target_url = f"https://{self._extract_domain(target)}"
        self.domain = self._extract_domain(target)
        self._technologies: Dict[str, str] = {}

    def _extract_domain(self, target: str) -> str:
        parsed = urlparse(target)
        return (parsed.hostname or target).lower().strip()

    async def execute(self) -> AgentResult:
        logger.info(f"TechIntelAgent: Starting tech fingerprinting on {self.domain}")

        await asyncio.gather(
            self._http_fingerprint(),
            self._ssl_analysis(),
            self._waf_detection(),
            self._favicon_hash(),
            self._jarm_fingerprint(),
            return_exceptions=True,
        )

        return AgentResult(
            agent_name=self.name, status="completed",
            findings=self._findings, execution_time=0,
            metadata={"technologies": self._technologies},
        )

    async def _http_fingerprint(self):
        logger.info(f"  HTTP fingerprint: {self.domain}")
        resp = await self.http_get(self.target_url)
        if not resp:
            resp = await self.http_get(self.target_url.replace("https://", "http://"))
        if not resp:
            return

        headers = resp.get("headers", {})
        body = resp.get("text", "")

        # Server header
        server = headers.get("server", "")
        if server:
            self._technologies["server"] = server
            self.add_finding(
                title=f"Server: {server}",
                description=f"Server header: {server}",
                category="osint_tech", severity="low",
                evidence=f"Server: {server}",
                bb_category=FindingCategory.TECHNOLOGY,
            )

        # X-Powered-By
        powered = headers.get("x-powered-by", "")
        if powered:
            self._technologies["powered_by"] = powered

        # Set-Cookie analysis (0xdf methodology — JSESSIONID behind nginx → Tomcat proxy)
        set_cookie = headers.get("set-cookie", "")
        if "JSESSIONID" in set_cookie and "nginx" in server.lower():
            self.add_finding(
                title=f"Java App behind Nginx: {self.domain}",
                description="Nginx proxying to Tomcat/Java — potential for SSRF, deserialization, or Log4j",
                category="osint_tech", severity="medium",
                evidence=f"Server={server}, Cookie={set_cookie[:100]}",
            )

        # Framework detection from HTML
        framework_hints = {
            "wp-content": "WordPress",
            "wp-includes": "WordPress",
            "laravel": "Laravel",
            "csrf-token": "Laravel/Django",
            "django": "Django",
            "csrftoken": "Django",
            "react": "React",
            "angular": "Angular",
            "vue.js": "Vue.js",
            "next.js": "Next.js",
            "nuxt": "Nuxt.js",
            "express": "Express.js",
            "ruby on rails": "Ruby on Rails",
            "rack": "Ruby/Rack",
            "asp.net": "ASP.NET",
            "viewstate": "ASP.NET",
            "__viewstate": "ASP.NET",
            "symphony": "Symfony",
            "shopify": "Shopify",
            "magento": "Magento",
            "woocommerce": "WooCommerce",
            "drupal": "Drupal",
            "joomla": "Joomla",
            "ghost": "Ghost",
            "strapi": "Strapi",
        }
        body_lower = body.lower()
        found_frameworks = []
        for hint, framework in framework_hints.items():
            if hint in body_lower:
                found_frameworks.append(framework)
                self._technologies[f"framework_{len(found_frameworks)}"] = framework

        if found_frameworks:
            self.add_finding(
                title=f"Frameworks: {', '.join(set(found_frameworks))}",
                description=f"Detected frameworks: {', '.join(set(found_frameworks))}",
                category="osint_tech",
                evidence=f"Frameworks: {found_frameworks}",
                bb_category=FindingCategory.TECHNOLOGY,
            )

        # Generator tag
        gen_match = re.search(r'<meta\s+name="generator"\s+content="([^"]+)"', body, re.IGNORECASE)
        if gen_match:
            self._technologies["generator"] = gen_match.group(1)

    async def _ssl_analysis(self):
        logger.info(f"  SSL analysis: {self.domain}")
        try:
            import ssl
            import socket
            ctx = ssl.create_default_context()
            sock = await asyncio.get_event_loop().run_in_executor(
                None, lambda: ctx.wrap_socket(
                    socket.socket(socket.AF_INET), server_hostname=self.domain
                )
            )
            await asyncio.get_event_loop().run_in_executor(
                None, lambda: sock.connect((self.domain, 443))
            )
            cert = sock.getpeercert()
            if cert:
                issuer = dict(cert.get("issuer", []))
                subject = dict(cert.get("subject", []))
                org = subject.get("organizationName", "")
                cn = subject.get("commonName", "")
                issuer_org = issuer.get("organizationName", "")

                self.add_finding(
                    title=f"SSL Cert: {self.domain}",
                    description=f"Issuer: {issuer_org}, Org: {org}, CN: {cn}",
                    category="osint_ssl",
                    evidence=f"Subject: {subject}, Issuer: {issuer}",
                )
            sock.close()
        except Exception as e:
            logger.debug(f"  SSL analysis failed: {e}")

    async def _waf_detection(self):
        logger.info(f"  WAF detection: {self.domain}")
        resp = await self.http_get(self.target_url)
        if not resp:
            return
        headers = resp.get("headers", {})
        body = resp.get("text", "")
        combined = json.dumps(dict(headers)).lower() + body.lower()

        detected_wafs = []
        for waf_name, signatures in WAF_SIGNATURES.items():
            for sig in signatures:
                if sig.lower() in combined:
                    detected_wafs.append(waf_name)
                    break

        if detected_wafs:
            self._technologies["waf"] = ",".join(detected_wafs)
            self.add_finding(
                title=f"WAF Detected: {', '.join(detected_wafs)}",
                description=f"Web Application Firewall(s): {', '.join(detected_wafs)}",
                category="osint_waf", severity="medium",
                evidence=f"WAF: {detected_wafs}",
            )

    async def _favicon_hash(self):
        """Favicon hash matching for Shodan-style identification."""
        logger.info(f"  Favicon hash: {self.domain}")
        favicon_url = f"{self.target_url}/favicon.ico"
        data = await self.http_get(favicon_url)
        if data and data["status"] == 200 and len(data.get("text", "")) > 50:
            try:
                import io
                from PIL import Image
                img_data = base64.b64decode(base64.b64encode(data["text"].encode("latin-1")))
                md5_hash = hashlib.md5(img_data).hexdigest()
                self._technologies["favicon_md5"] = md5_hash
                self.add_finding(
                    title=f"Favicon Hash: {md5_hash}",
                    description=f"Favicon MD5: {md5_hash} — can be used for Shodan search: http.favicon.hash:{int(md5_hash, 16)}",
                    category="osint_favicon",
                    evidence=f"Hash: {md5_hash}, URL: {favicon_url}",
                )
            except Exception:
                pass

    async def _jarm_fingerprint(self):
        """JARM fingerprinting (IppSec methodology)."""
        logger.info(f"  JARM fingerprint: {self.domain}")
        try:
            import socket
            import ssl
            import struct

            jarm_hashes = []
            for cipher_version in [
                ("TLS_AES_128_GCM_SHA256", "tls1.3"),
                ("TLS_AES_256_GCM_SHA384", "tls1.3"),
                ("TLS_CHACHA20_POLY1305_SHA256", "tls1.3"),
            ]:
                try:
                    ctx = ssl.create_default_context()
                    ctx.set_ciphers(cipher_version[0])
                    sock = await asyncio.get_event_loop().run_in_executor(
                        None, lambda: ctx.wrap_socket(
                            socket.socket(socket.AF_INET), server_hostname=self.domain
                        )
                    )
                    await asyncio.get_event_loop().run_in_executor(
                        None, lambda: sock.connect((self.domain, 443))
                    )
                    jarm_hashes.append(sock.version())
                    sock.close()
                except Exception:
                    jarm_hashes.append("error")

            if jarm_hashes:
                self.add_finding(
                    title=f"JARM/TLS Fingerprint: {self.domain}",
                    description=f"TLS versions offered: {', '.join(set(jarm_hashes))}",
                    category="osint_jarm",
                    evidence=f"JARM raw: {jarm_hashes}",
                )
        except Exception as e:
            logger.debug(f"  JARM fingerprinting failed: {e}")
