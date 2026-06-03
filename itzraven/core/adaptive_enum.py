"""
Adaptive Enumeration Engine — response-driven scanning that changes recon strategy
based on target responses instead of running a static tool list.

Logic:
1. Start with lightweight probes (ports 80, 443, 22)
2. Based on responses, add more targeted scans
3. If nginx detected → add vhost fuzzing
4. If Tomcat detected → add Java-specific checks
5. If cloud IP → add metadata checks
6. If WordPress → add plugin/theme enumeration
7. If API returns JSON → add GraphQL/API fuzzing
"""

import asyncio
import json
import re
from typing import Dict, List, Optional, Set, Any, Callable
from dataclasses import dataclass, field

from itzraven.core.logger import get_logger
from itzraven.core.graph_memory import (
    GraphMemory, EntityType, RelationType, get_graph_memory,
)
from itzraven.core.rate_limiter import get_rate_limiter

logger = get_logger()

TECH_SIGNATURES = {
    "nginx": {"indicators": ["nginx", "Server: nginx"], "next_scans": ["vhost", "lfi", "path-traversal"]},
    "apache": {"indicators": ["apache", "Server: Apache"], "next_scans": ["lfi", "phpmyadmin", "cgi"]},
    "tomcat": {"indicators": ["tomcat", "apache-tomcat", "JSESSIONID"], "next_scans": ["tomcat-mgr", "java-deserial", "log4j"]},
    "iis": {"indicators": ["iis", "Microsoft-IIS", "ASP.NET"], "next_scans": ["aspx", "viewstate", "iis-shortname"]},
    "wordpress": {"indicators": ["wp-content", "wp-includes", "wp-json", "WordPress"], "next_scans": ["wp-plugins", "wp-themes", "wp-users"]},
    "drupal": {"indicators": ["drupal", "sites/default", "Drupal.settings"], "next_scans": ["drupal-modules"]},
    "joomla": {"indicators": ["joomla", "com_content", "option=com_"], "next_scans": ["joomla-components"]},
    "laravel": {"indicators": ["laravel", "Laravel", "_token"], "next_scans": ["env-file", "debug-mode"]},
    "django": {"indicators": ["django", "csrftoken", "Django"], "next_scans": ["admin-panel", "debug-page"]},
    "rails": {"indicators": ["rails", "ruby on rails", "Rack"], "next_scans": ["ssti", "secret-key-base"]},
    "express": {"indicators": ["express", "X-Powered-By: Express"], "next_scans": ["graphql", "body-parser"]},
    "graphql": {"indicators": ["graphql", "/graphql", "query {", "__schema"], "next_scans": ["graphql-introspection", "graphql-batch"]},
    "swagger": {"indicators": ["swagger", "openapi", "api-docs", "/swagger.json"], "next_scans": ["api-fuzz", "parameter-pollution"]},
    "cloudflare": {"indicators": ["cloudflare", "__cfduid", "cf-ray"], "next_scans": ["origin-ip", "cloudflare-bypass"]},
    "amazon": {"indicators": ["amazonaws", "s3.amazonaws", "cloudfront"], "next_scans": ["s3-buckets", "cloudfront-bypass"]},
    "azure": {"indicators": ["azurewebsites", "azureedge", "trafficmanager"], "next_scans": ["azure-storage", "azure-functions"]},
    "google": {"indicators": ["appspot", "googleusercontent", "gstatic"], "next_scans": ["gcp-metadata", "gcp-storage"]},
}

SCAN_TEMPLATES = {
    "vhost": {"tool": "ffuf", "args": "-w /usr/share/wordlists/vhosts.txt -H 'Host: FUZZ.{domain}' -fc 200"},
    "lfi": {"tool": "nuclei", "args": "-t ~/nuclei-templates/vulnerabilities/other/lfi/"},
    "ssti": {"tool": "nuclei", "args": "-t ~/nuclei-templates/vulnerabilities/ssti/"},
    "graphql-introspection": {"tool": "nuclei", "args": "-t ~/nuclei-templates/vulnerabilities/graphql/"},
    "wp-plugins": {"tool": "nuclei", "args": "-t ~/nuclei-templates/technologies/wordpress/"},
    "s3-buckets": {"tool": "nuclei", "args": "-t ~/nuclei-templates/misconfiguration/aws/"},
    "tomcat-mgr": {"tool": "nuclei", "args": "-t ~/nuclei-templates/vulnerabilities/tomcat/"},
    "log4j": {"tool": "nuclei", "args": "-t ~/nuclei-templates/vulnerabilities/log4j/"},
    "java-deserial": {"tool": "nuclei", "args": "-t ~/nuclei-templates/vulnerabilities/java-deserialization/"},
    "env-file": {"tool": "nuclei", "args": "-t ~/nuclei-templates/exposed-configurations/"},
    "debug-mode": {"tool": "nuclei", "args": "-t ~/nuclei-templates/misconfiguration/debug/"},
    "origin-ip": {"tool": "nuclei", "args": "-t ~/nuclei-templates/misconfiguration/cloudflare-origin-ip/"},
    "api-fuzz": {"tool": "ffuf", "args": "-w /usr/share/wordlists/api.txt"},
}


@dataclass
class ScanDecision:
    scan_type: str
    target: str
    priority: int  # 1-10, higher = more urgent
    reason: str
    template: Optional[dict] = None
    confidence: float = 0.5

    def to_dict(self) -> dict:
        return {
            "scan_type": self.scan_type,
            "target": self.target,
            "priority": self.priority,
            "reason": self.reason,
            "confidence": self.confidence,
        }


class AdaptiveEnumEngine:
    """Response-driven scanning engine. Adapts recon based on findings."""

    def __init__(self, graph: Optional[GraphMemory] = None):
        self._graph = graph or get_graph_memory()
        self._rate_limiter = get_rate_limiter()
        self._decisions: List[ScanDecision] = []
        self._completed_scans: Set[str] = set()
        self._detected_tech: Dict[str, Set[str]] = {}  # target → {technologies}

    async def analyze_target(self, url: str, headers: dict, body: str,
                             status_code: int) -> List[ScanDecision]:
        """Analyze a target response and generate next scan decisions."""
        decisions = []
        target_lower = url.lower()
        hostname = self._extract_hostname(url)
        combined = json.dumps(headers).lower() + " " + body.lower()

        if hostname not in self._detected_tech:
            self._detected_tech[hostname] = set()

        for tech, sig in TECH_SIGNATURES.items():
            if any(ind.lower() in combined for ind in sig["indicators"]):
                if tech not in self._detected_tech[hostname]:
                    self._detected_tech[hostname].add(tech)
                    for scan in sig["next_scans"]:
                        if scan not in self._completed_scans:
                            template = SCAN_TEMPLATES.get(scan)
                            decisions.append(ScanDecision(
                                scan_type=scan,
                                target=url,
                                priority=7 if scan in ("origin-ip", "log4j", "env-file") else 5,
                                reason=f"Detected {tech} → recommended {scan} scan",
                                template=template,
                                confidence=0.8,
                            ))

        # Status-code based decisions
        if status_code == 401:
            decisions.append(ScanDecision(
                scan_type="auth-bypass", target=url, priority=8,
                reason="401 Unauthorized → test auth bypass",
                confidence=0.6,
            ))
        elif status_code == 403:
            decisions.append(ScanDecision(
                scan_type="forbidden-bypass", target=url, priority=7,
                reason="403 Forbidden → test path bypass, method override",
                confidence=0.6,
            ))
        elif status_code == 500:
            decisions.append(ScanDecision(
                scan_type="error-analysis", target=url, priority=9,
                reason="500 Internal Server Error → possible debugging/page source leak",
                confidence=0.7,
            ))
        elif status_code == 301 or status_code == 302:
            location = headers.get("location", "") or headers.get("Location", "")
            if location and "login" in location.lower():
                decisions.append(ScanDecision(
                    scan_type="auth-bypass", target=url, priority=8,
                    reason="Redirect to login page → test auth bypass",
                    confidence=0.5,
                ))

        # Content-type based decisions
        ct = (headers.get("content-type", "") or headers.get("Content-Type", "")).lower()
        if "graphql" in ct or "/graphql" in url:
            decisions.append(ScanDecision(
                scan_type="graphql-introspection", target=url, priority=9,
                reason="GraphQL endpoint detected → test introspection",
                confidence=0.9,
            ))
        if "json" in ct:
            decisions.append(ScanDecision(
                scan_type="api-fuzz", target=url, priority=6,
                reason="JSON API → fuzz endpoints and parameters",
                confidence=0.6,
            ))
        if "xml" in ct:
            decisions.append(ScanDecision(
                scan_type="xxe", target=url, priority=7,
                reason="XML endpoint → test XXE injection",
                confidence=0.6,
            ))

        # Technology-specific decisions from headers
        server = (headers.get("server", "") or headers.get("Server", "")).lower()
        if "iis" in server:
            decisions.append(ScanDecision(
                scan_type="iis-shortname", target=url, priority=6,
                reason="IIS detected → test shortname enumeration",
                confidence=0.7,
            ))

        # Check for cloud metadata exposure
        if "x-amz-request-id" in headers or "x-amz-id-2" in headers:
            decisions.append(ScanDecision(
                scan_type="s3-object-acl", target=url, priority=8,
                reason="S3 endpoint detected → check bucket ACL",
                confidence=0.8,
            ))

        self._decisions.extend(decisions)
        return decisions

    def analyze_graph_state(self, target: str) -> List[ScanDecision]:
        """Analyze current graph memory state for additional scan suggestions."""
        decisions = []
        hostname = self._extract_hostname(target)

        # Check for ports discovered
        ports_found = self._graph.find_entity(EntityType.PORT, tag=f"port_443")
        port_443_exists = any(p.properties.get("port") == 443 for p in ports_found) if ports_found else False
        port_80_exists = any(p.properties.get("port") == 80 for p in self._graph.find_entity(EntityType.PORT, tag="port_80")) if self._graph.find_entity(EntityType.PORT, tag="port_80") else False
        port_8443_exists = any(p.properties.get("port") == 8443 for p in self._graph.find_entity(EntityType.PORT, tag="port_8443")) if self._graph.find_entity(EntityType.PORT, tag="port_8443") else False

        if not port_443_exists and not port_80_exists:
            decisions.append(ScanDecision(
                scan_type="port-scan-common", target=target, priority=10,
                reason="No ports discovered yet → initial port scan needed",
                confidence=1.0,
            ))

        # Check for tech detection
        if self._detected_tech.get(hostname):
            if "wordpress" in self._detected_tech[hostname]:
                decisions.append(ScanDecision(
                    scan_type="wp-user-enum", target=target, priority=6,
                    reason="WordPress detected → enumerate users",
                    confidence=0.7,
                ))

        # Check for subdomain findings
        subdomain_entities = self._graph.find_entity(EntityType.DOMAIN, tag="subfinder")
        if subdomain_entities and len(subdomain_entities) > 0:
            new_subs = [s for s in subdomain_entities if s.name != hostname
                       and f"scanned:{s.name}" not in self._completed_scans]
            for sub in new_subs[:5]:
                decisions.append(ScanDecision(
                    scan_type="http-probe", target=sub.name, priority=5,
                    reason=f"New subdomain discovered: {sub.name} → probe HTTP",
                    confidence=0.8,
                ))
                self._completed_scans.add(f"scanned:{sub.name}")

        self._decisions.extend(decisions)
        return decisions

    def get_prioritized_decisions(self, min_priority: int = 3) -> List[ScanDecision]:
        """Get decisions sorted by priority (highest first)."""
        filtered = [d for d in self._decisions if d.priority >= min_priority
                   and d.scan_type not in self._completed_scans]
        return sorted(filtered, key=lambda d: d.priority, reverse=True)

    def mark_completed(self, scan_type: str, target: str):
        self._completed_scans.add(f"{scan_type}:{target}")

    def get_technologies(self, hostname: str) -> Set[str]:
        return self._detected_tech.get(hostname, set())

    def get_summary(self) -> dict:
        return {
            "pending_decisions": len([d for d in self._decisions
                                     if d.scan_type not in self._completed_scans]),
            "completed_scans": len(self._completed_scans),
            "technologies_detected": {k: list(v) for k, v in self._detected_tech.items()},
        }

    @staticmethod
    def _extract_hostname(url: str) -> str:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        return (parsed.hostname or url).lower().strip()
