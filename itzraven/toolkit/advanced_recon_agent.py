"""
AdvancedReconAgent — Implements top bug bounty recon techniques.
Next.js manifest enum, qsreplace fuzzing, DOM sink detection,
backup file scan, CDN bypass, JS domain discovery.
"""
import asyncio
import json
from pathlib import Path
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse

import httpx

from itzraven.agents.base_agent import BaseAgent, AgentResult, Finding, AgentStatus
from itzraven.toolkit.bbrecon import (
    NextJSManifestEnumerator,
    QSReplaceFuzzer,
    DOMSinkDetector,
    BackupFileScanner,
    CDNOriginBypass,
)
from itzraven.core.logger import get_logger

logger = get_logger()


class AdvancedReconAgent(BaseAgent):
    def __init__(self, target: str, event_bus=None, memory_manager=None, scope=None, scan_depth: str = "deep"):
        name = "Advanced Recon Agent"
        super().__init__(name, target, event_bus=event_bus, memory_manager=memory_manager, scope=scope)
        self._domain = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
        self._base = target.rstrip("/")
        self.scan_depth = scan_depth
        self.nextjs = NextJSManifestEnumerator()
        self.qsreplace = QSReplaceFuzzer()
        self.dom_sink = DOMSinkDetector()
        self.backup = BackupFileScanner()
        self.cdn = CDNOriginBypass()

    async def execute(self) -> AgentResult:
        logger.info(f"{self.name}: Running advanced recon on {self._domain}...")

        common_paths = ["/", "/api", "/admin", "/login", "/search", "/.env", "/robots.txt"]

        # 1. Next.js manifest enumeration
        await self._emit_progress("🔍 Checking Next.js manifest...", 0.1)
        next_routes = await self.nextjs.enumerate(self._base)
        if next_routes:
            self.add_finding(Finding(
                title=f"Next.js Routes: {len(next_routes)} discovered",
                severity="info", category="recon",
                description=f"Discovered {len(next_routes)} routes via Next.js BUILD_MANIFEST",
                evidence="\n".join(next_routes[:15]),
                confidence=0.95,
            ))

        # 2. QSReplace fuzzing for LFI
        if next_routes:
            await self._emit_progress("🎯 qsreplace fuzzing...", 0.3)
            for vuln in ["lfi", "open_redirect", "sqli"]:
                urls = [self._base + p for p in next_routes[:10]]
                results = await self.qsreplace.fuzz_urls(urls, vuln)
                for r in results:
                    severity = "critical" if vuln in ("lfi", "sqli") else "high"
                    self.add_finding(Finding(
                        title=f"[qsreplace] {vuln.upper()} in {r.get('param', '?')}",
                        severity=severity, category=vuln,
                        description=f"Mass fuzzing detected {vuln} at {r['url']}",
                        evidence=f"Payload: {r['payload']}\nIndicator: {r.get('indicator', '')}",
                        remediation="Validate and sanitize all input parameters",
                        confidence=0.7,
                    ))

        # 3. Backup file scan
        await self._emit_progress("📁 Scanning backup files...", 0.5)
        backup_results = await self.backup.scan(self._base, common_paths)
        for br in backup_results:
            self.add_finding(Finding(
                title=f"Backup File: {br['path']}{br['ext']}",
                severity="medium", category="info_disclosure",
                description=f"Backup file exposed at {br['backup_url']}",
                evidence=f"HTTP 200 | {br['size']} bytes",
                remediation="Remove backup files from web root",
                confidence=0.85,
            ))

        # 4. DOM sink detection
        await self._emit_progress("🕸️ Scanning JS for DOM sinks...", 0.7)
        js_urls = [self._base + "/_next/static/chunks/pages/index.js",
                    self._base + "/static/js/main.js",
                    self._base + "/app.js",
                    self._base + "/bundle.js"]
        dom_results = await self.dom_sink.scan_js(js_urls)
        if dom_results:
            for dr in dom_results[:5]:
                self.add_finding(Finding(
                    title=f"DOM Sink: {dr['sink']}",
                    severity="info", category="xss",
                    description=f"Dangerous DOM sink in JS: {dr['sink']}",
                    evidence=f"File: {dr['url']}\nContext: {dr.get('context', '')[:100]}",
                    remediation="Avoid using innerHTML, eval(), postMessage with untrusted data",
                    confidence=0.6,
                ))

        # 5. CDN origin bypass
        await self._emit_progress("🌐 CDN origin bypass check...", 0.9)
        cdn_result = await self.cdn.find_origin(self._domain)
        if cdn_result.get("ips"):
            self.add_finding(Finding(
                title=f"CDN Origin IPs: {cdn_result['ips']}",
                severity="info", category="recon",
                description=f"Found {len(cdn_result['ips'])} real IPs behind CDN",
                evidence=f"Techniques: {cdn_result['techniques'][:5]}",
                confidence=0.7,
            ))

        return AgentResult(
            agent_name=self.name,
            status=AgentStatus.COMPLETED,
            findings=self.findings,
            execution_time=0,
            metadata={"nextjs_routes": len(next_routes), "dom_sinks": len(dom_results)},
        )

    async def _emit_progress(self, msg: str, progress: float):
        logger.info(f"  {msg}")
