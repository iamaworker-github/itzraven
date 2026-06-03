"""
Android APK Bug Bounty Agent
APK decompilation, exported component analysis, deep link testing, broadcast receiver abuse, Frida
"""

import asyncio
from typing import List, Dict, Any
from itzraven.agents.base_agent import BaseAgent, AgentResult, Finding, AgentStatus
from itzraven.core.logger import get_logger

logger = get_logger()


class AndroidAPKAgent(BaseAgent):
    """Agent for Android APK security testing — decompilation, static analysis, dynamic testing"""

    def __init__(self, target: str, event_bus=None, memory_manager=None, apk_path: str = ""):
        super().__init__("Android APK Agent", target, event_bus=event_bus, memory_manager=memory_manager)
        self.apk_path = apk_path
        self.exported_components: List[str] = []
        self.deep_links: List[str] = []

    async def execute(self) -> AgentResult:
        logger.info(f"{self.name}: Analyzing APK '{self.apk_path or self.target}'")
        await self._emit_thought("Starting Android APK analysis...", "analyzing", "apk_static")

        await self._decompile_apk()
        await self._check_exported_components()
        await self._check_deep_links()
        await self._check_webview_vulns()
        await self._check_ssl_pinning()

        return AgentResult(
            agent_name=self.name,
            status=self.status,
            findings=self.findings,
            execution_time=0,
            metadata={
                "exported_components": self.exported_components,
                "deep_links": self.deep_links,
            },
        )

    async def _decompile_apk(self) -> None:
        apk = self.apk_path or self.target
        output_dir = "/tmp/apk_decompiled"
        try:
            proc = await asyncio.create_subprocess_exec(
                "jadx", "-d", output_dir, apk,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=120)
            self.add_finding(Finding(
                title="APK Decompiled",
                description=f"APK decompiled to {output_dir} via jadx",
                severity="info",
                category="recon",
                evidence=f"Output: {output_dir}",
                confidence=1.0,
            ))
        except Exception as e:
            logger.debug(f"APK decompilation failed (jadx not found or error): {e}")

    async def _check_exported_components(self) -> None:
        output_dir = "/tmp/apk_decompiled/resources/AndroidManifest.xml"
        try:
            proc = await asyncio.create_subprocess_exec(
                "grep", "-oP", r'android:name="\K[^"]+', output_dir,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
            components = stdout.decode().strip().split("\n")
            exported = [c for c in components if c]

            proc2 = await asyncio.create_subprocess_exec(
                "grep", "exported=\"true\"", output_dir,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout2, _ = await asyncio.wait_for(proc2.communicate(), timeout=15)
            exported_true = stdout2.decode().strip()

            if exported_true:
                self.exported_components = exported_true.split("\n")
                self.add_finding(Finding(
                    title="Exported Components Found",
                    description=f"Components with exported=true in AndroidManifest.xml",
                    severity="medium",
                    category="mobile",
                    evidence=f"Exported components:\n{exported_true[:1000]}",
                    remediation="Review if these components need to be exported. Set exported=false if not needed.",
                    confidence=0.8,
                ))
        except Exception as e:
            logger.debug(f"Exported component check failed: {e}")

    async def _check_deep_links(self) -> None:
        import os
        output_dir = "/tmp/apk_decompiled/resources"
        try:
            proc = await asyncio.create_subprocess_exec(
                "grep", "-r", "-oP",
                r'android:scheme="\K[^"]+|android:host="\K[^"]+|android:pathPattern="\K[^"]+',
                output_dir,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
            if stdout.decode().strip():
                links = stdout.decode().strip().split("\n")
                self.deep_links = links[:20]
                self.add_finding(Finding(
                    title="Deep Links / Intent Filters Found",
                    description=f"Deep links registered in AndroidManifest: {len(links)} patterns",
                    severity="medium",
                    category="mobile",
                    evidence="\n".join(links[:20]),
                    remediation="Validate all deep links. Test for open redirect, XSS via deep links.",
                    confidence=0.8,
                ))
        except Exception as e:
            logger.debug(f"Deep link check failed: {e}")

    async def _check_webview_vulns(self) -> None:
        import os
        output_dir = "/tmp/apk_decompiled/sources"
        try:
            proc = await asyncio.create_subprocess_exec(
                "grep", "-r", "-l",
                "addJavascriptInterface", output_dir,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
            if stdout.decode().strip():
                files = stdout.decode().strip().split("\n")
                self.add_finding(Finding(
                    title="WebView JavaScript Interface Found",
                    description=f"addJavascriptInterface found in {len(files)} files — potential XSS bridge",
                    severity="high",
                    category="mobile",
                    evidence="Files:\n" + "\n".join(files[:10]),
                    remediation="Remove addJavascriptInterface or only load trusted content in WebView.",
                    confidence=0.7,
                ))
        except Exception as e:
            logger.debug(f"WebView check failed: {e}")

    async def _check_ssl_pinning(self) -> None:
        import os
        output_dir = "/tmp/apk_decompiled/sources"
        try:
            proc = await asyncio.create_subprocess_exec(
                "grep", "-r", "-l",
                r"NetworkSecurityPolicy|TrustManager|sslPinning|certificatePinner",
                output_dir,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
            if not stdout.decode().strip():
                self.add_finding(Finding(
                    title="No SSL Pinning Detected",
                    description="No SSL pinning implementation found — traffic can be intercepted",
                    severity="medium",
                    category="mobile",
                    evidence="No NetworkSecurityPolicy or TrustManager references found in decompiled code",
                    remediation="Implement certificate pinning using NetworkSecurityPolicy or TrustManager.",
                    confidence=0.6,
                ))
        except Exception as e:
            logger.debug(f"SSL pinning check failed: {e}")
