"""
WordPress CMS Security Agent — Detects WordPress-specific vulnerabilities:
- Version disclosure, wp-json exposure, xmlrpc abuse
- Plugin/theme enumeration via known paths
- User enumeration, debug log exposure, upload dir listing
"""

import asyncio
from typing import List
import httpx
from itzraven.agents.base_agent import BaseAgent, AgentResult, Finding, AgentStatus
from itzraven.core.logger import get_logger

logger = get_logger()


WORDPRESS_CHECKS = [
    {"path": "/wp-admin/", "name": "wp-admin exposed", "severity": "medium"},
    {"path": "/wp-login.php", "name": "wp-login exposed", "severity": "low"},
    {"path": "/wp-json/", "name": "WP REST API exposed", "severity": "medium"},
    {"path": "/wp-json/wp/v2/users/", "name": "User enumeration via REST API", "severity": "high"},
    {"path": "/xmlrpc.php", "name": "XML-RPC enabled", "severity": "medium"},
    {"path": "/wp-content/debug.log", "name": "Debug log exposed", "severity": "critical"},
    {"path": "/wp-content/uploads/", "name": "Upload dir listing enabled", "severity": "medium"},
    {"path": "/wp-content/plugins/", "name": "Plugin directory listing", "severity": "medium"},
    {"path": "/readme.html", "name": "Readme file exposed", "severity": "low"},
    {"path": "/wp-config.php.bak", "name": "Config backup file", "severity": "critical"},
    {"path": "/wp-config.php~", "name": "Config backup (tilde)", "severity": "critical"},
    {"path": "/wp-config.php.old", "name": "Config backup (old)", "severity": "critical"},
    {"path": "/wp-config.php.save", "name": "Config backup (save)", "severity": "critical"},
    {"path": "/.wp-config.php.swp", "name": "Vim swap file", "severity": "critical"},
    {"path": "/wp-content/wp-config.php", "name": "Config in wp-content", "severity": "critical"},
    {"path": "/wp-admin/admin-ajax.php", "name": "admin-ajax exposed", "severity": "low"},
    {"path": "/wp-json/wp/v2/posts/", "name": "Posts API exposed", "severity": "info"},
    {"path": "/author/1/", "name": "Author page exists", "severity": "low"},
    {"path": "/?author=1", "name": "User enumeration via query", "severity": "medium"},
    {"path": "/wp-content/themes/", "name": "Theme directory listing", "severity": "medium"},
]

PLUGIN_PATHS = [
    "/wp-content/plugins/akismet/", "/wp-content/plugins/woocommerce/",
    "/wp-content/plugins/elementor/", "/wp-content/plugins/jetpack/",
    "/wp-content/plugins/wordfence/", "/wp-content/plugins/yoast-seo/",
    "/wp-content/plugins/contact-form-7/", "/wp-content/plugins/wp-super-cache/",
    "/wp-content/plugins/all-in-one-wp-migration/", "/wp-content/plugins/revslider/",
    "/wp-content/plugins/gravityforms/", "/wp-content/plugins/bbpress/",
    "/wp-content/plugins/buddypress/", "/wp-content/plugins/advanced-custom-fields/",
]


class WordPressAgent(BaseAgent):
    def __init__(self, target: str, event_bus=None, memory_manager=None, **kwargs):
        super().__init__("WordPress Agent", target, event_bus=event_bus, memory_manager=memory_manager)

    async def execute(self) -> AgentResult:
        logger.info(f"{self.name}: Scanning {self.target} for WordPress vulnerabilities")

        base_url = self.target.rstrip("/")

        async with httpx.AsyncClient(timeout=10.0, verify=False, follow_redirects=True) as client:
            for check in WORDPRESS_CHECKS:
                if self.should_stop:
                    break
                await self.check_pause()
                await self._check_path(client, base_url, check)

            for plugin_path in PLUGIN_PATHS:
                await self._check_plugin(client, base_url, plugin_path)

            await self._check_version_disclosure(client, base_url)

            await self._run_nuclei_tags(tags=["wordpress", "wp-plugin", "wp-theme"], severity="high")

        return AgentResult(agent_name=self.name, status=AgentStatus.COMPLETED, findings=self.findings, execution_time=0)

    async def _check_path(self, client: httpx.AsyncClient, base_url: str, check: dict):
        try:
            r = await client.get(f"{base_url}{check['path']}")
            if r.status_code == 200 and r.status_code != 404:
                # Exclude standard 404 pages
                if "404" not in r.text[:100] and "not found" not in r.text[:100].lower():
                    self.add_finding(Finding(
                        title=f"WordPress: {check['name']}",
                        description=f"WordPress path {check['path']} returned {r.status_code}",
                        severity=check["severity"], category="cms",
                        evidence=f"GET {check['path']} → {r.status_code} ({len(r.content)} bytes)",
                        confidence=0.7,
                        remediation="Restrict access to wp-admin, disable xmlrpc, remove readme, protect wp-config",
                    ))
        except Exception:
            pass

    async def _check_plugin(self, client: httpx.AsyncClient, base_url: str, plugin_path: str):
        try:
            r = await client.get(f"{base_url}{plugin_path}")
            if r.status_code == 200:
                self.add_finding(Finding(
                    title=f"WordPress Plugin Detected: {plugin_path.split('/')[-2]}",
                    description=f"Plugin installed at {plugin_path}",
                    severity="low", category="cms",
                    evidence=f"GET {plugin_path} → {r.status_code} ({len(r.content)} bytes)",
                    confidence=0.6,
                    remediation="Keep all plugins updated to latest versions",
                ))
        except Exception:
            pass

    async def _check_version_disclosure(self, client: httpx.AsyncClient, base_url: str):
        try:
            r = await client.get(f"{base_url}/wp-json/")
            if r.status_code == 200:
                import json
                try:
                    data = r.json()
                    version = data.get("version", "") or data.get("generator", "")
                    if version:
                        self.add_finding(Finding(
                            title=f"WordPress Version Disclosure: {version}",
                            description=f"WordPress version {version} exposed via REST API",
                            severity="medium", category="info_disclosure",
                            evidence=f"GET /wp-json/ → version: {version}",
                            confidence=0.8,
                            remediation="Remove version info from REST API responses",
                        ))
                except (json.JSONDecodeError, Exception):
                    pass
        except Exception:
            pass
