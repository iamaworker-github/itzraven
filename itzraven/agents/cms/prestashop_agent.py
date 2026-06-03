"""
PrestaShop CMS Security Agent
"""

import httpx
from itzraven.agents.base_agent import BaseAgent, AgentResult, Finding, AgentStatus
from itzraven.core.logger import get_logger

logger = get_logger()

PRESTASHOP_CHECKS = [
    {"path": "/admin/", "name": "Admin directory", "severity": "medium"},
    {"path": "/modules/", "name": "Modules directory", "severity": "medium"},
    {"path": "/themes/", "name": "Themes directory", "severity": "medium"},
    {"path": "/img/", "name": "Images directory", "severity": "low"},
    {"path": "/download/", "name": "Download directory", "severity": "high"},
    {"path": "/upload/", "name": "Upload directory", "severity": "high"},
    {"path": "/config/", "name": "Config directory", "severity": "critical"},
    {"path": "/config/settings.inc.php", "name": "Settings file", "severity": "critical"},
    {"path": "/cache/", "name": "Cache directory", "severity": "medium"},
    {"path": "/log/", "name": "Log directory", "severity": "high"},
    {"path": "/install/", "name": "Install directory", "severity": "critical"},
    {"path": "/install.php", "name": "Install script", "severity": "critical"},
    {"path": "/override/", "name": "Override directory", "severity": "medium"},
    {"path": "/translations/", "name": "Translations", "severity": "low"},
]


class PrestaShopAgent(BaseAgent):
    def __init__(self, target: str, event_bus=None, memory_manager=None, **kwargs):
        super().__init__("PrestaShop Agent", target, event_bus=event_bus, memory_manager=memory_manager)

    async def execute(self) -> AgentResult:
        logger.info(f"{self.name}: Scanning {self.target} for PrestaShop vulnerabilities")

        base_url = self.target.rstrip("/")
        async with httpx.AsyncClient(timeout=10.0, verify=False, follow_redirects=True) as client:
            for check in PRESTASHOP_CHECKS:
                if self.should_stop:
                    break
                await self.check_pause()
                try:
                    r = await client.get(f"{base_url}{check['path']}")
                    if r.status_code in (200, 403):
                        self.add_finding(Finding(
                            title=f"PrestaShop: {check['name']}",
                            description=f"PrestaShop path {check['path']} returned {r.status_code}",
                            severity=check["severity"], category="cms",
                            evidence=f"GET {check['path']} → {r.status_code}",
                            confidence=0.7,
                            remediation="Restrict access to PrestaShop admin and sensitive directories",
                        ))
                except Exception:
                    pass

            await self._run_nuclei_tags(tags=["prestashop"], severity="high")

        return AgentResult(agent_name=self.name, status=AgentStatus.COMPLETED, findings=self.findings, execution_time=0)
