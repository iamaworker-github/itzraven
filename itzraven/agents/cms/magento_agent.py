"""
Magento CMS Security Agent
"""

import httpx
from itzraven.agents.base_agent import BaseAgent, AgentResult, Finding, AgentStatus
from itzraven.core.logger import get_logger

logger = get_logger()

MAGENTO_CHECKS = [
    {"path": "/admin", "name": "Admin panel", "severity": "medium"},
    {"path": "/admin/", "name": "Admin panel trailing", "severity": "medium"},
    {"path": "/setup/", "name": "Setup wizard", "severity": "high"},
    {"path": "/download/", "name": "Download directory", "severity": "high"},
    {"path": "/media/", "name": "Media directory", "severity": "medium"},
    {"path": "/var/", "name": "Var directory", "severity": "high"},
    {"path": "/var/log/", "name": "Log directory", "severity": "high"},
    {"path": "/var/log/system.log", "name": "System log", "severity": "critical"},
    {"path": "/var/log/exception.log", "name": "Exception log", "severity": "critical"},
    {"path": "/app/etc/local.xml", "name": "Local config", "severity": "critical"},
    {"path": "/app/etc/env.php", "name": "Environment config", "severity": "critical"},
    {"path": "/pub/media/", "name": "Pub media", "severity": "medium"},
    {"path": "/errors/", "name": "Error pages", "severity": "low"},
    {"path": "/index.php/admin/", "name": "Index admin path", "severity": "medium"},
    {"path": "/static/version/", "name": "Static versioned assets", "severity": "info"},
]


class MagentoAgent(BaseAgent):
    def __init__(self, target: str, event_bus=None, memory_manager=None, **kwargs):
        super().__init__("Magento Agent", target, event_bus=event_bus, memory_manager=memory_manager)

    async def execute(self) -> AgentResult:
        logger.info(f"{self.name}: Scanning {self.target} for Magento vulnerabilities")

        base_url = self.target.rstrip("/")
        async with httpx.AsyncClient(timeout=10.0, verify=False, follow_redirects=True) as client:
            for check in MAGENTO_CHECKS:
                if self.should_stop:
                    break
                await self.check_pause()
                try:
                    r = await client.get(f"{base_url}{check['path']}")
                    if r.status_code in (200, 403):
                        self.add_finding(Finding(
                            title=f"Magento: {check['name']}",
                            description=f"Magento path {check['path']} returned {r.status_code}",
                            severity=check["severity"], category="cms",
                            evidence=f"GET {check['path']} → {r.status_code}",
                            confidence=0.7,
                            remediation="Restrict access to Magento admin and sensitive directories",
                        ))
                except Exception:
                    pass

            await self._run_nuclei_tags(tags=["magento"], severity="high")

        return AgentResult(agent_name=self.name, status=AgentStatus.COMPLETED, findings=self.findings, execution_time=0)
