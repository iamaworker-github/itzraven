"""
Drupal CMS Security Agent
"""

import httpx
from itzraven.agents.base_agent import BaseAgent, AgentResult, Finding, AgentStatus
from itzraven.core.logger import get_logger

logger = get_logger()

DRUPAL_CHECKS = [
    {"path": "/user/login", "name": "User login page", "severity": "low"},
    {"path": "/user/register", "name": "User registration", "severity": "medium"},
    {"path": "/admin", "name": "Admin path", "severity": "medium"},
    {"path": "/node/1", "name": "Node page accessible", "severity": "low"},
    {"path": "/sites/default/", "name": "Default site files", "severity": "high"},
    {"path": "/sites/default/files/", "name": "Files directory", "severity": "medium"},
    {"path": "/sites/default/settings.php", "name": "Settings file exposed", "severity": "critical"},
    {"path": "/.htaccess", "name": "Htaccess accessible", "severity": "high"},
    {"path": "/CHANGELOG.txt", "name": "Changelog exposed", "severity": "low"},
    {"path": "/README.txt", "name": "Readme exposed", "severity": "low"},
    {"path": "/cron.php", "name": "Cron.php accessible", "severity": "medium"},
    {"path": "/install.php", "name": "Install script", "severity": "high"},
    {"path": "/update.php", "name": "Update script", "severity": "high"},
    {"path": "/authorize.php", "name": "Authorize.php", "severity": "medium"},
]


class DrupalAgent(BaseAgent):
    def __init__(self, target: str, event_bus=None, memory_manager=None, **kwargs):
        super().__init__("Drupal Agent", target, event_bus=event_bus, memory_manager=memory_manager)

    async def execute(self) -> AgentResult:
        logger.info(f"{self.name}: Scanning {self.target} for Drupal vulnerabilities")

        base_url = self.target.rstrip("/")
        async with httpx.AsyncClient(timeout=10.0, verify=False, follow_redirects=True) as client:
            for check in DRUPAL_CHECKS:
                if self.should_stop:
                    break
                await self.check_pause()
                try:
                    r = await client.get(f"{base_url}{check['path']}")
                    if r.status_code in (200, 403):
                        self.add_finding(Finding(
                            title=f"Drupal: {check['name']}",
                            description=f"Drupal path {check['path']} returned {r.status_code}",
                            severity=check["severity"], category="cms",
                            evidence=f"GET {check['path']} → {r.status_code}",
                            confidence=0.7,
                            remediation="Restrict access to sensitive Drupal paths",
                        ))
                except Exception:
                    pass

            await self._run_nuclei_tags(tags=["drupal"], severity="high")

        return AgentResult(agent_name=self.name, status=AgentStatus.COMPLETED, findings=self.findings, execution_time=0)
