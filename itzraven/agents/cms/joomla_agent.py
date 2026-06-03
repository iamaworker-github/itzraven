"""
Joomla CMS Security Agent
"""

import httpx
from itzraven.agents.base_agent import BaseAgent, AgentResult, Finding, AgentStatus
from itzraven.core.logger import get_logger

logger = get_logger()

JOOMLA_CHECKS = [
    {"path": "/administrator/", "name": "Admin panel exposed", "severity": "medium"},
    {"path": "/components/", "name": "Components directory listing", "severity": "medium"},
    {"path": "/modules/", "name": "Modules directory listing", "severity": "medium"},
    {"path": "/plugins/", "name": "Plugins directory listing", "severity": "medium"},
    {"path": "/logs/", "name": "Logs directory", "severity": "high"},
    {"path": "/tmp/", "name": "Temp directory", "severity": "high"},
    {"path": "/configuration.php", "name": "Configuration file", "severity": "critical"},
    {"path": "/configuration.php.bak", "name": "Config backup", "severity": "critical"},
    {"path": "/htaccess.txt", "name": "Htaccess template", "severity": "low"},
    {"path": "/robots.txt", "name": "Robots.txt", "severity": "low"},
    {"path": "/LICENSE.txt", "name": "License file", "severity": "low"},
    {"path": "/README.txt", "name": "Readme file", "severity": "low"},
    {"path": "/language/", "name": "Language directory", "severity": "medium"},
    {"path": "/cache/", "name": "Cache directory", "severity": "medium"},
]


class JoomlaAgent(BaseAgent):
    def __init__(self, target: str, event_bus=None, memory_manager=None, **kwargs):
        super().__init__("Joomla Agent", target, event_bus=event_bus, memory_manager=memory_manager)

    async def execute(self) -> AgentResult:
        logger.info(f"{self.name}: Scanning {self.target} for Joomla vulnerabilities")

        base_url = self.target.rstrip("/")
        async with httpx.AsyncClient(timeout=10.0, verify=False, follow_redirects=True) as client:
            for check in JOOMLA_CHECKS:
                if self.should_stop:
                    break
                await self.check_pause()
                try:
                    r = await client.get(f"{base_url}{check['path']}")
                    if r.status_code in (200, 403):
                        self.add_finding(Finding(
                            title=f"Joomla: {check['name']}",
                            description=f"Joomla path {check['path']} returned {r.status_code}",
                            severity=check["severity"], category="cms",
                            evidence=f"GET {check['path']} → {r.status_code}",
                            confidence=0.7,
                            remediation="Restrict access to Joomla admin and sensitive directories",
                        ))
                except Exception:
                    pass

            await self._run_nuclei_tags(tags=["joomla"], severity="high")

        return AgentResult(agent_name=self.name, status=AgentStatus.COMPLETED, findings=self.findings, execution_time=0)
