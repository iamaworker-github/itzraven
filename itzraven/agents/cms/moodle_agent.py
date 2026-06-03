"""
Moodle LMS Security Agent
"""

import httpx
from itzraven.agents.base_agent import BaseAgent, AgentResult, Finding, AgentStatus
from itzraven.core.logger import get_logger

logger = get_logger()

MOODLE_CHECKS = [
    {"path": "/admin/", "name": "Admin directory", "severity": "medium"},
    {"path": "/login/", "name": "Login page", "severity": "low"},
    {"path": "/course/", "name": "Course directory", "severity": "low"},
    {"path": "/course/view.php?id=1", "name": "Course page", "severity": "low"},
    {"path": "/user/profile.php", "name": "User profile", "severity": "medium"},
    {"path": "/pluginfile.php", "name": "Plugin file serving", "severity": "medium"},
    {"path": "/moodle/", "name": "Moodle subdirectory", "severity": "info"},
    {"path": "/config.php", "name": "Config file check", "severity": "critical"},
    {"path": "/backup/", "name": "Backup directory", "severity": "high"},
    {"path": "/data/", "name": "Data directory", "severity": "high"},
    {"path": "/repository/", "name": "Repository access", "severity": "medium"},
    {"path": "/theme/", "name": "Theme directory", "severity": "medium"},
    {"path": "/badges/", "name": "Badges endpoint", "severity": "low"},
    {"path": "/tag/", "name": "Tag system", "severity": "low"},
    {"path": "/notes/", "name": "Notes endpoint", "severity": "low"},
]


class MoodleAgent(BaseAgent):
    def __init__(self, target: str, event_bus=None, memory_manager=None, **kwargs):
        super().__init__("Moodle Agent", target, event_bus=event_bus, memory_manager=memory_manager)

    async def execute(self) -> AgentResult:
        logger.info(f"{self.name}: Scanning {self.target} for Moodle vulnerabilities")

        base_url = self.target.rstrip("/")
        async with httpx.AsyncClient(timeout=10.0, verify=False, follow_redirects=True) as client:
            for check in MOODLE_CHECKS:
                if self.should_stop:
                    break
                await self.check_pause()
                try:
                    r = await client.get(f"{base_url}{check['path']}")
                    if r.status_code in (200, 403):
                        self.add_finding(Finding(
                            title=f"Moodle: {check['name']}",
                            description=f"Moodle path {check['path']} returned {r.status_code}",
                            severity=check["severity"], category="cms",
                            evidence=f"GET {check['path']} → {r.status_code}",
                            confidence=0.7,
                            remediation="Restrict access to Moodle admin and sensitive endpoints",
                        ))
                except Exception:
                    pass

            await self._run_nuclei_tags(tags=["moodle"], severity="high")

        return AgentResult(agent_name=self.name, status=AgentStatus.COMPLETED, findings=self.findings, execution_time=0)
