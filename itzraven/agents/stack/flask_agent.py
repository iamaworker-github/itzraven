"""
Flask Framework Security Agent
"""

import httpx
from itzraven.agents.base_agent import BaseAgent, AgentResult, Finding, AgentStatus
from itzraven.core.logger import get_logger

logger = get_logger()

FLASK_CHECKS = [
    {"path": "/.env", "name": "Environment file", "severity": "critical"},
    {"path": "/config.py", "name": "Config file", "severity": "critical"},
    {"path": "/config.py.bak", "name": "Config backup", "severity": "critical"},
    {"path": "/requirements.txt", "name": "Requirements file", "severity": "medium"},
    {"path": "/Pipfile", "name": "Pipfile", "severity": "medium"},
    {"path": "/Pipfile.lock", "name": "Pipfile lock", "severity": "medium"},
    {"path": "/console", "name": "Flask debug console", "severity": "critical"},
    {"path": "/admin", "name": "Admin endpoint", "severity": "medium"},
    {"path": "/api/", "name": "API endpoint", "severity": "low"},
    {"path": "/swagger/", "name": "Swagger docs", "severity": "medium"},
    {"path": "/apidocs/", "name": "API docs", "severity": "medium"},
    {"path": "/openapi.json", "name": "OpenAPI spec", "severity": "medium"},
    {"path": "/flask/", "name": "Flask subdir", "severity": "info"},
    {"path": "/static/", "name": "Static files", "severity": "low"},
]


class FlaskAgent(BaseAgent):
    def __init__(self, target: str, event_bus=None, memory_manager=None, **kwargs):
        super().__init__("Flask Stack Agent", target, event_bus=event_bus, memory_manager=memory_manager)

    async def execute(self) -> AgentResult:
        logger.info(f"{self.name}: Scanning {self.target} for Flask-specific vulnerabilities")

        base_url = self.target.rstrip("/")
        async with httpx.AsyncClient(timeout=10.0, verify=False, follow_redirects=True) as client:
            for check in FLASK_CHECKS:
                if self.should_stop:
                    break
                await self.check_pause()
                try:
                    r = await client.get(f"{base_url}{check['path']}")
                    if r.status_code in (200, 403):
                        self.add_finding(Finding(
                            title=f"Flask: {check['name']}",
                            description=f"Flask path {check['path']} returned {r.status_code}",
                            severity=check["severity"], category="stack",
                            evidence=f"GET {check['path']} → {r.status_code}",
                            confidence=0.7,
                            remediation="Disable debug mode, protect env and config files",
                        ))
                except Exception:
                    pass

            await self._run_nuclei_tags(tags=["flask", "python", "werkzeug"], severity="high")

        return AgentResult(agent_name=self.name, status=AgentStatus.COMPLETED, findings=self.findings, execution_time=0)
