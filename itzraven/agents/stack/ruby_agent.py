"""
Ruby / Ruby on Rails Stack Security Agent
"""

import httpx
from itzraven.agents.base_agent import BaseAgent, AgentResult, Finding, AgentStatus
from itzraven.core.logger import get_logger

logger = get_logger()

RUBY_CHECKS = [
    {"path": "/.env", "name": "Environment file", "severity": "critical"},
    {"path": "/Gemfile", "name": "Gemfile manifest", "severity": "medium"},
    {"path": "/Gemfile.lock", "name": "Gemfile lock", "severity": "medium"},
    {"path": "/config/database.yml", "name": "Database config", "severity": "critical"},
    {"path": "/config/secrets.yml", "name": "Secrets config", "severity": "critical"},
    {"path": "/config/credentials.yml.enc", "name": "Credentials encrypted", "severity": "high"},
    {"path": "/config/routes.rb", "name": "Routes config", "severity": "medium"},
    {"path": "/db/schema.rb", "name": "DB schema", "severity": "high"},
    {"path": "/db/migrate/", "name": "DB migrations", "severity": "high"},
    {"path": "/log/", "name": "Log directory", "severity": "high"},
    {"path": "/tmp/", "name": "Temp directory", "severity": "high"},
    {"path": "/public/", "name": "Public directory", "severity": "low"},
    {"path": "/assets/", "name": "Assets directory", "severity": "low"},
    {"path": "/storage/", "name": "Storage directory", "severity": "medium"},
    {"path": "/rails/info/routes", "name": "Rails route info", "severity": "high"},
    {"path": "/rails/info/properties", "name": "Rails properties", "severity": "high"},
    {"path": "/sidekiq/", "name": "Sidekiq dashboard", "severity": "high"},
    {"path": "/delayed_job/", "name": "Delayed job overview", "severity": "medium"},
    {"path": "/admin/", "name": "Admin panel", "severity": "medium"},
    {"path": "/api/", "name": "API endpoint", "severity": "low"},
]


class RubyAgent(BaseAgent):
    def __init__(self, target: str, event_bus=None, memory_manager=None, **kwargs):
        super().__init__("Ruby Stack Agent", target, event_bus=event_bus, memory_manager=memory_manager)

    async def execute(self) -> AgentResult:
        logger.info(f"{self.name}: Scanning {self.target} for Ruby/Rails-specific vulnerabilities")

        base_url = self.target.rstrip("/")
        async with httpx.AsyncClient(timeout=10.0, verify=False, follow_redirects=True) as client:
            for check in RUBY_CHECKS:
                if self.should_stop:
                    break
                await self.check_pause()
                try:
                    r = await client.get(f"{base_url}{check['path']}")
                    if r.status_code in (200, 403):
                        self.add_finding(Finding(
                            title=f"Ruby: {check['name']}",
                            description=f"Ruby/Rails path {check['path']} returned {r.status_code}",
                            severity=check["severity"], category="stack",
                            evidence=f"GET {check['path']} → {r.status_code}",
                            confidence=0.7,
                            remediation="Disable Rails info routes in production, protect credentials",
                        ))
                except Exception:
                    pass

            await self._run_nuclei_tags(tags=["ruby", "rails", "sidekiq"], severity="high")

        return AgentResult(agent_name=self.name, status=AgentStatus.COMPLETED, findings=self.findings, execution_time=0)
