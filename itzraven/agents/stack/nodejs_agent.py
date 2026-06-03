"""
NodeJS Stack Security Agent
"""

import httpx
from itzraven.agents.base_agent import BaseAgent, AgentResult, Finding, AgentStatus
from itzraven.core.logger import get_logger

logger = get_logger()

NODEJS_CHECKS = [
    {"path": "/.env", "name": "Environment file", "severity": "critical"},
    {"path": "/package.json", "name": "Package manifest", "severity": "medium"},
    {"path": "/package-lock.json", "name": "Package lock file", "severity": "medium"},
    {"path": "/yarn.lock", "name": "Yarn lock file", "severity": "medium"},
    {"path": "/webpack.config.js", "name": "Webpack config", "severity": "medium"},
    {"path": "/.next/", "name": "Next.js build dir", "severity": "high"},
    {"path": "/next.config.js", "name": "Next.js config", "severity": "medium"},
    {"path": "/nuxt.config.js", "name": "Nuxt config", "severity": "medium"},
    {"path": "/server.js", "name": "Server entry point", "severity": "medium"},
    {"path": "/app.js", "name": "App entry point", "severity": "medium"},
    {"path": "/index.js", "name": "Index file", "severity": "medium"},
    {"path": "/node_modules/", "name": "Node modules exposed", "severity": "critical"},
    {"path": "/.npmrc", "name": "NPM config", "severity": "high"},
    {"path": "/sitemap.xml", "name": "Sitemap", "severity": "info"},
    {"path": "/robots.txt", "name": "Robots.txt", "severity": "info"},
]


class NodeJSAgent(BaseAgent):
    def __init__(self, target: str, event_bus=None, memory_manager=None, **kwargs):
        super().__init__("NodeJS Stack Agent", target, event_bus=event_bus, memory_manager=memory_manager)

    async def execute(self) -> AgentResult:
        logger.info(f"{self.name}: Scanning {self.target} for NodeJS-specific vulnerabilities")

        base_url = self.target.rstrip("/")
        async with httpx.AsyncClient(timeout=10.0, verify=False, follow_redirects=True) as client:
            for check in NODEJS_CHECKS:
                if self.should_stop:
                    break
                await self.check_pause()
                try:
                    r = await client.get(f"{base_url}{check['path']}")
                    if r.status_code in (200, 403):
                        self.add_finding(Finding(
                            title=f"NodeJS: {check['name']}",
                            description=f"NodeJS path {check['path']} returned {r.status_code}",
                            severity=check["severity"], category="stack",
                            evidence=f"GET {check['path']} → {r.status_code}",
                            confidence=0.7,
                            remediation="Disable directory listing, protect config and env files",
                        ))
                except Exception:
                    pass

            await self._run_nuclei_tags(tags=["nodejs", "express", "nextjs"], severity="high")

        return AgentResult(agent_name=self.name, status=AgentStatus.COMPLETED, findings=self.findings, execution_time=0)
