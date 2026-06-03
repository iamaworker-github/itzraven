"""
PHP Stack Security Agent
"""

import httpx
from itzraven.agents.base_agent import BaseAgent, AgentResult, Finding, AgentStatus
from itzraven.core.logger import get_logger

logger = get_logger()

PHP_CHECKS = [
    {"path": "/info.php", "name": "PHP info exposed", "severity": "high"},
    {"path": "/phpinfo.php", "name": "PHP info (alt)", "severity": "high"},
    {"path": "/php_info.php", "name": "PHP info (alt2)", "severity": "high"},
    {"path": "/.git/config", "name": "Git config exposed", "severity": "critical"},
    {"path": "/.env", "name": "Environment file", "severity": "critical"},
    {"path": "/composer.json", "name": "Composer manifest", "severity": "medium"},
    {"path": "/composer.lock", "name": "Composer lock file", "severity": "medium"},
    {"path": "/symfony.lock", "name": "Symfony lock file", "severity": "medium"},
    {"path": "/var/log/", "name": "Log directory", "severity": "high"},
    {"path": "/vendor/", "name": "Vendor directory", "severity": "high"},
    {"path": "/.htaccess", "name": "Htaccess accessible", "severity": "high"},
    {"path": "/test.php", "name": "Test PHP file", "severity": "medium"},
    {"path": "/shell.php", "name": "Shell file check", "severity": "critical"},
    {"path": "/phpunit.xml", "name": "PHPUnit config", "severity": "medium"},
]


class PHPAgent(BaseAgent):
    def __init__(self, target: str, event_bus=None, memory_manager=None, **kwargs):
        super().__init__("PHP Stack Agent", target, event_bus=event_bus, memory_manager=memory_manager)

    async def execute(self) -> AgentResult:
        logger.info(f"{self.name}: Scanning {self.target} for PHP-specific vulnerabilities")

        base_url = self.target.rstrip("/")
        async with httpx.AsyncClient(timeout=10.0, verify=False, follow_redirects=True) as client:
            for check in PHP_CHECKS:
                if self.should_stop:
                    break
                await self.check_pause()
                try:
                    r = await client.get(f"{base_url}{check['path']}")
                    if r.status_code in (200, 403):
                        self.add_finding(Finding(
                            title=f"PHP: {check['name']}",
                            description=f"PHP path {check['path']} returned {r.status_code}",
                            severity=check["severity"], category="stack",
                            evidence=f"GET {check['path']} → {r.status_code}",
                            confidence=0.7,
                            remediation="Remove debug files, protect env and vendor dirs",
                        ))
                except Exception:
                    pass

            await self._run_nuclei_tags(tags=["php", "lfi", "php-cve"], severity="high")

        return AgentResult(agent_name=self.name, status=AgentStatus.COMPLETED, findings=self.findings, execution_time=0)
