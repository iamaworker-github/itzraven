"""
Spring Boot Framework Security Agent
"""

import httpx
from itzraven.agents.base_agent import BaseAgent, AgentResult, Finding, AgentStatus
from itzraven.core.logger import get_logger

logger = get_logger()

SPRING_PATHS = [
    {"path": "/actuator/", "name": "Actuator root", "severity": "medium"},
    {"path": "/actuator/health", "name": "Health endpoint", "severity": "low"},
    {"path": "/actuator/info", "name": "Info endpoint", "severity": "medium"},
    {"path": "/actuator/env", "name": "Env endpoint", "severity": "critical"},
    {"path": "/actuator/configprops", "name": "Config props", "severity": "critical"},
    {"path": "/actuator/beans", "name": "Beans endpoint", "severity": "medium"},
    {"path": "/actuator/mappings", "name": "Mappings endpoint", "severity": "high"},
    {"path": "/actuator/heapdump", "name": "Heap dump", "severity": "critical"},
    {"path": "/actuator/threaddump", "name": "Thread dump", "severity": "high"},
    {"path": "/actuator/loggers", "name": "Logger config", "severity": "high"},
    {"path": "/actuator/metrics", "name": "Metrics endpoint", "severity": "medium"},
    {"path": "/actuator/scheduledtasks", "name": "Scheduled tasks", "severity": "medium"},
    {"path": "/actuator/httptrace", "name": "HTTP trace", "severity": "high"},
    {"path": "/swagger-ui.html", "name": "Swagger UI", "severity": "medium"},
    {"path": "/v2/api-docs", "name": "Swagger v2 docs", "severity": "medium"},
    {"path": "/v3/api-docs", "name": "Swagger v3 docs", "severity": "medium"},
    {"path": "/h2-console/", "name": "H2 Console", "severity": "critical"},
    {"path": "/application.properties", "name": "App properties", "severity": "critical"},
    {"path": "/application.yml", "name": "App YAML", "severity": "critical"},
    {"path": "/.env", "name": "Environment file", "severity": "critical"},
    {"path": "/META-INF/", "name": "META-INF dir", "severity": "medium"},
]


class SpringBootAgent(BaseAgent):
    def __init__(self, target: str, event_bus=None, memory_manager=None, **kwargs):
        super().__init__("Spring Boot Agent", target, event_bus=event_bus, memory_manager=memory_manager)

    async def execute(self) -> AgentResult:
        logger.info(f"{self.name}: Scanning {self.target} for Spring Boot vulnerabilities")

        base_url = self.target.rstrip("/")
        async with httpx.AsyncClient(timeout=10.0, verify=False, follow_redirects=True) as client:
            for check in SPRING_PATHS:
                if self.should_stop:
                    break
                await self.check_pause()
                try:
                    r = await client.get(f"{base_url}{check['path']}")
                    if r.status_code == 200:
                        self.add_finding(Finding(
                            title=f"Spring Boot: {check['name']}",
                            description=f"Spring Boot actuator/path {check['path']} returned 200",
                            severity=check["severity"], category="stack",
                            evidence=f"GET {check['path']} → 200 ({len(r.content)} bytes)",
                            confidence=0.8,
                            remediation="Disable actuator endpoints or restrict access to admin only",
                        ))
                except Exception:
                    pass

            await self._run_nuclei_tags(tags=["spring", "springboot", "actuator"], severity="high")

        return AgentResult(agent_name=self.name, status=AgentStatus.COMPLETED, findings=self.findings, execution_time=0)
