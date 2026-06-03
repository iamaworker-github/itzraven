"""
ASP.NET Framework Security Agent
"""

import httpx
from itzraven.agents.base_agent import BaseAgent, AgentResult, Finding, AgentStatus
from itzraven.core.logger import get_logger

logger = get_logger()

ASPNET_CHECKS = [
    {"path": "/web.config", "name": "Web.config exposed", "severity": "critical"},
    {"path": "/web.config.bak", "name": "Web.config backup", "severity": "critical"},
    {"path": "/bin/", "name": "Bin directory", "severity": "high"},
    {"path": "/App_Code/", "name": "App_Code directory", "severity": "high"},
    {"path": "/App_Data/", "name": "App_Data directory", "severity": "high"},
    {"path": "/App_GlobalResources/", "name": "Global resources", "severity": "medium"},
    {"path": "/Trace.axd", "name": "Trace handler", "severity": "critical"},
    {"path": "/elmah.axd", "name": "ELMAH error log", "severity": "critical"},
    {"path": "/error/", "name": "Error page", "severity": "low"},
    {"path": "/Global.asax", "name": "Global ASAX", "severity": "medium"},
    {"path": "/packages.config", "name": "NuGet packages config", "severity": "medium"},
    {"path": "/.vs/", "name": "VS config dir", "severity": "medium"},
    {"path": "/obj/", "name": "Build objects", "severity": "medium"},
    {"path": "/Properties/", "name": "Properties dir", "severity": "medium"},
    {"path": "/swagger/", "name": "Swagger docs", "severity": "medium"},
    {"path": "/api/", "name": "API dir", "severity": "low"},
]


class ASPNetAgent(BaseAgent):
    def __init__(self, target: str, event_bus=None, memory_manager=None, **kwargs):
        super().__init__("ASP.NET Stack Agent", target, event_bus=event_bus, memory_manager=memory_manager)

    async def execute(self) -> AgentResult:
        logger.info(f"{self.name}: Scanning {self.target} for ASP.NET-specific vulnerabilities")

        base_url = self.target.rstrip("/")
        async with httpx.AsyncClient(timeout=10.0, verify=False, follow_redirects=True) as client:
            for check in ASPNET_CHECKS:
                if self.should_stop:
                    break
                await self.check_pause()
                try:
                    r = await client.get(f"{base_url}{check['path']}")
                    if r.status_code in (200, 403):
                        self.add_finding(Finding(
                            title=f"ASP.NET: {check['name']}",
                            description=f"ASP.NET path {check['path']} returned {r.status_code}",
                            severity=check["severity"], category="stack",
                            evidence=f"GET {check['path']} → {r.status_code}",
                            confidence=0.7,
                            remediation="Disable tracing, protect web.config, remove debug endpoints",
                        ))
                except Exception:
                    pass

            await self._run_nuclei_tags(tags=["aspnet", "dotnet", "iis"], severity="high")

        return AgentResult(agent_name=self.name, status=AgentStatus.COMPLETED, findings=self.findings, execution_time=0)
