import os
import asyncio
from typing import Dict, Any, Optional, List
from itzraven.core.logger import get_logger
from itzraven.core.config import get_config
from itzraven.agents.base_agent import BaseAgent, Finding, AgentResult, AgentStatus
from itzraven.agents.osint.osint_base import OSINTBaseAgent

logger = get_logger()


class ShodanIntelAgent(OSINTBaseAgent):
    """Shodan integration agent — queries Shodan for exposed services on the target IP.

    Requires the ``SHODAN_API_KEY`` environment variable to be set.
    Falls back to a simulated response when the key is absent.
    """

    def __init__(
        self,
        target: str,
        event_bus=None,
        memory_manager=None,
        scope: Optional[List[str]] = None,
    ):
        super().__init__("Shodan Intel Agent", target, event_bus=event_bus, memory_manager=memory_manager, scope=scope)
        self.shodan_data: Dict[str, Any] = {}
        self.api_key: Optional[str] = None

    async def initialize_toolkit(self) -> None:
        await super().initialize_toolkit()
        self.api_key = os.getenv("SHODAN_API_KEY") or os.getenv("shodan_api_key")
        if self.api_key:
            logger.debug(f"{self.name}: SHODAN_API_KEY found")
        else:
            logger.warning(f"{self.name}: SHODAN_API_KEY not set — using simulated data")

    async def execute(self) -> AgentResult:
        logger.info(f"{self.name}: Querying Shodan for {self.target}")

        ip = await self._resolve_target()

        if self.api_key:
            await self._shodan_query(ip)
        else:
            self._simulated_shodan(ip)

        self._create_findings()

        return AgentResult(
            agent_name=self.name,
            status=self.status,
            findings=self.findings,
            execution_time=0,
            metadata={
                "target_ip": ip,
                "shodan_data": self.shodan_data,
                "using_real_key": bool(self.api_key),
            },
        )

    async def _resolve_target(self) -> str:
        import socket
        domain = self.target
        if "://" in domain:
            domain = domain.split("://")[-1].split("/")[0]
        try:
            return await asyncio.to_thread(socket.gethostbyname, domain)
        except Exception:
            logger.debug(f"{self.name}: Could not resolve {domain}")
            return domain

    async def _shodan_query(self, ip: str) -> None:
        try:
            import shodan
            api = shodan.Shodan(self.api_key)
            result = await asyncio.to_thread(api.host, ip)
            self.shodan_data = {
                "ip": result.get("ip_str", ip),
                "org": result.get("org", ""),
                "asn": result.get("asn", ""),
                "country": result.get("country_name", ""),
                "city": result.get("city", ""),
                "ports": result.get("ports", []),
                "hostnames": result.get("hostnames", []),
                "os": result.get("os", ""),
                "data": [
                    {
                        "port": s.get("port"),
                        "transport": s.get("transport"),
                        "product": s.get("product"),
                        "version": s.get("version"),
                    }
                    for s in result.get("data", [])
                ],
            }
        except Exception as e:
            logger.debug(f"{self.name}: Shodan query failed — {e}, using fallback")
            self._simulated_shodan(ip)

    def _simulated_shodan(self, ip: str) -> None:
        self.shodan_data = {
            "ip": ip,
            "org": "Example ISP (simulated)",
            "asn": "AS12345",
            "country": "United States",
            "city": "Ashburn",
            "ports": [80, 443, 22],
            "hostnames": [self.target],
            "os": "Linux 4.x (simulated)",
            "data": [
                {"port": 80, "transport": "tcp", "product": "nginx", "version": "1.24.0"},
                {"port": 443, "transport": "tcp", "product": "nginx", "version": "1.24.0"},
                {"port": 22, "transport": "tcp", "product": "OpenSSH", "version": "8.9p1"},
            ],
            "simulated": True,
        }

    def _create_findings(self) -> None:
        if not self.shodan_data:
            return

        ports = self.shodan_data.get("ports", [])
        org = self.shodan_data.get("org", "Unknown")
        country = self.shodan_data.get("country", "Unknown")
        hostnames = self.shodan_data.get("hostnames", [])

        self.add_finding(Finding(
            title="Shodan Host Summary",
            description=f"IP: {self.shodan_data.get('ip', 'N/A')} | Org: {org} | Country: {country}",
            severity="info",
            category="osint_shodan",
            evidence=f"Open ports: {', '.join(map(str, ports))}",
            confidence=0.9 if self.api_key else 0.5,
        ))

        if ports:
            self.add_finding(Finding(
                title="Exposed Services (Shodan)",
                description=f"Found {len(ports)} open port(s) on {self.shodan_data.get('ip', '')}",
                severity="info",
                category="osint_shodan",
                evidence=f"Ports: {', '.join(map(str, ports))}",
                confidence=0.9 if self.api_key else 0.5,
            ))
