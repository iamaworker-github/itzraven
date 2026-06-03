from typing import Dict, List, Optional, Any
from itzraven.agents.category.base import CategoryAgent
from itzraven.agents.base_agent import Finding
from itzraven.core.logger import get_logger

logger = get_logger()


class NetworkSecurityAgent(CategoryAgent):
    category_name = "network"
    relevant_tags = ["network", "osint"]

    async def _run_static_tests(self) -> None:
        import socket
        target = self.target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]

        common_ports = [22, 80, 443, 3306, 5432, 6379, 8080, 8443, 27017]
        open_ports = []

        for port in common_ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)
                result = s.connect_ex((target, port))
                s.close()
                if result == 0:
                    open_ports.append(port)
            except Exception:
                pass

        if open_ports:
            service_map = {22: "SSH", 80: "HTTP", 443: "HTTPS", 3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB"}
            for port in open_ports:
                service = service_map.get(port, "unknown")
                self.add_finding(Finding(
                    title=f"Open Port: {port}/{service}",
                    severity="info", category="recon",
                    description=f"Port {port} ({service}) is open on {target}",
                    evidence=f"TCP connect to {target}:{port} succeeded",
                    remediation="Close unnecessary ports or restrict access",
                    confidence=0.95,
                ))
