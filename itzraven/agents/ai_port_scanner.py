"""
AIPortScannerAgent — Runs Nmap with AI-selected flags based on WAF/firewall detection.
Performs full port scan with service detection.
"""
import asyncio
import json
import subprocess
import re
from typing import Optional, List, Dict, Any
from itzraven.agents.base_agent import BaseAgent, AgentResult, Finding, AgentStatus
from itzraven.core.logger import get_logger

logger = get_logger()


class AIPortScannerAgent(BaseAgent):
    """AI-powered port scanner using Nmap with intelligent flag selection."""

    def __init__(self, target: str, event_bus=None, memory_manager=None,
                 nmap_flags: str = "-sS -sV -sC -p- -T4 --max-retries 2",
                 waf_detected: Optional[List[str]] = None):
        super().__init__("AI Port Scanner", target, event_bus=event_bus, memory_manager=memory_manager)
        self.nmap_flags = nmap_flags
        self.waf_detected = waf_detected or []
        self.open_ports: List[Dict[str, Any]] = []

    async def execute(self) -> AgentResult:
        logger.info(f"{self.name}: Scanning {self.target} with flags: {self.nmap_flags}")

        waf_context = f" (behind {', '.join(self.waf_detected)})" if self.waf_detected else ""
        self.add_finding(Finding(
            title=f"Nmap scan initiated on {self.target}{waf_context}",
            description=f"Flags: {self.nmap_flags}",
            severity="info", category="port_scan",
            evidence=f"Scan target: {self.target}",
            confidence=1.0,
        ))

        await self._run_nmap_scan()

        severity = "medium" if len(self.open_ports) > 5 else "low"
        if self.open_ports:
            ports_str = ", ".join(f"{p['port']}/{p['service']}" for p in self.open_ports[:10])
            self.add_finding(Finding(
                title=f"Open ports ({len(self.open_ports)}): {ports_str}",
                description=f"Found {len(self.open_ports)} open ports on {self.target}",
                severity=severity, category="reconnaissance",
                evidence=json.dumps(self.open_ports[:20]),
                remediation="Close unused ports, restrict access via firewall",
                confidence=0.95,
            ))

        for p in self.open_ports:
            if p.get("product"):
                self.add_finding(Finding(
                    title=f"Service: {p['port']}/{p['service']} — {p['product']} {p.get('version', '')}",
                    description=f"Port {p['port']}: {p['product']} {p.get('version', '')}",
                    severity="low" if p['port'] in [80, 443, 22] else "medium",
                    category="service_enum",
                    evidence=f"{p['product']} {p.get('version', '')}",
                    remediation=f"Keep {p['service']} updated and properly configured",
                    confidence=0.85,
                ))

        return AgentResult(
            agent_name=self.name,
            status=AgentStatus.COMPLETED,
            findings=self.findings,
            execution_time=0,
            metadata={
                "open_ports": self.open_ports,
                "total_open": len(self.open_ports),
                "nmap_flags_used": self.nmap_flags,
                "nmap_command": f"nmap {self.nmap_flags} {self.target}",
            },
        )

    async def _run_nmap_scan(self) -> None:
        try:
            cmd = f"nmap {self.nmap_flags} -oX - {self.target}".split()
            logger.info(f"{self.name}: Running: {' '.join(cmd)}")

            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=600)

            if stdout:
                self._parse_nmap_xml(stdout.decode("utf-8", errors="replace"))
            if not self.open_ports:
                for line in stderr.decode("utf-8", errors="replace").split("\n"):
                    if "open" in line.lower() and "/tcp" in line.lower():
                        match = re.match(r"\s*(\d+)/tcp\s+open\s+(\S+)", line)
                        if match:
                            self.open_ports.append({
                                "port": int(match.group(1)),
                                "protocol": "tcp",
                                "state": "open",
                                "service": match.group(2),
                            })

        except asyncio.TimeoutError:
            logger.error(f"{self.name}: Nmap timed out — no fallback scan")
        except Exception as e:
            logger.error(f"{self.name}: Nmap failed ({e}) — no fallback scan")

    def _parse_nmap_xml(self, xml_content: str) -> None:
        import xml.etree.ElementTree as ET
        try:
            root = ET.fromstring(xml_content)
            for host in root.findall(".//host"):
                for port_elem in host.findall(".//port"):
                    port_num = port_elem.get("portid")
                    protocol = port_elem.get("protocol", "tcp")
                    state_elem = port_elem.find("state")
                    if state_elem is not None and state_elem.get("state") == "open":
                        service_elem = port_elem.find("service")
                        entry = {
                            "port": int(port_num) if port_num else 0,
                            "protocol": protocol,
                            "state": "open",
                            "service": service_elem.get("name", "unknown") if service_elem is not None else "unknown",
                            "product": service_elem.get("product", "") if service_elem is not None else "",
                            "version": service_elem.get("version", "") if service_elem is not None else "",
                            "extrainfo": service_elem.get("extrainfo", "") if service_elem is not None else "",
                        }
                        self.open_ports.append(entry)
        except Exception as e:
            logger.debug(f"XML parse failed: {e}")
