"""
IoT/Embedded Security Testing Agent
IoT protocols: MQTT, CoAP, Modbus, BACnet, RTSP, firmware analysis
"""

import asyncio
from typing import List, Optional
import httpx
from itzraven.agents.base_agent import BaseAgent, AgentResult, Finding, AgentStatus
from itzraven.core.logger import get_logger

logger = get_logger()

IOT_PORTS = {
    "mqtt": [1883, 8883],
    "coap": [5683, 5684],
    "modbus": [502],
    "bacnet": [47808],
    "rtsp": [554, 8554],
    "upnp": [1900, 5000],
    "mdns": [5353],
}

IOT_PATH_CHECKS = [
    "/device", "/status", "/api/device", "/api/status",
    "/mqtt", "/ws", "/api/ws", "/firmware", "/update",
    "/api/update", "/config", "/api/config", "/debug",
    "/api/debug", "/shell", "/api/shell", "/console",
    "/api/console", "/log", "/api/log", "/syslog",
    "/camera", "/stream", "/video", "/audio",
    "/api/camera", "/api/stream", "/api/video",
    "/api/firmware", "/api/upgrade", "/upgrade",
    "/restart", "/reboot", "/api/restart", "/api/reboot",
    "/network", "/api/network", "/wifi", "/api/wifi",
    "/bluetooth", "/api/bluetooth", "/api/settings",
    "/settings", "/api/user", "/api/password",
    "/api/config/export", "/api/config/import",
    "/api/logs", "/api/syslog",
]


class IoTAgent(BaseAgent):
    """IoT/Embedded Device Security Testing Agent"""

    def __init__(self, target: str, event_bus=None, memory_manager=None):
        super().__init__("IoT Security Agent", target, event_bus=event_bus, memory_manager=memory_manager)

    async def execute(self) -> AgentResult:
        logger.info(f"{self.name}: Scanning {self.target} for IoT/embedded vulnerabilities")

        base_url = self.target.rstrip("/")

        async with httpx.AsyncClient(timeout=8.0, verify=False, follow_redirects=False) as client:
            for path in IOT_PATH_CHECKS:
                if self.should_stop:
                    break
                await self.check_pause()
                try:
                    r = await client.get(f"{base_url}{path}")
                    if r.status_code in (200, 403, 401):
                        sev = "critical" if any(x in path for x in ["shell", "console", "config", "firmware", "upgrade"]) else "medium"
                        self.add_finding(Finding(
                            title=f"IoT Endpoint: {path}",
                            description=f"IoT device path {path} returned {r.status_code}",
                            severity=sev, category="iot",
                            evidence=f"GET {path} → {r.status_code} ({len(r.content)} bytes)"
                                      f"\nResponse preview: {r.text[:200]}",
                            confidence=0.6,
                            remediation="Restrict access to device management endpoints, "
                                       "implement proper authentication",
                        ))
                except Exception:
                    pass

            mqtt_target = f"{base_url.replace('http://', '').replace('https://', '').split(':')[0]}"
            if mqtt_target:
                await self._check_mqtt(client, mqtt_target)
                await self._check_modbus(client, mqtt_target)

        await self._run_nuclei_tags(tags=["iot", "firmware", "embedded", "rtsp"], severity="high")

        return AgentResult(agent_name=self.name, status=AgentStatus.COMPLETED, findings=self.findings, execution_time=0)

    async def _check_mqtt(self, client: httpx.AsyncClient, target: str):
        for port in IOT_PORTS["mqtt"]:
            try:
                import socket
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(3)
                result = s.connect_ex((target, port))
                s.close()
                if result == 0:
                    self.add_finding(Finding(
                        title=f"MQTT Broker Detected (port {port})",
                        description=f"MQTT broker accessible on port {port} — "
                                   f"check for anonymous publish/subscribe",
                        severity="high", category="iot",
                        evidence=f"TCP port {port} open on {target}",
                        confidence=0.7,
                        remediation="Enable MQTT authentication and TLS, "
                                   "disable anonymous access",
                    ))
            except Exception:
                pass

    async def _check_modbus(self, client: httpx.AsyncClient, target: str):
        for port in IOT_PORTS["modbus"]:
            try:
                import socket
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(3)
                result = s.connect_ex((target, port))
                s.close()
                if result == 0:
                    self.add_finding(Finding(
                        title=f"Modbus TCP Detected (port {port})",
                        description=f"Modbus TCP accessible on port {port} — "
                                   f"potential for ICS protocol abuse",
                        severity="high", category="iot",
                        evidence=f"TCP port {port} open on {target}",
                        confidence=0.7,
                        remediation="Restrict Modbus TCP access to trusted networks only",
                    ))
            except Exception:
                pass
