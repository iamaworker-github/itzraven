"""
Enterprise VPN appliance attack agent.

CBH-style coverage: Cisco ASA/AnyConnect, Fortinet, Citrix NetScaler,
Palo Alto, Pulse/Ivanti, SonicWall, F5 BIG-IP.
"""

from typing import Optional, List, Dict, Any
import httpx
import re

from itzraven.agents.base_agent import BaseAgent, AgentResult, Finding, AgentStatus
from itzraven.core.logger import get_logger

logger = get_logger()


VPN_FINGERPRINTS = {
    "Cisco ASA/AnyConnect": {
        "paths": ["/+CSCOE+/logon.html", "/+CSCOE+/login.html"],
        "headers": {"User-Agent": "Mozilla/5.0"},
        "detect": ["cisco", "anyconnect", "webvpn", "+CSCOE+"],
    },
    "Fortinet FortiGate": {
        "paths": ["/remote/login", "/login", "/remote/logout"],
        "headers": {"User-Agent": "Mozilla/5.0"},
        "detect": ["fortinet", "fortigate", "fortitoken"],
    },
    "Citrix NetScaler": {
        "paths": ["/vpn/index.html", "/logon/LogonPoint/tmindex.html", "/vtml"],
        "headers": {"User-Agent": "Mozilla/5.0"},
        "detect": ["netscaler", "citrix", "nsc_ccg"],
    },
    "Palo Alto GlobalProtect": {
        "paths": ["/global-protect/login.esp", "/ssl-vpn/login.esp"],
        "headers": {"User-Agent": "Mozilla/5.0"},
        "detect": ["globalprotect", "panos", "paloalto"],
    },
    "Pulse/Ivanti Secure": {
        "paths": ["/dana-na/auth/url_default/login.cgi", "/dana-na/nc/nc_gina.cgi"],
        "headers": {"User-Agent": "Mozilla/5.0"},
        "detect": ["pulse secure", "ivanti", "dana-na"],
    },
    "SonicWall SMA/SRA": {
        "paths": ["/cgi-bin/welcome", "/auth.html", "/sgv.htm"],
        "headers": {"User-Agent": "Mozilla/5.0"},
        "detect": ["sonicwall", "sonicos"],
    },
    "F5 BIG-IP APM": {
        "paths": ["/my.policy", "/myvpn", "/xui/", "/tmui/"],
        "headers": {"User-Agent": "Mozilla/5.0"},
        "detect": ["big-ip", "f5", "tmui"],
    },
}

VPN_CVE_CHECKS = {
    "CVE-2023-20269": {
        "vendor": "Cisco ASA",
        "description": "Cisco ASA Remote Access VPN RCE",
    },
    "CVE-2024-21887": {
        "vendor": "Ivanti Pulse Secure",
        "description": "Ivanti Connect Secure RCE",
    },
    "CVE-2023-27997": {
        "vendor": "Fortinet FortiGate",
        "description": "FortiGate SSL VPN Heap Overflow",
    },
    "CVE-2022-42475": {
        "vendor": "Fortinet FortiGate",
        "description": "FortiGate SSL VPN Heap Overflow",
    },
    "CVE-2023-3519": {
        "vendor": "Citrix NetScaler",
        "description": "Citrix NetScaler RCE",
    },
    "CVE-2023-4966": {
        "vendor": "Citrix NetScaler",
        "description": "Citrix NetScaler Information Disclosure",
    },
    "CVE-2024-24919": {
        "vendor": "SonicWall SMA",
        "description": "SonicWall SMA SSLVPN Path Traversal",
    },
}


class VPNAgent(BaseAgent):
    """Agent for enterprise VPN appliance detection and vulnerability assessment."""

    def __init__(self, target: str, event_bus=None, memory_manager=None):
        super().__init__("VPN Appliance Agent", target, event_bus=event_bus, memory_manager=memory_manager)

    async def execute(self) -> AgentResult:
        logger.info(f"{self.name}: Testing VPN appliances on {self.target}")
        await self._fingerprint_vpn_appliances()
        await self._check_endpoints()
        return AgentResult(
            agent_name=self.name,
            status=self.status,
            findings=self.findings,
            execution_time=0,
        )

    async def _fingerprint_vpn_appliances(self):
        """Try to fingerprint known VPN appliances."""
        async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
            for vendor, config in VPN_FINGERPRINTS.items():
                for path in config["paths"]:
                    try:
                        url = f"https://{self.target}{path}"
                        resp = await client.get(url, headers=config["headers"])
                        text = resp.text.lower()
                        if any(kw in text for kw in config["detect"]):
                            self.add_finding(Finding(
                                title=f"{vendor} VPN Appliance Detected",
                                description=f"VPN appliance identified at {url}",
                                severity="medium",
                                category="enterprise_recon",
                                evidence=f"Status: {resp.status_code}, Path: {path}",
                                remediation="Ensure VPN appliance is patched and configured securely",
                                confidence=0.9,
                            ))
                            break
                    except Exception as e:
                        logger.debug(f"VPN fingerprint {vendor} error: {e}")

    async def _check_endpoints(self):
        """Check for CVE indicators on discovered VPN."""
        async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
            for cve_id, info in VPN_CVE_CHECKS.items():
                try:
                    resp = await client.get(
                        f"https://{self.target}/",
                        headers={"User-Agent": "Mozilla/5.0"},
                    )
                    server = resp.headers.get("Server", "").lower()
                    if any(kw in server for kw in ["fortinet", "cisco", "citrix", "sonicwall", "pulse"]):
                        self.add_finding(Finding(
                            title=f"Potential {cve_id} - {info['vendor']}",
                            description=info["description"],
                            severity="high",
                            category="enterprise_exploitation",
                            evidence=f"Server header: {server}",
                            remediation="Apply vendor security patches",
                            confidence=0.4,
                        ))
                except Exception:
                    pass

        for cve_id, check in VPN_CVE_CHECKS.items():
            if "445" in cve_id or "4966" in cve_id:
                continue
            try:
                async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
                    resp = await client.get(
                        f"https://{self.target}",
                        headers={"User-Agent": "Mozilla/5.0"},
                        follow_redirects=True,
                    )
                    if "IIS" in resp.headers.get("Server", ""):
                        logger.debug(f"Non-VPN server detected: {resp.headers.get('Server')}")
            except Exception:
                pass
