"""
VMware vCenter/ESXi exploitation agent.

CBH-style coverage: CVE-2021-21972, CVE-2024-37085, and other
vCenter/Workspace ONE/Aria attack chains.
"""

from typing import Optional, List, Dict, Any
import httpx
import re

from itzraven.agents.base_agent import BaseAgent, AgentResult, Finding, AgentStatus
from itzraven.core.logger import get_logger

logger = get_logger()


VSPHERE_PATHS = [
    "/ui",
    "/vsphere-client",
    "/webconsole",
    "/vami",
    "/appliance",
    "/sdk",
    "/mob",
    "/websso",
    "/vcac",
    "/catalina-ce",
    "/broker",
    "/lookupservice",
    "/sso-admins",
    "/vum",
    "/enrollment",
]

VSPHERE_CVE_CHECKS = {
    "CVE-2021-21972": {
        "path": "/ui/vropspluginui/rest/services/uploadova",
        "method": "POST",
        "description": "vCenter Server RCE in vRealize Operations plugin",
    },
    "CVE-2021-22005": {
        "path": "/analytics/telemetry/ph/api/hyper/send",
        "method": "POST",
        "description": "vCenter Server arbitrary file upload",
    },
    "CVE-2024-37085": {
        "path": "/sdk/vim25/ServiceInstance",
        "method": "POST",
        "description": "ESXi Authentication Bypass via AD group",
    },
}


class VSphereAgent(BaseAgent):
    """Agent for VMware vCenter/ESXi vulnerability assessment."""

    def __init__(self, target: str, event_bus=None, memory_manager=None):
        super().__init__("VMware vSphere Agent", target, event_bus=event_bus, memory_manager=memory_manager)

    async def execute(self) -> AgentResult:
        logger.info(f"{self.name}: Testing VMware vCenter on {self.target}")
        await self._detect_vcenter()
        await self._check_cve_chains()
        await self._scan_service_endpoints()
        return AgentResult(
            agent_name=self.name,
            status=self.status,
            findings=self.findings,
            execution_time=0,
        )

    async def _detect_vcenter(self):
        """Detect VMware vCenter/ESXi."""
        async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
            for path in ["/ui", "/", "/vsphere-client"]:
                try:
                    url = f"https://{self.target}{path}"
                    resp = await client.get(url, headers={"User-Agent": "Mozilla/5.0"})
                    text = resp.text.lower()
                    if any(kw in text for kw in ["vmware", "vsphere", "vcenter", "esxi"]):
                        version = self._extract_version(text)
                        self.add_finding(Finding(
                            title="VMware vCenter/ESXi Detected",
                            description=f"VMware product detected at {url}" + (f" (version: {version})" if version else ""),
                            severity="medium",
                            category="enterprise_recon",
                            evidence=f"Path: {path}, Status: {resp.status_code}",
                            confidence=0.9,
                        ))
                        return
                except Exception as e:
                    logger.debug(f"vCenter detect error: {e}")

    async def _check_cve_chains(self):
        """Check for known vCenter CVEs."""
        async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
            for cve_id, check in VSPHERE_CVE_CHECKS.items():
                try:
                    url = f"https://{self.target}{check['path']}"
                    resp = await client.request(
                        check["method"], url,
                        headers={"User-Agent": "Mozilla/5.0"},
                    )
                    if resp.status_code not in (404, 405, 403):
                        self.add_finding(Finding(
                            title=f"Potential {cve_id} Vulnerability",
                            description=check["description"],
                            severity="critical",
                            category="enterprise_exploitation",
                            evidence=f"Endpoint returned {resp.status_code}: {url}",
                            proof_of_concept=(
                                f"Access {url} and check for version-specific exploitation.\n"
                                f"curl -k -v '{url}'"
                            ),
                            remediation="Apply VMware security patches immediately",
                            confidence=0.6,
                        ))
                except Exception as e:
                    logger.debug(f"CVE check {cve_id} error: {e}")

    async def _scan_service_endpoints(self):
        """Scan for exposed vCenter service endpoints."""
        async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
            for path in VSPHERE_PATHS:
                try:
                    url = f"https://{self.target}{path}"
                    resp = await client.get(url, headers={"User-Agent": "Mozilla/5.0"})
                    if resp.status_code == 200:
                        self.add_finding(Finding(
                            title="VMware vCenter Endpoint Exposed",
                            description=f"Accessible endpoint: {url}",
                            severity="low",
                            category="enterprise_recon",
                            evidence=f"Status: {resp.status_code}, Size: {len(resp.text)} bytes",
                            remediation="Restrict vCenter management interfaces to trusted networks",
                            confidence=0.7,
                        ))
                except Exception:
                    pass

    def _extract_version(self, text: str) -> str:
        patterns = [
            r"vCenter Server[^\d]*([\d.]+)",
            r"ESXi[^\d]*([\d.]+)",
            r"version[^\d]*([\d.]+)",
            r"([\d]+\.[\d]+\.[\d]+)",
        ]
        for pat in patterns:
            match = re.search(pat, text, re.IGNORECASE)
            if match:
                return match.group(1)
        return ""
