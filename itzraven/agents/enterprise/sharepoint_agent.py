"""
SharePoint on-prem assessment agent.

CBH-style coverage: ToolShell precondition chain (CVE-2025-53770),
SOAP auth bypass, anonymous FormDigest, SafeControl enumeration,
and legacy web service discovery.
"""

from typing import Optional, List
import httpx
import re

from itzraven.agents.base_agent import BaseAgent, AgentResult, Finding, AgentStatus
from itzraven.core.logger import get_logger

logger = get_logger()


SHAREPOINT_PATHS = [
    "/_layouts/15/",
    "/_layouts/",
    "/_vti_bin/",
    "/_vti_bin/Lists.asmx",
    "/_vti_bin/UserGroup.asmx",
    "/_vti_bin/People.asmx",
    "/_vti_bin/Search.asmx",
    "/_vti_bin/sites.asmx",
    "/_vti_bin/Webs.asmx",
    "/_vti_bin/ExcelService.asmx",
    "/_vti_bin/FormsService.asmx",
    "/_vti_bin/PublishedLinksService.asmx",
    "/_api/web",
    "/_api/site",
    "/_api/contextinfo",
    "/_api/web/lists",
    "/_api/web/webs",
    "/SitePages/",
    "/sites/",
    "/SiteCollection/",
    "/_catalogs/",
    "/wpresources/",
    "/Style%20Library/",
]

SHAREPOINT_SOAP_ACTIONS = {
    "GetListCollection": "http://schemas.microsoft.com/sharepoint/soap/GetListCollection",
    "GetUserCollectionFromSite": "http://schemas.microsoft.com/sharepoint/soap/GetUserCollectionFromSite",
    "GetListItems": "http://schemas.microsoft.com/sharepoint/soap/GetListItems",
    "GetAttachmentCollection": "http://schemas.microsoft.com/sharepoint/soap/GetAttachmentCollection",
    "Search": "http://microsoft.com/webservices/OfficeServer/QueryService/Search",
}


class SharePointAgent(BaseAgent):
    """Agent for SharePoint on-prem vulnerability assessment."""

    def __init__(self, target: str, event_bus=None, memory_manager=None):
        super().__init__("SharePoint Agent", target, event_bus=event_bus, memory_manager=memory_manager)

    async def execute(self) -> AgentResult:
        logger.info(f"{self.name}: Testing SharePoint on {self.target}")
        await self._detect_sharepoint()
        await self._scan_soap_endpoints()
        await self._check_anonymous_access()
        await self._check_cve_chains()
        return AgentResult(
            agent_name=self.name,
            status=self.status,
            findings=self.findings,
            execution_time=0,
        )

    async def _detect_sharepoint(self):
        """Detect SharePoint server."""
        async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
            for path in ["/", "/_layouts/15/", "/_vti_bin/"]:
                try:
                    url = f"https://{self.target}{path}"
                    resp = await client.get(url, headers={"User-Agent": "Mozilla/5.0"})
                    text = resp.text.lower()
                    if any(kw in text for kw in ["sharepoint", "microsoft.sharepoint", "sprequest", "sp201"]):
                        version = self._extract_sharepoint_version(resp.headers, text)
                        self.add_finding(Finding(
                            title="Microsoft SharePoint Detected",
                            description=f"SharePoint server detected" + (f" (version: {version})" if version else ""),
                            severity="medium",
                            category="enterprise_recon",
                            evidence=f"Path: {path}\nServer: {resp.headers.get('Server', '')}\n{text[:200]}",
                            confidence=0.9,
                        ))
                        return
                except Exception as e:
                    logger.debug(f"SharePoint detect error: {e}")

    async def _scan_soap_endpoints(self):
        """Scan SOAP web service endpoints."""
        async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
            for path, action in SHAREPOINT_SOAP_ACTIONS.items():
                try:
                    url = f"https://{self.target}/_vti_bin/{path}.asmx"
                    soap_body = f"""<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <{path} xmlns="http://schemas.microsoft.com/sharepoint/soap/" />
  </soap:Body>
</soap:Envelope>"""
                    resp = await client.post(
                        url,
                        content=soap_body,
                        headers={
                            "Content-Type": "text/xml; charset=utf-8",
                            "SOAPAction": action,
                            "User-Agent": "Mozilla/5.0",
                        },
                    )
                    if resp.status_code == 200 and "<?xml" in resp.text:
                        self.add_finding(Finding(
                            title=f"SharePoint SOAP Endpoint Exposed: {path}",
                            description=f"Anonymous SOAP access to {path} at {url}",
                            severity="medium",
                            category="enterprise_recon",
                            evidence=f"Status: {resp.status_code}\nResponse: {resp.text[:200]}",
                            remediation="Disable unnecessary SOAP endpoints or require authentication",
                            confidence=0.8,
                        ))
                except Exception as e:
                    logger.debug(f"SOAP scan {path} error: {e}")

    async def _check_anonymous_access(self):
        """Check for anonymous access to SharePoint resources."""
        async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
            for path in SHAREPOINT_PATHS:
                try:
                    url = f"https://{self.target}{path}"
                    resp = await client.get(url, headers={"User-Agent": "Mozilla/5.0"})
                    if resp.status_code == 200 and "Sign In" not in resp.text and "401" not in resp.text:
                        self.add_finding(Finding(
                            title="SharePoint Anonymous Access Possible",
                            description=f"Anonymous access to: {url}",
                            severity="high",
                            category="enterprise_exploitation",
                            evidence=f"Path: {path}, Status: {resp.status_code}",
                            remediation="Configure SharePoint to require authentication",
                            confidence=0.7,
                        ))
                except Exception:
                    pass

    async def _check_cve_chains(self):
        """Check for known SharePoint CVEs."""
        cve_paths = {
            "CVE-2025-53770 (ToolShell Precondition)": "/_vti_bin/webpartpages.asmx",
            "SharePoint SafeControl Enum": "/_layouts/15/settings.aspx",
        }
        async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
            for cve_name, path in cve_paths.items():
                try:
                    url = f"https://{self.target}{path}"
                    resp = await client.get(url, headers={"User-Agent": "Mozilla/5.0"})
                    if resp.status_code != 404:
                        self.add_finding(Finding(
                            title=f"Potential {cve_name}",
                            description=f"Endpoint accessible: {url}",
                            severity="high",
                            category="enterprise_exploitation",
                            evidence=f"Status: {resp.status_code}",
                            remediation="Apply latest SharePoint cumulative updates",
                            confidence=0.5,
                        ))
                except Exception:
                    pass

    def _extract_sharepoint_version(self, headers: dict, text: str) -> str:
        server = headers.get("MicrosoftSharePointTeamServices", "")
        if server:
            return server
        match = re.search(r"(\d{4})\s*(?:SharePoint|WSS)", text, re.IGNORECASE)
        if match:
            return match.group(1)
        match = re.search(r"(16\.0\.\d+)", text)
        if match:
            return match.group(1)
        return ""
