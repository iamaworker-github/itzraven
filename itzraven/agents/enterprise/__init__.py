"""
Enterprise Platform Attack Agents — CBH-style coverage for enterprise perimeter.

Agents:
  - M365EntraAgent: M365/Entra ID enumeration and attack
  - OktaAgent: Okta IdP attack vectors
  - VSphereAgent: VMware vCenter/ESXi exploitation
  - VPNAgent: Enterprise VPN appliance testing
  - SharePointAgent: SharePoint on-prem testing
  - EDRBypassAgent: EDR evasion techniques (offensive-claude inspired)
  - ShellcodeAgent: Shellcode development and analysis
  - REAgent: Reverse engineering for binary/firmware analysis
"""

from itzraven.agents.enterprise.m365_entra_agent import M365EntraAgent
from itzraven.agents.enterprise.okta_agent import OktaAgent
from itzraven.agents.enterprise.vsphere_agent import VSphereAgent
from itzraven.agents.enterprise.vpn_agent import VPNAgent
from itzraven.agents.enterprise.sharepoint_agent import SharePointAgent
from itzraven.agents.enterprise.edr_bypass_agent import EDRBypassAgent
from itzraven.agents.enterprise.shellcode_agent import ShellcodeAgent
from itzraven.agents.enterprise.re_agent import REAgent

ENTERPRISE_AGENTS = {
    "m365": M365EntraAgent,
    "okta": OktaAgent,
    "vsphere": VSphereAgent,
    "vpn": VPNAgent,
    "sharepoint": SharePointAgent,
    "edr": EDRBypassAgent,
    "shellcode": ShellcodeAgent,
    "re": REAgent,
}

__all__ = [
    "M365EntraAgent", "OktaAgent", "VSphereAgent",
    "VPNAgent", "SharePointAgent", "EDRBypassAgent",
    "ShellcodeAgent", "REAgent", "ENTERPRISE_AGENTS",
]
