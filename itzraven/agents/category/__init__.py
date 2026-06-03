from itzraven.agents.category.base import CategoryAgent
from itzraven.agents.category.web_agent import WebSecurityAgent
from itzraven.agents.category.network_agent import NetworkSecurityAgent
from itzraven.agents.category.cloud_agent import CloudSecurityAgent
from itzraven.agents.category.api_agent import APISecurityAgent
from itzraven.agents.category.identity_agent import IdentityAccessAgent
from itzraven.agents.category.code_agent import CodeAnalysisAgent
from itzraven.agents.category.recon_agent import ReconOSINTAgent

CATEGORY_MAP = {
    "web": WebSecurityAgent,
    "network": NetworkSecurityAgent,
    "cloud": CloudSecurityAgent,
    "api": APISecurityAgent,
    "identity": IdentityAccessAgent,
    "code": CodeAnalysisAgent,
    "recon": ReconOSINTAgent,
}
