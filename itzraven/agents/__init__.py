"""
AI-powered security testing agents

Uses lazy loading to avoid circular imports and heavy dependencies
like Playwright being loaded at import time.
"""

_loaded = False
_classes = {}

def _ensure_loaded():
    global _loaded, _classes
    if not _loaded:
        from itzraven.agents.base_agent import BaseAgent, Finding, AgentResult, AgentStatus
        from itzraven.agents.orchestrator import AgentOrchestrator, ScanResult
        from itzraven.agents.sql_injection_agent import SQLInjectionAgent
        from itzraven.agents.xss_agent import XSSAgent
        from itzraven.agents.ssrf_agent import SSRFAgent
        from itzraven.agents.recon_agent import ReconAgent
        from itzraven.agents.command_injection_agent import CommandInjectionAgent
        from itzraven.agents.authentication_agent import AuthenticationAgent
        from itzraven.agents.idor_agent import IDORAgent
        from itzraven.agents.xxe_agent import XXEAgent
        from itzraven.agents.ssti_agent import SSTIAgent
        from itzraven.agents.open_redirect_agent import OpenRedirectAgent
        from itzraven.agents.cors_agent import CORSAgent
        from itzraven.agents.clickjacking_agent import ClickjackingAgent
        from itzraven.agents.nosql_injection_agent import NoSQLInjectionAgent
        from itzraven.agents.host_header_injection_agent import HostHeaderInjectionAgent
        from itzraven.agents.jwt_attack_agent import JWTTAttackAgent
        from itzraven.agents.rate_limit_agent import RateLimitAgent
        from itzraven.agents.autonomous_agent import AutonomousSecurityAgent
        from itzraven.agents.strix_pentest_agent import StrixPentestAgent
        from itzraven.agents.poc_validator_agent import PoCValidatorAgent
        from itzraven.agents.racing_ctf_agent import RacingCTFAgent
        from itzraven.agents.exploit_chain_agent import ExploitChainAgent
        _classes.update({
            "BaseAgent": BaseAgent, "Finding": Finding, "AgentResult": AgentResult, "AgentStatus": AgentStatus,
            "AgentOrchestrator": AgentOrchestrator, "ScanResult": ScanResult,
            "SQLInjectionAgent": SQLInjectionAgent, "XSSAgent": XSSAgent, "SSRFAgent": SSRFAgent,
            "ReconAgent": ReconAgent, "CommandInjectionAgent": CommandInjectionAgent,
            "AuthenticationAgent": AuthenticationAgent, "IDORAgent": IDORAgent,
            "XXEAgent": XXEAgent, "SSTIAgent": SSTIAgent,
            "OpenRedirectAgent": OpenRedirectAgent, "CORSAgent": CORSAgent,
            "ClickjackingAgent": ClickjackingAgent, "NoSQLInjectionAgent": NoSQLInjectionAgent,
            "HostHeaderInjectionAgent": HostHeaderInjectionAgent, "JWTTAttackAgent": JWTTAttackAgent,
            "RateLimitAgent": RateLimitAgent,
            "AutonomousSecurityAgent": AutonomousSecurityAgent,
            "StrixPentestAgent": StrixPentestAgent, "PoCValidatorAgent": PoCValidatorAgent,
            "RacingCTFAgent": RacingCTFAgent,
            "ExploitChainAgent": ExploitChainAgent,
        })
        _loaded = True

def get_default_agents():
    _ensure_loaded()
    return [
        _classes["ReconAgent"](),
        _classes["AuthenticationAgent"](),
        _classes["CommandInjectionAgent"](),
        _classes["SQLInjectionAgent"](),
        _classes["XSSAgent"](),
        _classes["SSRFAgent"](),
        _classes["IDORAgent"](),
    ]

def __getattr__(name):
    _ensure_loaded()
    if name in _classes:
        return _classes[name]
    raise AttributeError(f"module 'itzraven.agents' has no attribute '{name}'")

__all__ = [
    "BaseAgent", "Finding", "AgentResult", "AgentStatus",
    "AgentOrchestrator", "ScanResult",
    "SQLInjectionAgent", "XSSAgent", "SSRFAgent", "ReconAgent",
    "CommandInjectionAgent", "AuthenticationAgent", "IDORAgent",
    "XXEAgent", "SSTIAgent", "OpenRedirectAgent", "CORSAgent",
    "ClickjackingAgent", "NoSQLInjectionAgent", "HostHeaderInjectionAgent",
    "JWTTAttackAgent", "RateLimitAgent",
    "AutonomousSecurityAgent", "StrixPentestAgent", "PoCValidatorAgent",
    "RacingCTFAgent",
    "ExploitChainAgent",
    "get_default_agents",
]
