"""
Dynamic Agent Composer — assembles specialized agents at runtime from reusable
tool modules based on target technology and goals.

Instead of running all agents, compose exact agents needed:
- Java/Tomcat → SSRFAgent + DeserializationAgent + SQLiAgent
- PHP/WordPress → FileUploadAgent + XSSAgent + SQLiAgent
"""

from typing import Dict, List, Optional, Any, Type
from dataclasses import dataclass, field

from itzraven.core.logger import get_logger

logger = get_logger()


@dataclass
class AgentBlueprint:
    name: str
    technique: str
    description: str
    required_techs: List[str]
    agent_class_path: str
    priority: int = 5


AGENT_BLUEPRINTS = [
    AgentBlueprint("SQLi Agent", "sql_injection", "Test SQL injection in parameters",
                   ["mysql", "postgresql", "oracle", "mssql", "sqlite", "php", "java"],
                   "itzraven.agents.sql_injection_agent.SQLInjectionAgent", priority=9),
    AgentBlueprint("XSS Agent", "xss", "Test cross-site scripting",
                   ["php", "java", "python", "node", "asp"],
                   "itzraven.agents.xss_agent.XSSAgent", priority=8),
    AgentBlueprint("SSRF Agent", "ssrf", "Test server-side request forgery",
                   ["java", "tomcat", "node", "python", "php", "go", "ruby"],
                   "itzraven.agents.ssrf_agent.SSRFAgent", priority=9),
    AgentBlueprint("Auth Agent", "authentication", "Test auth bypass",
                   ["jwt", "oauth", "login", "session"],
                   "itzraven.agents.authentication_agent.AuthenticationAgent", priority=7),
    AgentBlueprint("IDOR Agent", "idor", "Test insecure direct object references",
                   ["rest", "api", "graphql", "soap"],
                   "itzraven.agents.idor_agent.IDORAgent", priority=7),
    AgentBlueprint("Command Injection Agent", "command_injection", "Test OS command injection",
                   ["php", "java", "python", "node", "perl", "ruby"],
                   "itzraven.agents.command_injection_agent.CommandInjectionAgent", priority=6),
    AgentBlueprint("XXE Agent", "xxe", "Test XML external entity injection",
                   ["xml", "soap", "dtd", "xerces", "dom4j"],
                   "itzraven.agents.xxe_agent.XXEAgent", priority=5),
    AgentBlueprint("SSTI Agent", "ssti", "Test server-side template injection",
                   ["jinja", "twig", "freemarker", "velocity", "smarty", "handlebars"],
                   "itzraven.agents.ssti_agent.SSTIAgent", priority=5),
    AgentBlueprint("Open Redirect Agent", "open_redirect", "Test open redirects",
                   ["php", "java", "python", "node", "go", "ruby", "asp"],
                   "itzraven.agents.open_redirect_agent.OpenRedirectAgent", priority=4),
    AgentBlueprint("CORS Agent", "cors", "Test CORS misconfigurations",
                   ["rest", "api", "graphql"],
                   "itzraven.agents.cors_agent.CORSAgent", priority=4),
    AgentBlueprint("JWT Attack Agent", "jwt", "Test JWT vulnerabilities",
                   ["jwt", "oauth", "oidc", "keycloak", "auth0"],
                   "itzraven.agents.jwt_attack_agent.JWTTAttackAgent", priority=6),
    AgentBlueprint("NoSQL Injection Agent", "nosql", "Test NoSQL injection",
                   ["mongodb", "couchdb", "firebase", "nosql", "node"],
                   "itzraven.agents.nosql_injection_agent.NoSQLInjectionAgent", priority=6),
    AgentBlueprint("Rate Limit Agent", "rate_limit", "Test rate limiting",
                   ["api", "rest", "graphql", "login"],
                   "itzraven.agents.rate_limit_agent.RateLimitAgent", priority=3),
    AgentBlueprint("Clickjacking Agent", "clickjacking", "Test clickjacking",
                   ["php", "java", "python", "node", "html"],
                   "itzraven.agents.clickjacking_agent.ClickjackingAgent", priority=3),
    AgentBlueprint("Host Header Agent", "host_header", "Test host header injection",
                   ["nginx", "apache", "iis", "caddy"],
                   "itzraven.agents.host_header_injection_agent.HostHeaderInjectionAgent", priority=4),
    AgentBlueprint("Strix Pentest Agent", "strix", "Comprehensive pentest agent",
                   [],
                   "itzraven.agents.strix_pentest_agent.StrixPentestAgent", priority=2),
]


class AgentComposer:
    _instance = None

    def __init__(self):
        self.blueprints = {bp.name: bp for bp in AGENT_BLUEPRINTS}

    @classmethod
    def get_instance(cls) -> "AgentComposer":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def compose(self, technologies: List[str], mode: str = "pentest",
                plan_categories: List[str] = None,
                min_priority: int = 1) -> List[dict]:
        """Compose agent list based on detected technologies and plan categories."""
        from itzraven.core.learning_engine import get_learning_engine
        le = get_learning_engine()

        tech_lower = [t.lower() for t in technologies]
        candidates = []

        for bp in self.blueprints.values():
            if bp.priority < min_priority:
                continue
            if bp.required_techs and not any(r in tech_lower for r in bp.required_techs):
                continue
            if plan_categories:
                cat_map = {
                    "sql_injection": "web", "xss": "web", "ssrf": "web",
                    "authentication": "web", "idor": "web",
                    "command_injection": "web", "xxe": "web", "ssti": "web",
                    "open_redirect": "web", "cors": "web", "jwt": "api",
                    "nosql": "api", "rate_limit": "api", "clickjacking": "web",
                    "host_header": "web", "strix": "web",
                }
                mapped_cat = cat_map.get(bp.technique, "web")
                if mapped_cat not in plan_categories:
                    continue

            candidates.append({
                "name": bp.name,
                "technique": bp.technique,
                "agent_class_path": bp.agent_class_path,
                "priority": bp.priority,
                "skip": False,
            })

        candidates.sort(key=lambda x: -x["priority"])

        for c in candidates:
            try:
                skip = le.should_skip(c["technique"], technologies[0] if technologies else "unknown")
                if skip:
                    c["skip"] = True
                    logger.info(f"⏭ Composer skipped {c['name']} (learning: historically unreliable)")
            except Exception:
                pass

        logger.info(f"🔧 AgentComposer: {len([c for c in candidates if not c['skip']])} agents composed from {len(self.blueprints)} blueprints")
        return candidates

    def instantiate(self, target: str, event_bus=None, memory_manager=None,
                    technologies: List[str] = None,
                    plan_categories: List[str] = None) -> List[object]:
        """Compose and instantiate agents for a target."""
        import importlib

        candidates = self.compose(technologies or [], plan_categories=plan_categories)
        agents = []

        for c in candidates:
            if c["skip"]:
                continue
            try:
                mod_path, cls_name = c["agent_class_path"].rsplit(".", 1)
                mod = importlib.import_module(mod_path)
                cls = getattr(mod, cls_name)
                agent = cls(target, event_bus=event_bus, memory_manager=memory_manager)
                agents.append(agent)
                logger.debug(f"  + Composed: {agent.name}")
            except Exception as e:
                logger.debug(f"  ✗ Failed to compose {c['name']}: {e}")

        return agents


get_agent_composer = AgentComposer.get_instance
