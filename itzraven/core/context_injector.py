"""
Context Injector — builds dynamic target context for all agents.

Generates a structured context string from:
- Target information (URL, IP, domain)
- Detected technologies
- Open ports & services
- Prior findings from same session
- Active skills from SkillLibrary matching the target
- Learning data (similar targets' success rates)
"""

import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any

from itzraven.core.logger import get_logger
from itzraven.core.skill_library import get_skill_library

logger = get_logger()


@dataclass
class TargetContext:
    target: str = ""
    target_ip: str = ""
    technologies: List[str] = field(default_factory=list)
    open_ports: List[dict] = field(default_factory=list)
    subdomains: List[str] = field(default_factory=list)
    endpoints: List[str] = field(default_factory=list)
    findings_count: int = 0
    active_skills: List[dict] = field(default_factory=list)
    tech_recommendations: List[str] = field(default_factory=list)
    session_id: str = ""
    scan_depth: str = "quick"

    def build_prompt_block(self) -> str:
        lines = ["<target-context>"]
        lines.append(f"  Target: {self.target}")
        if self.target_ip:
            lines.append(f"  IP: {self.target_ip}")
        if self.technologies:
            lines.append(f"  Technologies: {', '.join(self.technologies)}")
        if self.subdomains:
            lines.append(f"  Subdomains: {', '.join(self.subdomains[:10])}")
        if self.open_ports:
            lines.append(f"  Open Ports: {', '.join(str(p.get('port', '')) for p in self.open_ports[:20])}")
        if self.endpoints:
            lines.append(f"  Endpoints: {', '.join(self.endpoints[:10])}")
        lines.append(f"  Scan Depth: {self.scan_depth}")

        if self.active_skills:
            lines.append("")
            lines.append("  Previously Learned Skills (matching this target):")
            for s in self.active_skills[:8]:
                lines.append(f"    • {s.get('name', '')} [{s.get('confidence', 0):.0%}] — {s.get('technique', '')} on {', '.join(s.get('required_techs', []))}")

        if self.tech_recommendations:
            lines.append("")
            lines.append("  Recommendations:")
            for r in self.tech_recommendations:
                lines.append(f"    → {r}")

        lines.append("</target-context>")
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "target_ip": self.target_ip,
            "technologies": self.technologies,
            "open_ports": self.open_ports,
            "subdomains": self.subdomains,
            "endpoints": self.endpoints,
            "findings_count": self.findings_count,
            "active_skills": self.active_skills,
            "session_id": self.session_id,
            "scan_depth": self.scan_depth,
        }


class ContextInjector:
    _instance = None

    def __init__(self):
        self.contexts: Dict[str, TargetContext] = {}

    @classmethod
    def get_instance(cls) -> "ContextInjector":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def build_context(self, target: str, technologies: List[str],
                      endpoints: List[str] = None, open_ports: List[dict] = None,
                      subdomains: List[str] = None, target_ip: str = "",
                      findings_count: int = 0, session_id: str = "",
                      scan_depth: str = "quick") -> TargetContext:

        ctx = TargetContext(
            target=target,
            target_ip=target_ip,
            technologies=technologies,
            open_ports=open_ports or [],
            subdomains=subdomains or [],
            endpoints=endpoints or [],
            findings_count=findings_count,
            session_id=session_id,
            scan_depth=scan_depth,
        )

        skill_lib = get_skill_library()
        matching_skills = skill_lib.recommend_for_tech(technologies, min_confidence=0.3)
        ctx.active_skills = [s.to_dict() for s in matching_skills]

        if technologies:
            tech_strs = [t.lower() for t in technologies]
            if any(k in tech_strs for k in ["java", "tomcat", "jboss", "websphere"]):
                ctx.tech_recommendations.append("Java stack detected — prioritize SSRF, expression language injection, deserialization attacks")
            if any(k in tech_strs for k in ["php", "wordpress", "drupal", "joomla"]):
                ctx.tech_recommendations.append("PHP/CMS stack — prioritize file upload bypass, template injection, SQLi via input validation")
            if any(k in tech_strs for k in ["nginx", "apache"]):
                ctx.tech_recommendations.append("Web server detected — check for path traversal, misconfigurations, directory listing")
            if any(k in tech_strs for k in ["node", "express", "react"]):
                ctx.tech_recommendations.append("Node.js stack — prioritize prototype pollution, SSRF, NoSQL injection")
            if any("cloudflare" in t.lower() for t in technologies):
                ctx.tech_recommendations.append("Cloudflare detected — use real IP discovery techniques, header-based bypass")

        self.contexts[target] = ctx
        return ctx

    def get_context(self, target: str) -> Optional[TargetContext]:
        return self.contexts.get(target)

    def inject_into_agent(self, agent, target: str):
        ctx = self.get_context(target)
        if ctx and hasattr(agent, 'context'):
            agent.context["target_context"] = ctx.build_prompt_block()
            agent.context["technologies"] = ctx.technologies
            agent.context["active_skills"] = ctx.active_skills


get_context_injector = ContextInjector.get_instance
