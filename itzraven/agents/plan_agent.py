"""
PlanAgent — Analyzes target, selects relevant category agents via LLM.
Only 1 LLM call. Returns optimized agent execution plan.
"""
import json
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field

from itzraven.agents.base_agent import BaseAgent, AgentResult, Finding, AgentStatus
from itzraven.agents.llm_client import LLMClient
from itzraven.skills.registry import SkillRegistry, get_skill_registry
from itzraven.core.logger import get_logger
from itzraven.core.json_utils import extract_json_safe

logger = get_logger()

CATEGORY_AGENTS = {
    "web": {
        "name": "Web Security Agent",
        "tags": ["sqli", "xss", "ssrf", "command-injection", "idor", "auth", "xxe", "csrf", "path-traversal"],
    },
    "network": {
        "name": "Network Security Agent",
        "tags": ["network", "osint", "wireless"],
    },
    "cloud": {
        "name": "Cloud Security Agent",
        "tags": ["cloud", "container", "iam"],
    },
    "api": {
        "name": "API Security Agent",
        "tags": ["api", "graphql", "jwt"],
    },
    "identity": {
        "name": "Identity & Access Agent",
        "tags": ["auth", "zero-trust", "secret-scan"],
    },
    "code": {
        "name": "Code Analysis Agent",
        "tags": ["code-review", "dep-check", "secret-scan", "sast"],
    },
    "recon": {
        "name": "Recon & OSINT Agent",
        "tags": ["osint", "network"],
    },
}

SCAN_MODE_CATEGORIES: Dict[str, List[str]] = {
    "pentest": ["web", "network", "api", "identity", "recon"],
    "whitebox": ["code", "cloud", "identity"],
    "blackbox": ["web", "network", "api", "recon"],
    "quick": ["web", "recon"],
    "deep": ["web", "network", "cloud", "api", "identity", "code", "recon"],
}


@dataclass
class AgentPlan:
    categories: List[str]
    reason: str = ""
    scan_depth: str = "deep"


class PlanAgent(BaseAgent):
    def __init__(self, target: str, event_bus=None, memory_manager=None, scope=None):
        super().__init__("Plan Agent", target, event_bus=event_bus, memory_manager=memory_manager, scope=scope)
        self.llm_client = LLMClient()
        self.registry = get_skill_registry()

    async def _emit_thought(self, thought: str, thought_type: str = "reasoning", phase: str = "") -> None:
        if self.event_bus:
            try:
                from itzraven.core.events import AgentThinkingEvent
                await self.event_bus.publish_event(AgentThinkingEvent(
                    agent_name=self.name,
                    thought=thought,
                    thought_type=thought_type,
                    phase=phase or "",
                ))
            except Exception:
                pass

    async def execute(self) -> AgentResult:
        logger.info(f"{self.name}: Analyzing target {self.target} for optimal agent selection...")
        await self._emit_thought(f"Analyzing target {self.target} for optimal agent selection...", "analyzing", "planning")

        config = getattr(self.llm_client, 'config', None)
        has_ai = config and getattr(config, 'has_ai_enabled', False)

        if not has_ai:
            plan = self._fallback_plan()
        else:
            plan = await self._ai_plan()

        self.add_finding(Finding(
            title="Agent Selection Plan",
            severity="info",
            category="planning",
            description=f"Selected categories: {plan.categories} | Depth: {plan.scan_depth}",
            evidence=f"Reason: {plan.reason}",
            confidence=1.0,
        ))

        return AgentResult(
            agent_name=self.name,
            status=AgentStatus.COMPLETED,
            findings=self.findings,
            execution_time=0,
            metadata={"plan": {"categories": plan.categories, "reason": plan.reason, "scan_depth": plan.scan_depth}},
        )

    def _fallback_plan(self) -> AgentPlan:
        from urllib.parse import urlparse
        target = self.target.lower().strip()

        if target.startswith(("http://", "https://")):
            categories = ["web", "api", "recon"]
        elif "." in target and " " not in target:
            categories = ["recon", "network", "web"]
        elif target.startswith(("/", ".", "~")) or "\\" in target:
            categories = ["code", "identity"]
        else:
            categories = ["web", "network", "recon"]

        return AgentPlan(categories=categories, reason="fallback heuristic (no LLM)", scan_depth="standard")

    async def _ai_plan(self) -> AgentPlan:
        available = list(CATEGORY_AGENTS.keys())
        await self._emit_thought(f"Calling LLM to analyze target {self.target}...", "reasoning", "planning")
        prompt = f"""Target: {self.target}
Available agents: {json.dumps(available)}
Scope: {self.scope or 'none'}

Analyze the target and return ONLY a JSON object:
{{"categories": ["web", "api"], "reason": "why these categories", "scan_depth": "quick|standard|deep"}}

Rules:
- URL/domain targets → web, api, recon, network
- IP targets → network, recon, web
- Directory/git targets → code, identity, cloud
- Choose 2-4 categories minimum
- quick=3 skills per category, standard=5, deep=8"""

        try:
            response = await self.llm_client.generate(prompt=prompt, max_tokens=300, temperature=0.3)
            await self._emit_thought(f"LLM response received: {response.content[:200]}", "reasoning", "planning")
            parsed = extract_json_safe(response.content.strip(), {})
            cats = parsed.get("categories", ["web", "recon"])
            cats = [c for c in cats if c in CATEGORY_AGENTS]
            if not cats:
                cats = ["web", "recon"]
            return AgentPlan(
                categories=cats[:5],
                reason=parsed.get("reason", "AI-selected"),
                scan_depth=parsed.get("scan_depth", "standard") if parsed.get("scan_depth") in ("quick", "standard", "deep") else "standard",
            )
        except Exception as e:
            logger.warning(f"{self.name}: AI planning failed ({e}), using heuristic")
            return self._fallback_plan()
