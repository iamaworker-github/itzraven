"""
CategoryAgent — Base class for specialized category agents.
Each agent loads 5-8 relevant skills from SkillRegistry and runs targeted tests.
"""
import asyncio
import json
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse

import httpx

from itzraven.agents.base_agent import BaseAgent, AgentResult, Finding, AgentStatus
from itzraven.agents.llm_client import LLMClient
from itzraven.skills.registry import Skill, SkillRegistry, get_skill_registry
from itzraven.skills.engine import get_skills_engine
from itzraven.core.logger import get_logger

logger = get_logger()


class CategoryAgent(BaseAgent):
    category_name = "base"
    relevant_tags: List[str] = []

    def __init__(self, target: str, event_bus=None, memory_manager=None, scope=None, scan_depth: str = "deep"):
        name = f"{self.category_name.title()} Security Agent"
        super().__init__(name, target, event_bus=event_bus, memory_manager=memory_manager, scope=scope)
        self.scan_depth = scan_depth
        self.registry = get_skill_registry()
        self.loaded_skills: List[Skill] = []
        self.llm_client = LLMClient()

    def load_skills(self) -> int:
        self.registry.build_index()
        depth_limits = {"quick": 3, "standard": 5, "deep": 8}
        limit = depth_limits.get(self.scan_depth, 5)

        # Also load HackerOne report skills
        h1_tags = self.relevant_tags + ["hackerone"]
        seen: set = set()
        for tag in h1_tags:
            skills = self.registry.get_by_tag(tag, limit)
            for s in skills:
                if s.name not in seen:
                    self.loaded_skills.append(s)
                    seen.add(s.name)

        self.loaded_skills = self.loaded_skills[:limit + 3]  # extra slots for H1 priority
        h1_count = sum(1 for s in self.loaded_skills if s.name.startswith("h1-"))
        logger.info(f"{self.name}: Loaded {len(self.loaded_skills)} skills (h1={h1_count}, depth={self.scan_depth})")
        return len(self.loaded_skills)

    def inject_skills_context(self) -> str:
        if not self.loaded_skills:
            return ""
        parts = [f"\n## Specialized Skills — {self.category_name}\n"]
        for skill in self.loaded_skills:
            parts.append(f"\n### {skill.name}\n{skill.description}\n")
            parts.append(skill.content[:500])
        return "\n".join(parts)

    async def execute(self) -> AgentResult:
        self.load_skills()
        skills_context = self.inject_skills_context()

        findings_before = len(self.findings)

        config = getattr(self.llm_client, 'config', None)
        has_ai = config and getattr(config, 'has_ai_enabled', False)

        if has_ai:
            await self._run_ai_guided(skills_context)
        else:
            await self._run_static_tests()

        return AgentResult(
            agent_name=self.name,
            status=AgentStatus.COMPLETED,
            findings=self.findings[findings_before:],
            execution_time=0,
            metadata={
                "category": self.category_name,
                "skills_loaded": len(self.loaded_skills),
                "scan_depth": self.scan_depth,
            },
        )

    async def _run_ai_guided(self, skills_context: str) -> None:
        if not self._is_web_target():
            await self._run_static_tests()
            return

        prompt = f"""Target: {self.target}
Category: {self.category_name}
Available skills: {[s.name for s in self.loaded_skills[:5]]}
{skills_context}

Generate up to 5 security test actions as JSON array:
[{{"method":"GET","path":"/","params":{{}},"hypothesis":"test description"}}]
Focus on {self.category_name} vulnerabilities. Return ONLY valid JSON."""

        try:
            response = await self.llm_client.generate(prompt=prompt, max_tokens=800, temperature=0.3)
            actions = json.loads(response.content.strip())
            if isinstance(actions, list):
                await self._execute_actions(actions[:5])
        except Exception as e:
            logger.debug(f"{self.name}: AI test failed ({e}), running static")
            await self._run_static_tests()

    async def _execute_actions(self, actions: List[Dict]) -> None:
        async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
            for action in actions:
                try:
                    method = action.get("method", "GET").upper()
                    path = action.get("path", "/")
                    url = self.target.rstrip("/") + path
                    params = action.get("params", {})

                    if method == "POST":
                        resp = await client.post(url, params=params, data=action.get("data", {}))
                    else:
                        resp = await client.get(url, params=params)

                    if resp.status_code < 500:
                        logger.info(f"  {method} {url} → {resp.status_code}")
                except Exception:
                    pass

    async def _run_static_tests(self) -> None:
        pass

    def _is_web_target(self) -> bool:
        return self.target.startswith(("http://", "https://"))
