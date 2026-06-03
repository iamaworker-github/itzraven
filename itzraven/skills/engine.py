"""
Skills Engine - loads, caches, and injects skills into agent context.

Mirrors Strix's skills system where specialized knowledge packages
are loaded based on the task context and injected into agent prompts.
"""

import os
import re
import yaml
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field

from itzraven.core.logger import get_logger

logger = get_logger()


@dataclass
class Skill:
    name: str
    description: str
    content: str
    category: str = "general"
    metadata: Dict[str, Any] = field(default_factory=dict)


class SkillsEngine:
    MAX_SKILLS_PER_AGENT = 10

    def __init__(self, skills_dir: Optional[Path] = None):
        self.skills_dir = skills_dir or Path(__file__).parent
        self._skills_cache: Dict[str, Skill] = {}
        self._loaded = False

    def load_all(self) -> None:
        if self._loaded:
            return
        self._skills_cache = {}
        for skill_file in self.skills_dir.glob("*.md"):
            try:
                skill = self._parse_skill_file(skill_file)
                if skill:
                    self._skills_cache[skill.name] = skill
            except Exception as e:
                logger.debug(f"Failed to load skill {skill_file.name}: {e}")
        self._loaded = True
        logger.debug(f"Loaded {len(self._skills_cache)} base skills")

    def load_recursive(self) -> None:
        if self._loaded:
            return
        self._skills_cache = {}
        for skill_file in self.skills_dir.rglob("*.md"):
            try:
                skill = self._parse_skill_file(skill_file)
                if skill:
                    self._skills_cache[skill.name] = skill
            except Exception as e:
                logger.debug(f"Failed to load skill {skill_file.name}: {e}")
        self._loaded = True
        logger.info(f"Loaded {len(self._skills_cache)} skills from {self.skills_dir} (recursive)")

    def load_claudskills(self, categories: Optional[List[str]] = None) -> int:
        claudskills_dir = self.skills_dir / "claudskills"
        if not claudskills_dir.exists():
            return 0
        self.load_all()
        matched = 0
        glob_pattern = "*.md"
        for skill_file in claudskills_dir.rglob(glob_pattern):
            try:
                skill = self._parse_skill_file(skill_file)
                if not skill:
                    continue
                if categories and skill.category not in categories:
                    continue
                if skill.name not in self._skills_cache:
                    self._skills_cache[skill.name] = skill
                    matched += 1
            except Exception as e:
                logger.debug(f"Failed to load claudskills skill {skill_file.name}: {e}")
        if matched:
            hint = f" in categories {categories}" if categories else ""
            logger.info(f"Loaded {matched} claudskills{hint}")
        return matched

    def load_h1_reports(self, categories: Optional[List[str]] = None) -> int:
        h1_dir = self.skills_dir / "h1-reports"
        if not h1_dir.exists():
            return 0
        self.load_all()
        matched = 0
        for skill_file in h1_dir.glob("*.md"):
            try:
                skill = self._parse_skill_file(skill_file)
                if not skill:
                    continue
                if categories and skill.category not in categories:
                    continue
                if skill.name not in self._skills_cache:
                    self._skills_cache[skill.name] = skill
                    matched += 1
            except Exception as e:
                logger.debug(f"Failed to load h1 skill {skill_file.name}: {e}")
        if matched:
            hint = f" in categories {categories}" if categories else ""
            logger.info(f"Loaded {matched} HackerOne report skills{hint}")
        return matched

    def _parse_skill_file(self, path: Path) -> Optional[Skill]:
        content = path.read_text(encoding="utf-8")
        name = None
        description = None
        category = "general"
        metadata = {}

        frontmatter_match = re.match(r"^---\s*\n(.*?)\n---\s*\n", content, re.DOTALL)
        if frontmatter_match:
            try:
                frontmatter = yaml.safe_load(frontmatter_match.group(1))
                if isinstance(frontmatter, dict):
                    name = frontmatter.get("name") or path.stem
                    description = frontmatter.get("description", "")
                    category = frontmatter.get("category", "general")
                    metadata = {k: v for k, v in frontmatter.items() if k not in ("name", "description", "category")}
            except Exception:
                pass

        if not name:
            name = path.stem

        skill_body = content
        if frontmatter_match:
            skill_body = content[frontmatter_match.end():].strip()

        return Skill(
            name=name,
            description=description or f"Skill: {name}",
            content=skill_body,
            category=category,
            metadata=metadata,
        )

    def get_skill(self, name: str) -> Optional[Skill]:
        self.load_all()
        return self._skills_cache.get(name)

    def load_learned_skills(self, categories: Optional[List[str]] = None) -> int:
        learned_dir = self.skills_dir / "learned"
        if not learned_dir.exists():
            return 0
        self.load_all()
        matched = 0
        for skill_file in learned_dir.glob("*.md"):
            try:
                skill = self._parse_skill_file(skill_file)
                if not skill:
                    continue
                if categories and skill.category not in categories:
                    continue
                if skill.name not in self._skills_cache:
                    self._skills_cache[skill.name] = skill
                    matched += 1
            except Exception as e:
                logger.debug(f"Failed to load learned skill {skill_file.name}: {e}")
        if matched:
            logger.info(f"Loaded {matched} learned skills")
        return matched

    def load_by_categories(self, categories: List[str]) -> int:
        self.load_all()
        matched = 0
        for skill_file in self.skills_dir.glob("*.md"):
            try:
                skill = self._parse_skill_file(skill_file)
                if skill and skill.category in categories:
                    if skill.name not in self._skills_cache:
                        self._skills_cache[skill.name] = skill
                        matched += 1
            except Exception as e:
                logger.debug(f"Failed to load skill {skill_file.name}: {e}")
        matched += self.load_claudskills(categories=categories)
        matched += self.load_h1_reports(categories=categories)
        matched += self.load_learned_skills(categories=categories)
        if matched:
            logger.info(f"Loaded {matched} skills matching categories: {categories}")
        return matched

    def get_skills_by_subcategory(self, subcategory: str) -> List[Skill]:
        self.load_all()
        return [
            s for s in self._skills_cache.values()
            if s.metadata.get("subcategory", "") == subcategory
        ]

    def get_skills_by_tag(self, tag: str) -> List[Skill]:
        self.load_all()
        tag_lower = tag.lower()
        return [
            s for s in self._skills_cache.values()
            if tag_lower in [t.lower() for t in s.metadata.get("tags", [])]
        ]

    def select_skills(self, task: str, context_hints: Optional[List[str]] = None) -> List[Skill]:
        self.load_all()
        hints = [h.lower() for h in (context_hints or [])]
        task_lower = task.lower()

        scored: List[tuple[float, Skill]] = []
        for skill in self._skills_cache.values():
            score = 0.0
            if skill.name.lower() in task_lower:
                score += 2.0
            if skill.description.lower() in task_lower:
                score += 1.5
            for hint in hints:
                if hint in skill.name.lower():
                    score += 1.0
                if hint in skill.content.lower():
                    score += 0.5
            if score > 0:
                scored.append((score, skill))

        scored.sort(key=lambda x: x[0], reverse=True)
        selected = [s for _, s in scored[:self.MAX_SKILLS_PER_AGENT]]

        if selected:
            logger.debug(f"Selected {len(selected)} skills for task: {task[:60]}...")
        return selected

    def inject_into_prompt(self, task: str, context_hints: Optional[List[str]] = None) -> str:
        skills = self.select_skills(task, context_hints)
        if not skills:
            return ""

        parts = ["\n\n## Specialized Knowledge Packages\n"]
        for skill in skills:
            parts.append(f"\n### {skill.name}\n")
            parts.append(skill.content[:800])
            parts.append("")
        return "\n".join(parts)

    def inject_pentest_skills(self, subcategory: str, max_skills: int = 8) -> str:
        self.load_all()
        skills = self.get_skills_by_subcategory(subcategory)
        if not skills:
            return ""
        skills = skills[:max_skills]

        parts = [f"\n\n## Pentest Skills - {subcategory}\n"]
        for skill in skills:
            parts.append(f"\n### {skill.name}\n{skill.description}\n")
            content_preview = skill.content[:600]
            parts.append(content_preview)
            parts.append("")
        return "\n".join(parts)

    @property
    def available_skills(self) -> List[str]:
        self.load_all()
        return list(self._skills_cache.keys())

    @property
    def categories(self) -> Dict[str, List[str]]:
        self.load_all()
        cats: Dict[str, List[str]] = {}
        for skill in self._skills_cache.values():
            cats.setdefault(skill.category, []).append(skill.name)
        return cats


_engine_instance: Optional[SkillsEngine] = None


def get_skills_engine() -> SkillsEngine:
    global _engine_instance
    if _engine_instance is None:
        _engine_instance = SkillsEngine()
    return _engine_instance
