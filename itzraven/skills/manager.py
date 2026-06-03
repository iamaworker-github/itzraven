"""
Skills Manager — list, search, and inspect all loaded skills
"""

from typing import List, Dict, Optional
from pathlib import Path

from itzraven.skills.engine import SkillsEngine, get_skills_engine
from itzraven.core.logger import get_logger

logger = get_logger()


class SkillsManager:
    def __init__(self, engine: Optional[SkillsEngine] = None):
        self.engine = engine or get_skills_engine()
        self.engine.load_all()

    def list_all(self) -> List[Dict]:
        return [
            {"name": s.name, "description": s.description, "category": s.category}
            for s in self.engine._skills_cache.values()
        ]

    def search(self, query: str) -> List[Dict]:
        q = query.lower()
        results = []
        for s in self.engine._skills_cache.values():
            if q in s.name.lower() or q in s.description.lower() or q in s.content.lower()[:200]:
                results.append({"name": s.name, "description": s.description, "category": s.category})
        return results

    def get_by_category(self, category: str) -> List[Dict]:
        return [
            {"name": s.name, "description": s.description}
            for s in self.engine._skills_cache.values()
            if s.category == category
        ]

    def summary(self) -> Dict:
        cats = self.engine.categories
        return {
            "total": len(self.engine._skills_cache),
            "categories": {k: len(v) for k, v in cats.items()},
        }

    def get_skill_content(self, name: str) -> Optional[str]:
        skill = self.engine.get_skill(name)
        if skill:
            return skill.content[:2000]
        return None
