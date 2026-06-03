"""
Strix-style Skills System for specialized agent knowledge.

Skills are structured knowledge packages that give agents deep expertise
in specific vulnerability types, technologies, and testing methodologies.
"""

from itzraven.skills.engine import SkillsEngine, Skill, get_skills_engine

__all__ = ["SkillsEngine", "Skill", "get_skills_engine"]
