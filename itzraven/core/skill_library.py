"""
Skill Library — autonomous attack pattern learning & reuse.

Whenever an agent finds a vulnerability, it can save the technique as a Skill.
Future scans reuse skills matching the target's technology stack.
"""

import json
import time
import hashlib
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Dict, List, Optional, Any, Set
from datetime import datetime

from itzraven.core.logger import get_logger

logger = get_logger()

SKILLS_DIR = Path.home() / ".itzraven" / "skills"


@dataclass
class AttackSkill:
    name: str
    technique: str
    category: str
    description: str
    required_techs: List[str]
    payload_template: str
    evidence: str
    source_agent: str
    target_url: str
    severity: str
    confidence: float = 0.0
    success_rate: float = 1.0
    times_used: int = 1
    times_success: int = 1
    last_used: float = 0.0
    created_at: float = 0.0
    tags: List[str] = field(default_factory=list)
    skill_id: str = ""

    def __post_init__(self):
        if not self.skill_id:
            raw = f"{self.technique}:{self.target_url}:{self.payload_template[:80]}"
            self.skill_id = hashlib.sha256(raw.encode()).hexdigest()[:12]
        if not self.created_at:
            self.created_at = time.time()
        self.update_confidence()

    def update_confidence(self):
        base = self.success_rate
        volume = min(self.times_used / 5.0, 1.0)
        recency = 1.0 - min((time.time() - self.last_used) / 86400.0, 0.5)
        self.confidence = round(base * 0.5 + volume * 0.3 + recency * 0.2, 3)

    def matches_tech(self, technologies: List[str]) -> bool:
        tech_lower = [t.lower() for t in technologies]
        return any(r.lower() in tech_lower for r in self.required_techs) if self.required_techs else True

    def record_use(self, success: bool):
        self.times_used += 1
        if success:
            self.times_success += 1
        self.success_rate = self.times_success / max(self.times_used, 1)
        self.last_used = time.time()
        self.update_confidence()

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_finding(cls, finding, agent_name: str, target: str, technologies: List[str]) -> "AttackSkill":
        raw = f"{finding.category}:{finding.evidence}"
        skill_id = hashlib.sha256(raw.encode()).hexdigest()[:12]
        return cls(
            name=f"{finding.category.upper()}: {finding.title[:60]}",
            technique=finding.category,
            category=finding.category,
            description=finding.description[:200],
            required_techs=technologies[:5],
            payload_template=finding.evidence[:200],
            evidence=finding.evidence[:300],
            source_agent=agent_name,
            target_url=target,
            severity=finding.severity,
            confidence=finding.confidence,
            last_used=time.time(),
            created_at=time.time(),
            skill_id=skill_id,
        )


class SkillLibrary:
    _instance = None

    def __init__(self):
        self.skills: Dict[str, AttackSkill] = {}
        self._modified = False
        SKILLS_DIR.mkdir(parents=True, exist_ok=True)
        self._load()

    @classmethod
    def get_instance(cls) -> "SkillLibrary":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def _load(self):
        path = SKILLS_DIR / "skills.json"
        if path.exists():
            try:
                data = json.loads(path.read_text())
                for item in data:
                    skill = AttackSkill(**item)
                    self.skills[skill.skill_id] = skill
                logger.info(f"SkillLibrary: loaded {len(self.skills)} skills")
            except Exception as e:
                logger.debug(f"SkillLibrary load error: {e}")

    def save(self):
        path = SKILLS_DIR / "skills.json"
        try:
            path.write_text(json.dumps([s.to_dict() for s in self.skills.values()], indent=2))
            self._modified = False
        except Exception as e:
            logger.debug(f"SkillLibrary save error: {e}")

    def add_skill(self, skill: AttackSkill) -> bool:
        existing = self.skills.get(skill.skill_id)
        if existing:
            existing.record_use(success=True)
            existing.last_used = time.time()
            return False
        self.skills[skill.skill_id] = skill
        self._modified = True
        self.save()
        logger.info(f"🏅 New skill learned: {skill.name} [{skill.technique}] on {skill.required_techs}")
        return True

    def learn_from_finding(self, finding, agent_name: str, target: str, technologies: List[str]) -> Optional[AttackSkill]:
        if finding.confidence < 0.6 or finding.severity in ("info",):
            return None
        skill = AttackSkill.from_finding(finding, agent_name, target, technologies)
        self.add_skill(skill)
        return skill

    def recommend_for_tech(self, technologies: List[str], min_confidence: float = 0.4, limit: int = 10) -> List[AttackSkill]:
        candidates = [s for s in self.skills.values() if s.confidence >= min_confidence]
        scored = sorted(
            ((s, s.confidence * (1.2 if s.matches_tech(technologies) else 0.5)) for s in candidates),
            key=lambda x: -x[1],
        )
        return [s for s, _ in scored[:limit]]

    def recommend_for_category(self, category: str, technologies: List[str]) -> List[AttackSkill]:
        return [s for s in self.skills.values()
                if s.category == category and s.matches_tech(technologies) and s.confidence >= 0.3]

    def record_result(self, technique: str, success: bool):
        for skill in self.skills.values():
            if skill.technique == technique:
                skill.record_use(success)
        self._modified = True
        self.save()

    def get_stats(self) -> dict:
        total = len(self.skills)
        by_tech: Dict[str, int] = {}
        for s in self.skills.values():
            for t in s.required_techs:
                by_tech[t] = by_tech.get(t, 0) + 1
        return {
            "total_skills": total,
            "by_technique": {t: sum(1 for s in self.skills.values() if s.technique == t) for t in set(s.technique for s in self.skills.values())},
            "by_tech_stack": by_tech,
            "avg_confidence": round(sum(s.confidence for s in self.skills.values()) / max(total, 1), 3),
        }


get_skill_library = SkillLibrary.get_instance
