"""
Evidence-Gated Finding Lifecycle — Numasec-inspired.

Stages:
  candidate → observed → verified → reportable
       ↓          ↓          ↓
    rejected   rejected   rejected

Each transition requires evidence (replayable proof).
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from itzraven.core.logger import get_logger

logger = get_logger()


class FindingStage(Enum):
    CANDIDATE = "candidate"
    OBSERVED = "observed"
    VERIFIED = "verified"
    REPORTABLE = "reportable"
    REJECTED = "rejected"

    @staticmethod
    def _valid_transitions() -> Dict[str, List[str]]:
        return {
            "candidate": ["observed", "rejected"],
            "observed": ["verified", "rejected"],
            "verified": ["reportable", "rejected"],
            "reportable": [],
            "rejected": ["candidate"],
        }

    def can_transition_to(self, target: "FindingStage") -> bool:
        return target.value in self._valid_transitions().get(self.value, [])


@dataclass
class Evidence:
    type: str  # http_response, code_snippet, poc_output, screenshot, log
    data: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    verified_by: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"type": self.type, "data": self.data[:500], "timestamp": self.timestamp, "verified_by": self.verified_by}


@dataclass
class LifecycleFinding:
    title: str
    description: str
    severity: str  # critical, high, medium, low, info
    category: str  # sqli, xss, ssrf, auth, idor, etc.
    stage: FindingStage = FindingStage.CANDIDATE
    evidence_chain: List[Evidence] = field(default_factory=list)
    confidence: float = 0.0
    agent_name: str = ""
    target: str = ""
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now().isoformat())
    metadata: Dict[str, Any] = field(default_factory=dict)

    def transition_to(self, target: FindingStage, evidence: Optional[Evidence] = None) -> bool:
        if not self.stage.can_transition_to(target):
            logger.warning(f"Finding '{self.title}': invalid transition {self.stage.value} → {target.value}")
            return False
        if evidence:
            self.evidence_chain.append(evidence)
            self.confidence = min(1.0, self.confidence + 0.25)
        self.stage = target
        self.updated_at = datetime.now().isoformat()
        return True

    def add_evidence(self, evidence: Evidence):
        self.evidence_chain.append(evidence)
        self.confidence = min(1.0, self.confidence + 0.15)
        self.updated_at = datetime.now().isoformat()

    @property
    def is_reportable(self) -> bool:
        return self.stage == FindingStage.REPORTABLE and len(self.evidence_chain) >= 2

    @property
    def replay_poc(self) -> str:
        for e in reversed(self.evidence_chain):
            if e.type in ("http_response", "poc_output"):
                return e.data[:2000]
        return "No replayable PoC available"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "category": self.category,
            "stage": self.stage.value,
            "confidence": self.confidence,
            "evidence_count": len(self.evidence_chain),
            "replay_poc": self.replay_poc,
            "agent_name": self.agent_name,
            "target": self.target,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


class FindingLifecycleManager:
    _instance: Optional["FindingLifecycleManager"] = None

    def __init__(self):
        self._findings: Dict[str, LifecycleFinding] = {}

    def create(self, title: str, description: str, severity: str, category: str, agent_name: str = "", target: str = "") -> LifecycleFinding:
        f = LifecycleFinding(title=title, description=description, severity=severity, category=category, agent_name=agent_name, target=target)
        self._findings[f"{agent_name}:{title}"] = f
        return f

    def get(self, key: str) -> Optional[LifecycleFinding]:
        return self._findings.get(key)

    def get_all(self) -> List[LifecycleFinding]:
        return list(self._findings.values())

    def get_reportable(self) -> List[LifecycleFinding]:
        return [f for f in self._findings.values() if f.is_reportable]

    def observe(self, finding: LifecycleFinding, evidence: Evidence) -> bool:
        return finding.transition_to(FindingStage.OBSERVED, evidence)

    def verify(self, finding: LifecycleFinding, evidence: Evidence) -> bool:
        return finding.transition_to(FindingStage.VERIFIED, evidence)

    def mark_reportable(self, finding: LifecycleFinding, evidence: Evidence) -> bool:
        return finding.transition_to(FindingStage.REPORTABLE, evidence)

    def reject(self, finding: LifecycleFinding, reason: str = ""):
        finding.transition_to(FindingStage.REJECTED)
        finding.metadata["rejection_reason"] = reason

    @classmethod
    def get_instance(cls) -> "FindingLifecycleManager":
        if cls._instance is None:
            cls._instance = FindingLifecycleManager()
        return cls._instance


_flm: Optional[FindingLifecycleManager] = None


def get_finding_lifecycle() -> FindingLifecycleManager:
    global _flm
    if _flm is None:
        _flm = FindingLifecycleManager()
    return _flm
