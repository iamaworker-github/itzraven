"""
Quality Checker - scores bug bounty report quality from 1 to 10
"""

from typing import Dict, Any, Optional

from itzraven.core.logger import get_logger
from itzraven.core.config import get_config
from itzraven.agents.base_agent import Finding

logger = get_logger()

WEIGHTS = {
    "title_quality": 1.5,
    "description_length": 2.0,
    "evidence_quality": 2.0,
    "proof_of_concept": 2.0,
    "remediation": 1.5,
    "reproducibility": 1.0,
}

MAX_SCORE = sum(WEIGHTS.values())


class QualityChecker:
    def __init__(self, weights: Dict[str, float] = WEIGHTS):
        self.weights = weights
        self._max_score = sum(weights.values())

    def score(self, finding: Finding) -> float:
        scores = {
            "title_quality": self._score_title(finding.title),
            "description_length": self._score_description(finding.description),
            "evidence_quality": self._score_evidence(finding.evidence),
            "proof_of_concept": self._score_poc(finding.proof_of_concept),
            "remediation": self._score_remediation(finding.remediation),
            "reproducibility": self._score_reproducibility(finding.reproducibility_steps),
        }

        weighted = sum(
            scores[key] * self.weights.get(key, 0)
            for key in scores
        )

        raw = round((weighted / self._max_score) * 10, 2)
        final = max(1.0, min(10.0, raw))

        if final < 5:
            logger.warning(f"Low quality score ({final}) for: {finding.title}")
        else:
            logger.debug(f"Quality score {final} for: {finding.title}")

        return final

    def is_above_threshold(self, finding: Finding, threshold: float = 7.0) -> bool:
        s = self.score(finding)
        result = s >= threshold
        logger.info(
            f"Quality check: {finding.title} — {s}/10 "
            f"({'PASS' if result else 'FAIL'}, threshold={threshold})"
        )
        return result

    def get_breakdown(self, finding: Finding) -> Dict[str, Any]:
        scores = {
            "title_quality": self._score_title(finding.title),
            "description_length": self._score_description(finding.description),
            "evidence_quality": self._score_evidence(finding.evidence),
            "proof_of_concept": self._score_poc(finding.proof_of_concept),
            "remediation": self._score_remediation(finding.remediation),
            "reproducibility": self._score_reproducibility(finding.reproducibility_steps),
        }
        return {
            "overall_score": self.score(finding),
            "component_scores": scores,
            "max_score": 10.0,
            "threshold": 7.0,
        }

    @staticmethod
    def _score_title(title: str) -> float:
        t = (title or "").strip()
        if not t:
            return 0.0
        length = len(t)
        if length < 10:
            return 0.3
        if length < 30:
            return 0.6
        if length > 100:
            return 0.7
        return 1.0

    @staticmethod
    def _score_description(desc: str) -> float:
        d = (desc or "").strip()
        if not d:
            return 0.0
        length = len(d)
        if length < 50:
            return 0.2
        if length < 150:
            return 0.5
        if length < 300:
            return 0.7
        if length < 500:
            return 0.85
        return 1.0

    @staticmethod
    def _score_evidence(evidence: str) -> float:
        e = (evidence or "").strip()
        if not e:
            return 0.0
        length = len(e)
        if length < 20:
            return 0.2
        if length < 100:
            return 0.5
        has_request = any(m in e.lower() for m in ["get ", "post ", "http://", "https://", "request"])
        has_response = any(m in e.lower() for m in ["response", "status", "200", "401", "500"])
        base = 0.7 if length >= 100 else 0.5
        if has_request and has_response:
            return min(1.0, base + 0.3)
        if has_request or has_response:
            return min(1.0, base + 0.15)
        return base

    @staticmethod
    def _score_poc(poc: Optional[str]) -> float:
        p = (poc or "").strip()
        if not p:
            return 0.0
        length = len(p)
        if length < 30:
            return 0.3
        if length < 100:
            return 0.6
        has_code = "```" in p or "def " in p or "curl" in p or "fetch" in p
        has_steps = any(m in p.lower() for m in ["step", "navigate", "visit", "submit", "click"])
        base = 0.7
        if has_code and has_steps:
            return 1.0
        if has_code or has_steps:
            return 0.85
        return base

    @staticmethod
    def _score_remediation(rem: Optional[str]) -> float:
        r = (rem or "").strip()
        if not r:
            return 0.0
        length = len(r)
        if length < 30:
            return 0.3
        if length < 100:
            return 0.5
        has_action = any(m in r.lower() for m in ["use ", "implement", "add ", "configure", "sanitize", "validate", "encode"])
        if has_action and length >= 100:
            return 1.0
        if has_action:
            return 0.75
        return 0.6

    @staticmethod
    def _score_reproducibility(steps: list) -> float:
        if not steps:
            return 0.0
        count = len(steps)
        if count == 0:
            return 0.0
        total_chars = sum(len(s) for s in steps)
        if count >= 4 and total_chars >= 200:
            return 1.0
        if count >= 3:
            return 0.8
        if count >= 2:
            return 0.5
        return 0.3
