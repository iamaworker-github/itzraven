"""
Duplicate Checker - detects duplicate findings via title/description similarity
"""

import re
from difflib import SequenceMatcher
from typing import List, Dict, Any

from itzraven.core.logger import get_logger
from itzraven.core.config import get_config
from itzraven.agents.base_agent import Finding

logger = get_logger()

SIMILARITY_THRESHOLD = 0.75


class DuplicateChecker:
    def __init__(self, threshold: float = SIMILARITY_THRESHOLD):
        self.threshold = threshold

    def check(self, finding: Finding, known_findings: List[Finding]) -> Dict[str, Any]:
        similar: List[Dict[str, Any]] = []
        max_score = 0.0

        for known in known_findings:
            score = self._compute_similarity(finding, known)
            if score >= self.threshold:
                similar.append({
                    "finding": known,
                    "similarity_score": round(score, 4),
                })
            max_score = max(max_score, score)

        is_duplicate = max_score >= self.threshold

        if is_duplicate:
            logger.warning(f"Duplicate detected: {finding.title} (score: {max_score:.2f})")
        else:
            logger.debug(f"No duplicate for: {finding.title} (max score: {max_score:.2f})")

        return {
            "is_duplicate": is_duplicate,
            "similar_findings": similar,
            "similarity_score": round(max_score, 4),
        }

    def _compute_similarity(self, a: Finding, b: Finding) -> float:
        title_score = SequenceMatcher(None, a.title.lower(), b.title.lower()).ratio()
        desc_score = SequenceMatcher(
            None,
            self._normalize(a.description),
            self._normalize(b.description),
        ).ratio()

        return 0.4 * title_score + 0.6 * desc_score

    @staticmethod
    def _normalize(text: str) -> str:
        text = re.sub(r"\s+", " ", text or "")
        text = re.sub(r"[^a-zA-Z0-9\s]", "", text)
        return text.lower().strip()
