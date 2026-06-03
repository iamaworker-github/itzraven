"""
Confidence Filter — Traffic-light self-evaluation system.

Before executing any action, the agent self-scores:
  Green  → Proceed (confidence >= 0.7)
  Yellow → Try alternative approach (0.4 <= confidence < 0.7)
  Red    → Stop and re-evaluate (confidence < 0.4)

Inspired by Deadend CLI's confidence threshold system.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


class TrafficLight(Enum):
    GREEN = "green"
    YELLOW = "yellow"
    RED = "red"


@dataclass
class ConfidenceScore:
    value: float  # 0.0 to 1.0
    reasons: List[str]
    traffic_light: TrafficLight

    @property
    def can_proceed(self) -> bool:
        return self.traffic_light != TrafficLight.RED

    @property
    def should_retry(self) -> bool:
        return self.traffic_light == TrafficLight.YELLOW

    def to_dict(self) -> Dict[str, Any]:
        return {"value": round(self.value, 2), "reasons": self.reasons, "traffic_light": self.traffic_light.value}


class ConfidenceEngine:
    """Self-evaluates action confidence based on context, history, and signals."""

    def __init__(self):
        self._history: Dict[str, List[ConfidenceScore]] = {}

    def evaluate_action(self, action_type: str, params: Dict[str, Any], context: Dict[str, Any], past_attempts: List[Dict[str, Any]]) -> ConfidenceScore:
        reasons = []
        score = 0.5  # neutral baseline

        # Factor 1: Have we tried this exact action before?
        similar_past = [a for a in past_attempts if a.get("action") == action_type and a.get("params", {}).get("param") == params.get("param")]
        if similar_past:
            last_result = similar_past[-1].get("result", "")
            if "error" in last_result.lower() or "timeout" in last_result.lower():
                score -= 0.2
                reasons.append(f"Previous {action_type} on {params.get('param','?')} failed")
            elif "suspicious" in last_result.lower() or "reflected" in last_result.lower():
                score += 0.2
                reasons.append(f"Previous {action_type} showed promising results")

        # Factor 2: Do we have the right context?
        techs = context.get("shared_technologies", [])
        if action_type == "test_sqli" and any(t.lower() in ("mysql", "postgresql", "mariadb", "php", "oracle") for t in techs):
            score += 0.15
            reasons.append("Technology stack supports SQL injection")
        if action_type == "test_xss" and any(t.lower() in ("react", "angular", "vue", "php") for t in techs):
            score += 0.1
            reasons.append("Technology stack may be XSS-prone")
        if action_type == "test_ssrf" and any(t.lower() in ("node.js", "express", "python") for t in techs):
            score += 0.1
            reasons.append("Technology stack has SSRF history")

        # Factor 3: Do we have endpoints to test?
        endpoints = context.get("shared_endpoints", [])
        if not endpoints and action_type in ("test_sqli", "test_xss", "test_ssrf"):
            score -= 0.2
            reasons.append("No endpoints discovered yet")

        # Factor 4: Is there handoff context suggesting this direction?
        handoff = context.get("handoff_context", "")
        if action_type == "test_sqli" and "sqli" in handoff.lower():
            score += 0.15
            reasons.append("Previous agents suggested SQL injection")
        if action_type == "test_xss" and "xss" in handoff.lower():
            score += 0.15
            reasons.append("Previous agents suggested XSS testing")

        # Determine traffic light
        score = max(0.0, min(1.0, score))
        if score >= 0.7:
            light = TrafficLight.GREEN
        elif score >= 0.4:
            light = TrafficLight.YELLOW
        else:
            light = TrafficLight.RED

        cs = ConfidenceScore(value=score, reasons=reasons, traffic_light=light)

        key = f"{action_type}:{params.get('param','?')}"
        if key not in self._history:
            self._history[key] = []
        self._history[key].append(cs)

        return cs

    def get_history(self, action_key: str) -> List[ConfidenceScore]:
        return self._history.get(action_key, [])

    def clear(self):
        self._history.clear()


_confidence_engine: Optional[ConfidenceEngine] = None


def get_confidence_engine() -> ConfidenceEngine:
    global _confidence_engine
    if _confidence_engine is None:
        _confidence_engine = ConfidenceEngine()
    return _confidence_engine
