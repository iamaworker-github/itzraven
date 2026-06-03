"""
Meta-Cognition — self-reflection loop for autonomous strategy switching.

Agents periodically reflect on their progress and adjust strategy:
- "I've tried 5 SQLi payloads, none worked → switch to SSRF"
- "WAF keeps blocking me → try different bypass technique"
- "Found 3 XSS already → good, continue this vector"
"""

import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any

from itzraven.core.logger import get_logger

logger = get_logger()


@dataclass
class ReflectionInsight:
    step: int
    timestamp: float
    observation: str
    decision: str
    action_taken: str
    technique: str = ""


@dataclass
class AgentReflection:
    agent_name: str
    start_time: float = 0.0
    steps: int = 0
    findings_count: int = 0
    last_finding_step: int = 0
    techniques_tried: Dict[str, int] = field(default_factory=dict)
    techniques_succeeded: Dict[str, int] = field(default_factory=dict)
    errors_encountered: List[str] = field(default_factory=list)
    reflections: List[ReflectionInsight] = field(default_factory=list)
    strategy: str = "explore"
    consecutive_failures: int = 0

    def record_step(self, technique: str = "", success: bool = False, error: str = ""):
        self.steps += 1
        if technique:
            self.techniques_tried[technique] = self.techniques_tried.get(technique, 0) + 1
            if success:
                self.techniques_succeeded[technique] = self.techniques_succeeded.get(technique, 0) + 1
                self.last_finding_step = self.steps
                self.consecutive_failures = 0
            else:
                self.consecutive_failures += 1
        if error:
            self.errors_encountered.append(error)

    def record_finding(self):
        self.findings_count += 1
        self.last_finding_step = self.steps
        self.consecutive_failures = 0

    def should_reflect(self, interval: int = 5) -> bool:
        return self.steps > 0 and self.steps % interval == 0

    def generate_insight(self) -> Optional[str]:
        if self.findings_count == 0 and self.steps >= 8:
            return "NO_FINDINGS: No vulnerabilities found yet after several attempts. Consider switching technique or target vector."

        top_technique = max(self.techniques_tried, key=self.techniques_tried.get) if self.techniques_tried else ""
        succeeded_techs = set(self.techniques_succeeded.keys())

        if self.consecutive_failures >= 3 and len(self.techniques_tried) >= 2:
            failed_techs = [t for t in self.techniques_tried if t not in succeeded_techs]
            if failed_techs:
                return f"STRATEGY_SHIFT: {failed_techs[-1]} failing consistently ({self.consecutive_failures}x). Switch to different technique."

        if top_technique and top_technique in succeeded_techs:
            return f"CONTINUE: {top_technique} is working. Stay on this vector."

        if self.errors_encountered:
            last_error = self.errors_encountered[-1]
            if "timeout" in last_error.lower():
                return "ADAPT: Timeouts detected. Reduce payload complexity or increase timeout."

        return None

    def reflect(self) -> Optional[ReflectionInsight]:
        insight_text = self.generate_insight()
        if not insight_text:
            return None

        parts = insight_text.split(":", 1)
        decision = parts[0].strip() if len(parts) > 1 else "OBSERVE"
        observation = parts[1].strip() if len(parts) > 1 else insight_text

        top_tech = max(self.techniques_tried, key=self.techniques_tried.get) if self.techniques_tried else ""

        if "STRATEGY_SHIFT" in decision:
            self.strategy = "pivot"
        elif "CONTINUE" in decision:
            self.strategy = "deepen"
        elif "NO_FINDINGS" in decision:
            self.strategy = "explore_wider"

        insight = ReflectionInsight(
            step=self.steps,
            timestamp=time.time(),
            observation=observation,
            decision=decision,
            action_taken=self.strategy,
            technique=top_tech,
        )
        self.reflections.append(insight)
        return insight


class MetaCognitionEngine:
    _instance = None

    def __init__(self):
        self.agents: Dict[str, AgentReflection] = {}

    @classmethod
    def get_instance(cls) -> "MetaCognitionEngine":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def register_agent(self, name: str) -> AgentReflection:
        ref = AgentReflection(agent_name=name, start_time=time.time())
        self.agents[name] = ref
        return ref

    def get_reflection(self, name: str) -> Optional[AgentReflection]:
        return self.agents.get(name)

    def record_step(self, name: str, technique: str = "", success: bool = False, error: str = ""):
        ref = self.agents.get(name)
        if ref:
            ref.record_step(technique=technique, success=success, error=error)

    def record_finding(self, name: str):
        ref = self.agents.get(name)
        if ref:
            ref.record_finding()

    def check_reflection(self, name: str, interval: int = 5) -> Optional[ReflectionInsight]:
        ref = self.agents.get(name)
        if ref and ref.should_reflect(interval):
            return ref.reflect()
        return None

    def get_summary(self, name: str) -> dict:
        ref = self.agents.get(name)
        if not ref:
            return {}
        return {
            "agent": name,
            "steps": ref.steps,
            "findings": ref.findings_count,
            "strategy": ref.strategy,
            "techniques_tried": dict(ref.techniques_tried),
            "techniques_succeeded": dict(ref.techniques_succeeded),
            "consecutive_failures": ref.consecutive_failures,
            "reflections": [r.observation for r in ref.reflections],
            "elapsed": round(time.time() - ref.start_time, 1),
        }


get_meta_cognition = MetaCognitionEngine.get_instance
