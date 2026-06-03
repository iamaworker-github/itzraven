"""
LLM-Powered Self-Reflection Engine — deep introspection of agent actions.
Reflection loop that analyzes failures, successes, and blind spots using LLM.
"""

import time
import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from itzraven.core.logger import get_logger
from itzraven.agents.llm_client import LLMClient

logger = get_logger()


@dataclass
class ReflectionInsight:
    step: int
    timestamp: float
    observation: str
    root_cause: str
    recommendation: str
    confidence: float
    blind_spot: str = ""
    strategy_shift: str = ""


@dataclass
class SessionReflection:
    agent_name: str
    session_id: str
    total_steps: int = 0
    successes: int = 0
    failures: int = 0
    findings: List[Dict] = field(default_factory=list)
    techniques_tried: Dict[str, int] = field(default_factory=dict)
    techniques_succeeded: Dict[str, int] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    insights: List[ReflectionInsight] = field(default_factory=list)
    start_time: float = field(default_factory=time.time)
    last_reflection_time: float = 0.0

    def record_step(self, technique: str, success: bool, error: str = ""):
        self.total_steps += 1
        self.techniques_tried[technique] = self.techniques_tried.get(technique, 0) + 1
        if success:
            self.successes += 1
            self.techniques_succeeded[technique] = self.techniques_succeeded.get(technique, 0) + 1
        else:
            self.failures += 1
        if error:
            self.errors.append(error)

    def should_reflect(self) -> bool:
        elapsed = time.time() - self.last_reflection_time
        return (self.total_steps >= 3 and elapsed >= 30) or (self.failures >= 3)

    def summary(self) -> str:
        return (
            f"Session: {self.session_id} | Steps: {self.total_steps} "
            f"(+{self.successes}/-{self.failures}) | Findings: {len(self.findings)} "
            f"| Techniques tried: {len(self.techniques_tried)}"
        )


class SelfReflectionEngine:
    _instance = None

    def __init__(self):
        self.sessions: Dict[str, SessionReflection] = {}
        self.llm = LLMClient()
        self._insight_history: List[str] = []

    @classmethod
    def get_instance(cls) -> "SelfReflectionEngine":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def start_session(self, agent_name: str, session_id: str) -> SessionReflection:
        ref = SessionReflection(agent_name=agent_name, session_id=session_id)
        self.sessions[session_id] = ref
        logger.info(f"SelfReflection: started session {session_id} for {agent_name}")
        return ref

    def get_session(self, session_id: str) -> Optional[SessionReflection]:
        return self.sessions.get(session_id)

    async def deep_reflect(self, session_id: str) -> Optional[ReflectionInsight]:
        session = self.sessions.get(session_id)
        if not session or not session.should_reflect():
            return None

        prompt = self._build_reflection_prompt(session)
        system = (
            "You are a meta-cognitive security AI analyzing your own actions. "
            "Identify root causes of failures, blind spots, and recommend strategy shifts. "
            "Output valid JSON: {observation, root_cause, recommendation, blind_spot, strategy_shift, confidence}"
        )

        try:
            resp = await self.llm.generate(prompt=prompt, system=system, max_tokens=1000, task="self_reflection")
            parsed = json.loads(resp.content)
            if isinstance(parsed, str):
                parsed = json.loads(parsed)
        except Exception as e:
            logger.debug(f"Self-reflection parse failed: {e}")
            return None

        insight = ReflectionInsight(
            step=session.total_steps,
            timestamp=time.time(),
            observation=parsed.get("observation", "No observation"),
            root_cause=parsed.get("root_cause", "Unknown"),
            recommendation=parsed.get("recommendation", "Continue current strategy"),
            confidence=float(parsed.get("confidence", 0.5)),
            blind_spot=parsed.get("blind_spot", ""),
            strategy_shift=parsed.get("strategy_shift", ""),
        )
        session.insights.append(insight)
        session.last_reflection_time = time.time()
        self._insight_history.append(f"[{session_id}] {insight.observation}")

        logger.info(f"SelfReflection: {insight.observation} (confidence={insight.confidence:.2f})")
        return insight

    def _build_reflection_prompt(self, session: SessionReflection) -> str:
        return (
            f"You are analyzing a security testing session:\n\n"
            f"Agent: {session.agent_name}\n"
            f"Total Steps: {session.total_steps}\n"
            f"Successes: {session.successes}\n"
            f"Failures: {session.failures}\n"
            f"Errors: {session.errors[-5:]}\n\n"
            f"Techniques tried: {json.dumps(session.techniques_tried, indent=2)}\n"
            f"Techniques succeeded: {json.dumps(session.techniques_succeeded, indent=2)}\n\n"
            f"Findings: {json.dumps(session.findings[-3:], indent=2)}\n\n"
            "Analyze: Why are techniques failing? What am I missing? "
            "What should I try next? What is my current blind spot? "
            "Should I shift strategy? Output JSON only."
        )

    async def generate_improvement_plan(self, session_id: str) -> Optional[str]:
        session = self.sessions.get(session_id)
        if not session:
            return None

        prompt = (
            f"Based on this security testing session, generate a concrete improvement plan:\n\n"
            f"{session.summary()}\n\n"
            f"Errors: {session.errors[-10:]}\n\n"
            f"What should I do differently next time? "
            f"What new techniques should I try? What tools should I use?"
        )
        system = "You are a senior security engineer providing actionable improvement advice."
        try:
            resp = await self.llm.generate(prompt=prompt, system=system, max_tokens=800, task="improvement_plan")
            return resp.content
        except Exception as e:
            logger.debug(f"Improvement plan failed: {e}")
            return None


get_self_reflection = SelfReflectionEngine.get_instance
