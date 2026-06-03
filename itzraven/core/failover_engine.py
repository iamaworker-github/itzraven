"""
Fail-Aware Recovery Engine — Plan A fail → Plan B automatically.
LLM analyzes failure, selects alternative approach, executes recovery.
"""

import json
import time
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from enum import Enum

from itzraven.core.logger import get_logger
from itzraven.agents.llm_client import LLMClient

logger = get_logger()


class RecoveryStrategy(Enum):
    RETRY_DIFFERENT = "retry_different"
    SIMPLIFY = "simplify"
    ESCALATE = "escalate"
    PIVOT = "pivot"
    DECOMPOSE = "decompose"
    RESEARCH = "research"
    ABORT = "abort"


@dataclass
class FallbackPlan:
    strategy: RecoveryStrategy
    description: str
    action: str
    params: Dict[str, Any]
    expected_outcome: str
    confidence: float
    condition: str = ""


@dataclass
class FailoverState:
    primary_action: str
    primary_params: Dict
    failure_reason: str
    failure_detail: str
    attempts: int = 0
    fallback_plans: List[FallbackPlan] = field(default_factory=list)
    current_plan_index: int = 0
    resolved: bool = False
    duration_seconds: float = 0.0
    start_time: float = field(default_factory=time.time)


class FailoverEngine:
    _instance = None

    def __init__(self):
        self.llm = LLMClient()
        self.active_failovers: Dict[str, FailoverState] = {}
        self.history: List[Dict] = []

    @classmethod
    def get_instance(cls) -> "FailoverEngine":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    async def handle_failure(self, failover_id: str, action: str, params: Dict,
                              error: str, context: str = "") -> Optional[FallbackPlan]:
        state = self.active_failovers.get(failover_id)
        if not state:
            state = FailoverState(
                primary_action=action,
                primary_params=params,
                failure_reason=error,
                failure_detail=context,
            )
            self.active_failovers[failover_id] = state

        state.attempts += 1

        if state.current_plan_index < len(state.fallback_plans):
            plan = state.fallback_plans[state.current_plan_index]
            state.current_plan_index += 1
            logger.info(f"Failover [{failover_id}]: trying fallback {state.current_plan_index}/{len(state.fallback_plans)}: {plan.strategy.value}")
            return plan

        plans = await self._generate_fallback_plans(state)
        state.fallback_plans = plans
        state.current_plan_index = 0

        if plans:
            plan = plans[0]
            state.current_plan_index = 1
            logger.info(f"Failover [{failover_id}]: generated {len(plans)} plans, trying: {plan.strategy.value}")
            return plan

        return None

    async def _generate_fallback_plans(self, state: FailoverState) -> List[FallbackPlan]:
        prompt = (
            f"A security testing action failed. Generate alternative approaches.\n\n"
            f"Action: {state.primary_action}\n"
            f"Parameters: {json.dumps(state.primary_params, indent=2)}\n"
            f"Failure: {state.failure_reason}\n"
            f"Context: {state.failure_detail[:500]}\n"
            f"Attempts: {state.attempts}\n\n"
            "Generate 3 alternative fallback plans. For each:\n"
            "{\n"
            '  "plans": [\n'
            "    {\n"
            '      "strategy": "retry_different/simplify/escalate/pivot/decompose/research/abort",\n'
            '      "description": "what the plan does",\n'
            '      "action": "specific action to take",\n'
            '      "params": {"key": "value"},\n'
            '      "expected_outcome": "what should happen",\n'
            '      "confidence": 0.0-1.0\n'
            "    }\n"
            "  ]\n"
            "}"
        )
        system = "You are a disaster recovery planner for security testing. Generate practical fallback plans."

        try:
            resp = await self.llm.generate(prompt=prompt, system=system, max_tokens=1000, task="failover_planning")
            raw = resp.content
            parsed = json.loads(raw) if isinstance(raw, dict) else json.loads(raw)
        except Exception as e:
            logger.debug(f"Failover planning failed: {e}")
            return [FallbackPlan(
                strategy=RecoveryStrategy.ABORT,
                description="LLM planning failed, aborting",
                action="abort",
                params={},
                expected_outcome="No further action",
                confidence=0.0,
            )]

        plans = []
        for p in parsed.get("plans", []):
            try:
                strategy = RecoveryStrategy(p.get("strategy", "abort"))
            except ValueError:
                strategy = RecoveryStrategy.ABORT
            plans.append(FallbackPlan(
                strategy=strategy,
                description=p.get("description", ""),
                action=p.get("action", "abort"),
                params=p.get("params", {}),
                expected_outcome=p.get("expected_outcome", ""),
                confidence=float(p.get("confidence", 0.0)),
            ))

        plans.sort(key=lambda p: p.confidence, reverse=True)
        return plans

    def record_resolution(self, failover_id: str, success: bool, notes: str = ""):
        state = self.active_failovers.get(failover_id)
        if state:
            state.resolved = success
            state.duration_seconds = time.time() - state.start_time
            record = {
                "failover_id": failover_id,
                "action": state.primary_action,
                "failure": state.failure_reason,
                "plans_generated": len(state.fallback_plans),
                "plans_tried": state.current_plan_index,
                "resolved": success,
                "duration": round(state.duration_seconds, 1),
                "notes": notes,
            }
            self.history.append(record)
            logger.info(f"Failover [{failover_id}]: {'RESOLVED' if success else 'UNRESOLVED'} after {state.current_plan_index} plans")

    def get_stats(self) -> dict:
        total = len(self.history)
        resolved = sum(1 for h in self.history if h["resolved"])
        return {
            "total_failures": total,
            "resolved": resolved,
            "resolution_rate": round(resolved / max(total, 1) * 100, 1),
            "active_failovers": len(self.active_failovers),
        }


get_failover_engine = FailoverEngine.get_instance
