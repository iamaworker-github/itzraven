"""
Budget Controller — per-agent tool call limits with cost-aware early stopping.

Each agent gets a budget (max tool calls). Tracks usage and can signal
early termination when ROI drops below threshold.
"""

import time
from dataclasses import dataclass, field
from typing import Dict, Optional, List

from itzraven.core.logger import get_logger

logger = get_logger()


@dataclass
class AgentBudget:
    agent_name: str
    max_calls: int = 50
    calls_made: int = 0
    start_time: float = 0.0
    findings_found: int = 0
    last_finding_time: float = 0.0
    stalled_iterations: int = 0
    is_active: bool = True
    strategy_shifts: int = 0
    total_response_time: float = 0.0

    @property
    def remaining(self) -> int:
        return max(0, self.max_calls - self.calls_made)

    @property
    def utilization(self) -> float:
        return self.calls_made / max(self.max_calls, 1)

    @property
    def findings_per_call(self) -> float:
        return self.findings_found / max(self.calls_made, 1)

    def record_call(self):
        self.calls_made += 1

    def record_finding(self):
        self.findings_found += 1
        self.last_finding_time = time.time()
        self.stalled_iterations = 0

    def record_stall(self):
        self.stalled_iterations += 1

    def should_stop(self) -> tuple:
        if not self.is_active:
            return True, "inactive"
        if self.calls_made >= self.max_calls:
            return True, "budget_exhausted"
        if self.calls_made >= 10 and self.findings_found == 0:
            return True, "no_findings_after_10_calls"
        if self.stalled_iterations >= 5:
            return True, "stalled_5_iterations"
        if self.calls_made >= 20 and self.findings_per_call < 0.05:
            return True, "low_roi"
        return False, ""


class BudgetController:
    _instance = None

    def __init__(self, default_max_calls: int = 50):
        self.default_max_calls = default_max_calls
        self.budgets: Dict[str, AgentBudget] = {}

    @classmethod
    def get_instance(cls, default_max_calls: int = 50) -> "BudgetController":
        if cls._instance is None:
            cls._instance = cls(default_max_calls)
        return cls._instance

    def register_agent(self, name: str, max_calls: Optional[int] = None) -> AgentBudget:
        budget = AgentBudget(
            agent_name=name,
            max_calls=max_calls or self.default_max_calls,
            start_time=time.time(),
        )
        self.budgets[name] = budget
        return budget

    def get_budget(self, name: str) -> Optional[AgentBudget]:
        return self.budgets.get(name)

    def record_call(self, name: str):
        b = self.budgets.get(name)
        if b:
            b.record_call()

    def record_finding(self, name: str):
        b = self.budgets.get(name)
        if b:
            b.record_finding()

    def record_stall(self, name: str):
        b = self.budgets.get(name)
        if b:
            b.record_stall()

    def should_stop(self, name: str) -> tuple:
        b = self.budgets.get(name)
        if not b:
            return False, ""
        return b.should_stop()

    def set_strategy_shift(self, name: str):
        b = self.budgets.get(name)
        if b:
            b.strategy_shifts += 1

    def get_report(self, name: str) -> dict:
        b = self.budgets.get(name)
        if not b:
            return {}
        return {
            "agent": name,
            "calls": b.calls_made,
            "max_calls": b.max_calls,
            "findings": b.findings_found,
            "findings_per_call": round(b.findings_per_call, 3),
            "utilization": round(b.utilization, 2),
            "stalled": b.stalled_iterations,
            "strategy_shifts": b.strategy_shifts,
            "elapsed": round(time.time() - b.start_time, 1),
            "status": "stopped" if not b.is_active else "running",
        }

    def get_all_reports(self) -> List[dict]:
        return [self.get_report(n) for n in self.budgets]


get_budget_controller = BudgetController.get_instance
