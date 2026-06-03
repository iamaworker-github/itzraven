"""
Cost Tracking & Token Management for Itzraven.
Extends the CostTracker in llm_client.py with session-level tracking.
"""

import time
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List

from itzraven.core.logger import get_logger
from itzraven.core.config import get_config
from itzraven.agents.llm_client import CostTracker, get_cost_tracker, LLMCallRecord

logger = get_logger()
config = get_config()


@dataclass
class ToolExecutionRecord:
    tool_name: str
    duration: float
    timestamp: float = field(default_factory=time.time)


@dataclass
class Session:
    name: str
    start_time: float
    end_time: Optional[float] = None
    llm_calls: List[LLMCallRecord] = field(default_factory=list)
    tool_executions: List[ToolExecutionRecord] = field(default_factory=list)


class SessionTracker:
    """Tracks LLM costs and tool execution at the session level.

    Wraps the global ``CostTracker`` from ``llm_client.py`` and adds
    session start/stop semantics, budget enforcement, and tool-level
    instrumentation.
    """

    def __init__(self, cost_tracker: Optional[CostTracker] = None):
        self._sessions: List[Session] = []
        self._current_session: Optional[Session] = None
        self._max_budget: Optional[float] = None
        self._cost_tracker: CostTracker = cost_tracker or get_cost_tracker()

    # ------------------------------------------------------------------
    # Budget
    # ------------------------------------------------------------------
    def set_budget(self, max_budget: float) -> None:
        """Set the maximum allowed cost in USD."""
        self._max_budget = max_budget

    def is_over_budget(self) -> bool:
        """Return ``True`` if total cost exceeds the configured budget."""
        if self._max_budget is None:
            return False
        return self.get_total_cost() > self._max_budget

    # ------------------------------------------------------------------
    # Session lifecycle
    # ------------------------------------------------------------------
    def start_session(self, name: str = "default") -> str:
        """Start a new tracking session with the given *name*.

        Returns the session name (for chaining / logging).
        """
        if self._current_session is not None:
            logger.warning(
                f"Session '{self._current_session.name}' is still active — ending it before starting '{name}'",
            )
            self.end_session()

        session = Session(name=name, start_time=time.time())
        self._sessions.append(session)
        self._current_session = session
        logger.info(f"Session '{name}' started")
        return name

    def end_session(self) -> Dict[str, Any]:
        """End the current session and return its summary dict.

        If no session is active this is a no-op that returns an empty dict.
        """
        session = self._current_session
        if session is None:
            logger.warning("end_session() called with no active session")
            return {}

        session.end_time = time.time()
        self._current_session = None

        summary = self._build_session_summary(session)
        logger.info(
            f"Session '{session.name}' ended — "
            f"cost={summary['total_cost']:.4f} "
            f"tokens={summary['total_tokens']} "
            f"calls={summary['llm_call_count']} "
            f"tools={summary['tool_execution_count']}",
        )
        return summary

    # ------------------------------------------------------------------
    # Cost queries
    # ------------------------------------------------------------------
    def get_total_cost(self) -> float:
        """Return the cumulative cost across all recorded sessions."""
        if not self._sessions:
            return self._cost_tracker.total_cost
        return sum(
            sum(r.cost for r in s.llm_calls if r.success)
            for s in self._sessions
        )

    def get_session_report(self) -> Dict[str, Any]:
        """Return a full cost breakdown as a JSON-serialisable dict."""
        return {
            "total_cost": round(self.get_total_cost(), 4),
            "budget": self._max_budget,
            "over_budget": self.is_over_budget(),
            "session_count": len(self._sessions),
            "sessions": [
                self._build_session_summary(s) for s in self._sessions
            ],
        }

    # ------------------------------------------------------------------
    # Logging helpers
    # ------------------------------------------------------------------
    def log_llm_call(
        self,
        provider: str,
        model: str,
        tokens_in: int,
        tokens_out: int,
    ) -> LLMCallRecord:
        """Record an LLM call via the underlying ``CostTracker``.

        The record is also attached to the current session (if any).
        """
        record = self._cost_tracker.record(
            provider=provider,
            model=model,
            tokens_in=tokens_in,
            tokens_out=tokens_out,
            latency_ms=0.0,
        )
        if self._current_session is not None:
            self._current_session.llm_calls.append(record)
        return record

    def log_tool_execution(self, tool_name: str, duration: float) -> ToolExecutionRecord:
        """Record a tool execution with its duration in seconds."""
        record = ToolExecutionRecord(tool_name=tool_name, duration=duration)
        if self._current_session is not None:
            self._current_session.tool_executions.append(record)
        else:
            logger.debug("No active session — tool '%s' not tracked", tool_name)
        return record

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _build_session_summary(session: Session) -> Dict[str, Any]:
        duration = None
        if session.end_time is not None:
            duration = round(session.end_time - session.start_time, 3)

        llm_cost = sum(r.cost for r in session.llm_calls if r.success)
        llm_tokens = sum(r.tokens_in + r.tokens_out for r in session.llm_calls if r.success)

        return {
            "name": session.name,
            "start_time": session.start_time,
            "end_time": session.end_time,
            "duration_seconds": duration,
            "total_cost": round(llm_cost, 4),
            "total_tokens": llm_tokens,
            "llm_call_count": len(session.llm_calls),
            "llm_calls": [
                {
                    "provider": r.provider,
                    "model": r.model,
                    "tokens_in": r.tokens_in,
                    "tokens_out": r.tokens_out,
                    "cost": round(r.cost, 6),
                    "latency_ms": round(r.latency_ms, 1),
                    "success": r.success,
                    "timestamp": r.timestamp,
                }
                for r in session.llm_calls
            ],
            "tool_execution_count": len(session.tool_executions),
            "tool_executions": [
                {
                    "tool_name": t.tool_name,
                    "duration": round(t.duration, 4),
                    "timestamp": t.timestamp,
                }
                for t in session.tool_executions
            ],
        }


# -----------------------------------------------------------------------
# Global singleton
# -----------------------------------------------------------------------
_session_tracker: Optional[SessionTracker] = None


def get_session_tracker() -> SessionTracker:
    global _session_tracker
    if _session_tracker is None:
        _session_tracker = SessionTracker()
    return _session_tracker
