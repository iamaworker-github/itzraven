"""
Agent Handoff — CAI-style peer-to-peer context transfer between agents.

Each agent publishes a HandoffContext when it finishes. Subsequent agents
receive accumulated contexts so they know what was tested, what was found,
and what should be prioritized next.
"""

import json
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Dict, List, Optional, Any
from itzraven.core.logger import get_logger

logger = get_logger()


@dataclass
class HandoffContext:
    agent_name: str
    phase: str
    target: str
    findings_summary: str = ""
    technologies: List[str] = field(default_factory=list)
    endpoints: List[str] = field(default_factory=list)
    open_ports: List[Dict[str, Any]] = field(default_factory=list)
    waf_info: str = ""
    hidden_paths: List[str] = field(default_factory=list)
    service_details: List[Dict[str, Any]] = field(default_factory=list)
    tested_parameters: List[Dict[str, str]] = field(default_factory=list)
    blocked_paths: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    confidence: float = 1.0
    timestamp: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def short_summary(self, max_len: int = 200) -> str:
        parts = []
        if self.findings_summary:
            parts.append(self.findings_summary[:max_len])
        if self.technologies:
            parts.append(f"tech: {', '.join(self.technologies[:5])}")
        if self.endpoints:
            parts.append(f"endpoints: {len(self.endpoints)}")
        if self.open_ports:
            parts.append(f"ports: {len(self.open_ports)}")
        if self.recommendations:
            parts.append(f"recommends: {'; '.join(self.recommendations[:3])}")
        return " | ".join(parts)


class HandoffManager:
    _instance: Optional["HandoffManager"] = None

    def __init__(self):
        self._contexts: Dict[str, List[HandoffContext]] = {}
        self._agent_order: List[str] = []
        self._phase_order: List[str] = []

    def publish(self, ctx: HandoffContext):
        target = ctx.target
        if target not in self._contexts:
            self._contexts[target] = []
        self._contexts[target].append(ctx)
        self._agent_order.append(ctx.agent_name)
        if ctx.phase not in self._phase_order:
            self._phase_order.append(ctx.phase)
        logger.debug(f"Handoff: {ctx.agent_name} [{ctx.phase}] published for {target}")

    def get_context(self, target: str) -> List[HandoffContext]:
        return self._contexts.get(target, [])

    def get_latest(self, target: str, agent_name: Optional[str] = None) -> Optional[HandoffContext]:
        contexts = self._contexts.get(target, [])
        if agent_name:
            for ctx in reversed(contexts):
                if ctx.agent_name == agent_name:
                    return ctx
            return None
        return contexts[-1] if contexts else None

    def get_phase_contexts(self, target: str, phase: str) -> List[HandoffContext]:
        return [c for c in self._contexts.get(target, []) if c.phase == phase]

    def build_handoff_prompt(self, target: str) -> str:
        contexts = self._contexts.get(target, [])
        if not contexts:
            return ""
        lines = ["<agent-handoff>"]
        lines.append("Previous agents' findings and recommendations:")
        for ctx in contexts:
            summary = ctx.short_summary()
            if summary:
                lines.append(f"  [{ctx.agent_name}] ({ctx.phase}): {summary}")
        lines.append("</agent-handoff>")
        return "\n".join(lines)

    def build_phase_prompt(self, target: str, phase: str) -> str:
        contexts = self.get_phase_contexts(target, phase)
        if not contexts:
            return ""
        lines = [f"<{phase}-handoff>"]
        for ctx in contexts:
            lines.append(f"  Agent {ctx.agent_name}: {ctx.short_summary()}")
        lines.append(f"</{phase}-handoff>")
        return "\n".join(lines)

    def get_all_findings_text(self, target: str) -> str:
        lines = []
        for ctx in self._contexts.get(target, []):
            if ctx.findings_summary:
                lines.append(f"[{ctx.agent_name}]: {ctx.findings_summary[:500]}")
        return "\n".join(lines)

    def clear_target(self, target: str):
        self._contexts.pop(target, None)

    def clear_all(self):
        self._contexts.clear()
        self._agent_order.clear()
        self._phase_order.clear()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "contexts": {t: [c.to_dict() for c in clist] for t, clist in self._contexts.items()},
            "agent_order": self._agent_order,
            "phase_order": self._phase_order,
        }

    def save_json(self, path: str):
        with open(path, "w") as f:
            json.dump(self.to_dict(), f, indent=2)

    @classmethod
    def get_instance(cls) -> "HandoffManager":
        if cls._instance is None:
            cls._instance = HandoffManager()
        return cls._instance


_handoff_manager: Optional[HandoffManager] = None


def get_handoff_manager() -> HandoffManager:
    global _handoff_manager
    if _handoff_manager is None:
        _handoff_manager = HandoffManager()
    return _handoff_manager
