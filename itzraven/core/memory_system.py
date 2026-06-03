"""
Memory System — Three-tier memory for autonomous agents.

Inspired by PentAGI's memory architecture:
1. Episodic: Recent actions, observations, outcomes (short-term, session-scoped)
2. Working: Current context, goals, open questions, pending actions
3. Long-term: Past sessions, learned patterns, known vulnerabilities (persistent)

All tiers are in-memory with optional JSON persistence for long-term.
"""

import json
import time
from pathlib import Path
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from collections import deque
from datetime import datetime


@dataclass
class MemoryEntry:
    content: str
    entry_type: str  # observation, action, thought, finding, decision, goal
    agent_name: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    importance: float = 1.0  # 0.0 to 1.0 for retrieval prioritization
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "content": self.content,
            "type": self.entry_type,
            "agent": self.agent_name,
            "metadata": self.metadata,
            "timestamp": self.timestamp,
            "importance": self.importance,
            "tags": self.tags,
        }

    def summarize(self, max_len: int = 120) -> str:
        return self.content[:max_len]


class EpisodicMemory:
    """Short-term memory for current session actions/observations (FIFO, max 200)."""

    def __init__(self, max_size: int = 200):
        self._entries: deque = deque(maxlen=max_size)

    def add(self, entry: MemoryEntry):
        self._entries.append(entry)

    def add_observation(self, content: str, agent: str = "", **metadata) -> MemoryEntry:
        e = MemoryEntry(content=content, entry_type="observation", agent_name=agent, metadata=metadata)
        self.add(e)
        return e

    def add_action(self, content: str, agent: str = "", **metadata) -> MemoryEntry:
        e = MemoryEntry(content=content, entry_type="action", agent_name=agent, metadata=metadata)
        self.add(e)
        return e

    def add_thought(self, content: str, agent: str = "", importance: float = 0.5) -> MemoryEntry:
        e = MemoryEntry(content=content, entry_type="thought", agent_name=agent, importance=importance)
        self.add(e)
        return e

    def add_finding(self, title: str, severity: str, agent: str = "") -> MemoryEntry:
        e = MemoryEntry(
            content=f"[{severity.upper()}] {title}",
            entry_type="finding", agent_name=agent,
            importance=1.0 if severity in ("critical", "high") else 0.7,
            tags=[severity, "finding"],
        )
        self.add(e)
        return e

    def get_recent(self, n: int = 10) -> List[MemoryEntry]:
        return list(self._entries)[-n:]

    def get_by_type(self, entry_type: str) -> List[MemoryEntry]:
        return [e for e in self._entries if e.entry_type == entry_type]

    def get_recent_context(self, n: int = 15) -> str:
        entries = self.get_recent(n)
        lines = ["[Episodic Memory - Recent Activity]", ""]
        for e in entries:
            ts = datetime.fromtimestamp(e.timestamp).strftime("%H:%M:%S")
            lines.append(f"  [{ts}] ({e.entry_type}) {e.summarize()}")
        return "\n".join(lines)

    def clear(self):
        self._entries.clear()

    @property
    def count(self) -> int:
        return len(self._entries)

    def to_dict(self) -> list:
        return [e.to_dict() for e in self._entries]


class WorkingMemory:
    """Current session context — goals, open questions, blockers, state."""

    def __init__(self):
        self.goals: List[Dict[str, Any]] = []
        self.open_questions: List[str] = []
        self.blockers: List[str] = []
        self.session_state: Dict[str, Any] = {}
        self.current_focus: str = ""
        self.known_findings: List[str] = []
        self.target_info: Dict[str, Any] = {}

    def set_goal(self, goal: str, priority: str = "medium") -> int:
        idx = len(self.goals)
        self.goals.append({"id": idx, "goal": goal, "priority": priority, "status": "active", "created": time.time()})
        return idx

    def complete_goal(self, goal_id: int):
        for g in self.goals:
            if g["id"] == goal_id:
                g["status"] = "completed"
                break

    def add_open_question(self, question: str):
        if question not in self.open_questions:
            self.open_questions.append(question)

    def answer_question(self, question: str):
        self.open_questions = [q for q in self.open_questions if q != question]

    def add_blocker(self, blocker: str):
        if blocker not in self.blockers:
            self.blockers.append(blocker)

    def resolve_blocker(self, blocker: str):
        self.blockers = [b for b in self.blockers if b != blocker]

    def set_focus(self, focus: str):
        self.current_focus = focus

    def record_finding(self, title: str):
        self.known_findings.append(title)

    def to_context(self) -> str:
        lines = ["[Working Memory - Current State]", ""]
        if self.goals:
            active = [g for g in self.goals if g["status"] == "active"]
            lines.append(f"Active Goals ({len(active)}):")
            for g in active[:5]:
                lines.append(f"  - [{g['priority']}] {g['goal']}")
            lines.append("")
        if self.open_questions:
            lines.append(f"Open Questions ({len(self.open_questions)}):")
            for q in self.open_questions[:5]:
                lines.append(f"  ? {q}")
            lines.append("")
        if self.blockers:
            lines.append(f"Blockers ({len(self.blockers)}):")
            for b in self.blockers[:3]:
                lines.append(f"  ! {b}")
            lines.append("")
        if self.current_focus:
            lines.append(f"Current Focus: {self.current_focus}")
        if self.known_findings:
            lines.append(f"Findings ({len(self.known_findings)}): {', '.join(self.known_findings[-5:])}")
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "goals": self.goals,
            "open_questions": self.open_questions,
            "blockers": self.blockers,
            "session_state": self.session_state,
            "current_focus": self.current_focus,
            "known_findings": self.known_findings,
            "target_info": self.target_info,
        }


class LongTermMemory:
    """Persistent memory across sessions — stored as JSON."""

    def __init__(self, storage_path: str = ""):
        self._storage_path = storage_path or str(Path.home() / ".itzraven" / "memory" / "long_term.json")
        self._sessions: Dict[str, List[MemoryEntry]] = {}
        self._patterns: Dict[str, Any] = {}
        self._target_history: Dict[str, List[Dict[str, Any]]] = {}
        self._load()

    def store_session(self, session_id: str, entries: List[MemoryEntry]):
        self._sessions[session_id] = entries[-100:]  # keep last 100
        self._save()

    def get_session(self, session_id: str) -> List[MemoryEntry]:
        return self._sessions.get(session_id, [])

    def get_recent_sessions(self, n: int = 5) -> Dict[str, List[MemoryEntry]]:
        all_sessions = list(self._sessions.items())
        return dict(all_sessions[-n:])

    def record_target(self, target: str, metadata: Dict[str, Any]):
        if target not in self._target_history:
            self._target_history[target] = []
        self._target_history[target].append({**metadata, "timestamp": time.time()})
        self._save()

    def get_target_history(self, target: str) -> List[Dict[str, Any]]:
        return self._target_history.get(target, [])

    def learn_pattern(self, pattern_key: str, pattern_data: Any):
        self._patterns[pattern_key] = {
            "data": pattern_data,
            "timestamp": time.time(),
            "count": self._patterns.get(pattern_key, {}).get("count", 0) + 1,
        }
        self._save()

    def get_pattern(self, pattern_key: str) -> Optional[Any]:
        p = self._patterns.get(pattern_key)
        return p["data"] if p else None

    def get_all_findings(self) -> List[str]:
        """Aggregate all findings across all sessions."""
        findings = []
        for entries in self._sessions.values():
            for e in entries:
                if e.entry_type == "finding" and e.content not in findings:
                    findings.append(e.content)
        return findings

    def search(self, query: str) -> List[Dict[str, Any]]:
        results = []
        q = query.lower()
        for sid, entries in self._sessions.items():
            for e in entries:
                if q in e.content.lower():
                    results.append({
                        "session": sid,
                        "content": e.content,
                        "type": e.entry_type,
                        "timestamp": e.timestamp,
                    })
        return results[:20]

    def _load(self):
        try:
            path = Path(self._storage_path)
            if path.exists():
                data = json.loads(path.read_text())
                self._sessions = {k: [MemoryEntry(**e) for e in v] for k, v in data.get("sessions", {}).items()}
                self._patterns = data.get("patterns", {})
                self._target_history = data.get("targets", {})
        except Exception:
            pass

    def _save(self):
        try:
            path = Path(self._storage_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            data = {
                "sessions": {k: [e.to_dict() for e in v] for k, v in self._sessions.items()},
                "patterns": self._patterns,
                "targets": self._target_history,
            }
            path.write_text(json.dumps(data, indent=2))
        except Exception:
            pass


class MemorySystem:
    """Unified memory system combining all three tiers."""

    def __init__(self, storage_path: str = ""):
        self.episodic = EpisodicMemory()
        self.working = WorkingMemory()
        self.long_term = LongTermMemory(storage_path)
        self._session_id: str = ""

    def start_session(self, session_id: str):
        self._session_id = session_id
        self.episodic.clear()
        self.working = WorkingMemory()

    def end_session(self):
        if self._session_id:
            self.long_term.store_session(self._session_id, list(self.episodic._entries))

    def observe(self, content: str, agent: str = "", **metadata) -> MemoryEntry:
        return self.episodic.add_observation(content, agent, **metadata)

    def act(self, content: str, agent: str = "", **metadata) -> MemoryEntry:
        return self.episodic.add_action(content, agent, **metadata)

    def think(self, content: str, agent: str = "", importance: float = 0.5) -> MemoryEntry:
        return self.episodic.add_thought(content, agent, importance)

    def add_finding(self, title: str, severity: str, agent: str = "") -> MemoryEntry:
        entry = self.episodic.add_finding(title, severity, agent)
        self.working.record_finding(title)
        return entry

    def get_context(self) -> str:
        parts = [
            self.episodic.get_recent_context(12),
            "",
            self.working.to_context(),
        ]
        return "\n".join(parts)

    def get_episodic_context(self, n: int = 10) -> str:
        return self.episodic.get_recent_context(n)

    def get_working_context(self) -> str:
        return self.working.to_context()

    def to_dict(self) -> dict:
        return {
            "episodic": self.episodic.to_dict(),
            "working": self.working.to_dict(),
            "session_id": self._session_id,
        }


_memory_system: Optional[MemorySystem] = None


def get_memory_system(storage_path: str = "") -> MemorySystem:
    global _memory_system
    if _memory_system is None:
        _memory_system = MemorySystem(storage_path)
    return _memory_system


def set_memory_system(ms: MemorySystem) -> None:
    global _memory_system
    _memory_system = ms
