"""
Stigmergic Blackboard — shared knowledge store.
Agents coordinate by reading/writing findings with pheromone weights.
No central planner. Order emerges from trigger predicates + pheromones.
"""
import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Callable, Set
from collections import defaultdict
from datetime import datetime
from threading import Lock

from itzraven.core.swarm.pheromone import PheromoneConfig, effective_weight, pheromone_weight
from itzraven.core.logger import get_logger

logger = get_logger()


@dataclass
class BlackboardEntry:
    finding_type: str  # PORT_OPEN, TECHNOLOGY, CVE_MATCH, VULNERABILITY, etc.
    agent_name: str
    target: str
    title: str
    data: Dict[str, Any]
    id: str = ""
    pheromone_base: float = 1.0
    half_life_sec: float = 300.0
    created_at: float = field(default_factory=time.time)
    superseded_by: Optional[str] = None
    tags: List[str] = field(default_factory=list)

    @property
    def weight(self) -> float:
        return pheromone_weight(
            base=self.pheromone_base,
            created_at=self.created_at,
            half_life=self.half_life_sec,
        )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "finding_type": self.finding_type,
            "agent_name": self.agent_name,
            "target": self.target,
            "title": self.title,
            "data": self.data,
            "pheromone_base": self.pheromone_base,
            "half_life_sec": self.half_life_sec,
            "created_at": self.created_at,
            "weight": self.weight,
            "superseded_by": self.superseded_by,
            "tags": self.tags,
        }


@dataclass
class BlackboardQuery:
    finding_types: Optional[List[str]] = None
    min_weight: float = 0.05
    target: Optional[str] = None
    agent_name: Optional[str] = None
    tags: Optional[List[str]] = None
    limit: int = 50
    since_id: Optional[str] = None

    def matches(self, entry: BlackboardEntry) -> bool:
        if self.finding_types and entry.finding_type not in self.finding_types:
            return False
        if entry.weight < self.min_weight:
            return False
        if self.target and entry.target != self.target:
            return False
        if self.agent_name and entry.agent_name != self.agent_name:
            return False
        if self.tags and not any(t in entry.tags for t in self.tags):
            return False
        if self.since_id and entry.id <= self.since_id:
            return False
        return True


class Blackboard:
    """Stigmergic blackboard — shared environment state.
    
    Agents write findings (with pheromone weights).
    Agents query by trigger predicate.
    Order emerges from state, not from a central planner.
    """

    def write(self, entry: BlackboardEntry) -> str:
        raise NotImplementedError

    def query(self, q: BlackboardQuery) -> List[BlackboardEntry]:
        raise NotImplementedError

    def subscribe(self, q: BlackboardQuery) -> Any:
        raise NotImplementedError

    def supersede(self, entry_id: str, new_id: str):
        raise NotImplementedError

    def get_stats(self) -> dict:
        raise NotImplementedError


class MemoryBlackboard(Blackboard):
    """In-memory blackboard (for development/single-node).
    
    In production, replace with Postgres+pgvector for durability + vector search.
    """

    def __init__(self):
        self._entries: Dict[str, BlackboardEntry] = {}
        self._by_type: Dict[str, List[str]] = defaultdict(list)
        self._by_target: Dict[str, List[str]] = defaultdict(list)
        self._lock = Lock()
        self._subscribers: List[tuple] = []
        self._write_counter = 0

    def write(self, entry: BlackboardEntry) -> str:
        with self._lock:
            if not entry.id:
                entry.id = f"bb_{uuid.uuid4().hex[:12]}"
            entry.created_at = time.time()
            self._entries[entry.id] = entry
            self._by_type[entry.finding_type].append(entry.id)
            self._by_target[entry.target].append(entry.id)
            self._write_counter += 1

        # Notify subscribers
        for query, callback in self._subscribers:
            if query.matches(entry):
                try:
                    callback(entry)
                except Exception as e:
                    logger.debug(f"Subscriber error: {e}")

        return entry.id

    def query(self, q: BlackboardQuery) -> List[BlackboardEntry]:
        with self._lock:
            candidates = list(self._entries.values())
            # If filtering by type, narrow first
            if q.finding_types:
                candidates = [
                    e for e in candidates
                    if e.finding_type in q.finding_types
                ]
            matched = [e for e in candidates if q.matches(e)]
            matched.sort(key=lambda e: e.weight, reverse=True)
            return matched[:q.limit]

    def subscribe(self, q: BlackboardQuery, callback: Callable[[BlackboardEntry], None]):
        self._subscribers.append((q, callback))

    def supersede(self, entry_id: str, new_id: str):
        with self._lock:
            if entry_id in self._entries:
                self._entries[entry_id].superseded_by = new_id

    def get_entry(self, entry_id: str) -> Optional[BlackboardEntry]:
        with self._lock:
            return self._entries.get(entry_id)

    def get_stats(self) -> dict:
        with self._lock:
            type_counts = defaultdict(int)
            for e in self._entries.values():
                type_counts[e.finding_type] += 1
            return {
                "total_entries": len(self._entries),
                "by_type": dict(type_counts),
                "active_types": list(set(e.finding_type for e in self._entries.values())),
                "targets": list(set(e.target for e in self._entries.values())),
                "total_writes": self._write_counter,
            }

    def get_by_type(self, finding_type: str, min_weight: float = 0.0) -> List[BlackboardEntry]:
        return self.query(BlackboardQuery(
            finding_types=[finding_type],
            min_weight=min_weight,
        ))

    def get_active_findings(self, target: str, min_weight: float = 0.1) -> List[BlackboardEntry]:
        return self.query(BlackboardQuery(
            target=target,
            min_weight=min_weight,
        ))


_instance: Optional[Blackboard] = None


def get_blackboard() -> Blackboard:
    global _instance
    if _instance is None:
        _instance = MemoryBlackboard()
    return _instance
