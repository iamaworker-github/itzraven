"""
Stigmergic Blackboard — shared state for agent coordination.

Inspired by Pentest-Swarm-AI's stigmergy approach:
- Agents coordinate by reading/writing to a shared blackboard
- Each finding has a pheromone weight that decays over time
- High-pheromone findings attract more agents
- Stale paths die naturally via decay
"""

import math
import time
from typing import Any, Dict, List, Optional, Set, Callable
from dataclasses import dataclass, field
from enum import Enum
from itzraven.core.logger import get_logger

logger = get_logger()


class FindingCategory(Enum):
    TARGET_REG = "target_reg"
    SUBDOMAIN = "subdomain"
    PORT_OPEN = "port_open"
    HTTP_ENDPOINT = "http_endpoint"
    TECHNOLOGY = "technology"
    CVE_MATCH = "cve_match"
    MISCONFIGURATION = "misconfiguration"
    EXPLOIT_CHAIN = "exploit_chain"
    EXPLOIT_RESULT = "exploit_result"
    SESSION = "session"
    CREDENTIAL = "credential"
    FLAG = "flag"
    OSINT_LEAD = "osint_lead"
    CAMPAIGN_COMPLETE = "campaign_complete"


PHEROMONE_HALF_LIFE: Dict[FindingCategory, float] = {
    FindingCategory.PORT_OPEN: 1800,
    FindingCategory.SUBDOMAIN: 3600,
    FindingCategory.TECHNOLOGY: 3600,
    FindingCategory.CVE_MATCH: 7200,
    FindingCategory.EXPLOIT_CHAIN: 3600,
    FindingCategory.EXPLOIT_RESULT: 1800,
    FindingCategory.SESSION: 300,
    FindingCategory.CREDENTIAL: 7200,
    FindingCategory.FLAG: 999999,
    FindingCategory.OSINT_LEAD: 3600,
    FindingCategory.HTTP_ENDPOINT: 1800,
    FindingCategory.MISCONFIGURATION: 3600,
    FindingCategory.TARGET_REG: 999999,
    FindingCategory.CAMPAIGN_COMPLETE: 999999,
}


@dataclass
class BlackboardEntry:
    category: FindingCategory
    key: str
    data: Dict[str, Any]
    pheromone: float = 1.0
    timestamp: float = field(default_factory=time.time)
    source_agent: str = ""
    entry_id: str = ""
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def age(self) -> float:
        return time.time() - self.timestamp

    @property
    def decayed_pheromone(self) -> float:
        half_life = PHEROMONE_HALF_LIFE.get(self.category, 1800)
        if half_life >= 999999:
            return self.pheromone
        decay = math.pow(0.5, self.age / half_life)
        return self.pheromone * decay

    def is_hot(self, threshold: float = 0.3) -> bool:
        return self.decayed_pheromone >= threshold

    def reinforce(self, amount: float = 0.3) -> None:
        self.pheromone = min(2.0, self.pheromone + amount)
        self.timestamp = time.time()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "category": self.category.value,
            "key": self.key,
            "data": self.data,
            "pheromone": round(self.pheromone, 3),
            "decayed_pheromone": round(self.decayed_pheromone, 3),
            "age": round(self.age, 1),
            "hot": self.is_hot(),
            "source_agent": self.source_agent,
            "tags": self.tags,
        }


class Blackboard:
    def __init__(self, decay_interval: float = 60.0):
        self._entries: Dict[str, BlackboardEntry] = {}
        self._subscribers: Dict[str, List[Callable]] = {}
        self._decay_interval = decay_interval
        self._last_decay = time.time()

    def post(
        self,
        category: FindingCategory,
        key: str,
        data: Dict[str, Any],
        source_agent: str = "",
        pheromone: float = 1.0,
        tags: Optional[List[str]] = None,
    ) -> BlackboardEntry:
        if key in self._entries:
            existing = self._entries[key]
            existing.data.update(data)
            existing.reinforce(pheromone * 0.3)
            existing.source_agent = source_agent
            if tags:
                existing.tags.extend(t for t in tags if t not in existing.tags)
            self._notify("updated", existing)
            return existing

        entry = BlackboardEntry(
            category=category,
            key=key,
            data=data,
            pheromone=pheromone,
            source_agent=source_agent,
            entry_id=key,
            tags=tags or [],
        )
        self._entries[key] = entry
        self._notify("new", entry)
        logger.debug(f"Blackboard: [{category.value}] {key} (pheromone={pheromone})")
        return entry

    def get(self, key: str) -> Optional[BlackboardEntry]:
        return self._entries.get(key)

    def query(
        self,
        category: Optional[FindingCategory] = None,
        min_pheromone: float = 0.0,
        tags: Optional[List[str]] = None,
        hot_only: bool = False,
        limit: int = 100,
    ) -> List[BlackboardEntry]:
        results = []
        for entry in self._entries.values():
            if category and entry.category != category:
                continue
            if hot_only and not entry.is_hot():
                continue
            if entry.decayed_pheromone < min_pheromone:
                continue
            if tags and not any(t in entry.tags for t in tags):
                continue
            results.append(entry)

        results.sort(key=lambda e: e.decayed_pheromone, reverse=True)
        return results[:limit]

    def get_hot_findings(self, threshold: float = 0.3, limit: int = 50) -> List[BlackboardEntry]:
        return [e for e in self.query(min_pheromone=threshold, limit=limit) if e.is_hot(threshold)]

    def get_by_category(self, category: FindingCategory, hot_only: bool = False) -> List[BlackboardEntry]:
        return self.query(category=category, hot_only=hot_only)

    def decay(self, force: bool = False) -> int:
        now = time.time()
        if not force and (now - self._last_decay) < self._decay_interval:
            return 0
        self._last_decay = now
        before = len(self._entries)
        to_remove = [k for k, e in self._entries.items() if e.decayed_pheromone < 0.01]
        for k in to_remove:
            entry = self._entries.pop(k)
            self._notify("decayed", entry)
        removed = before - len(self._entries)
        if removed:
            logger.debug(f"Blackboard: decayed {removed} stale entries")
        return removed

    def reinforce(self, key: str, amount: float = 0.3) -> Optional[BlackboardEntry]:
        entry = self._entries.get(key)
        if entry:
            entry.reinforce(amount)
            self._notify("reinforced", entry)
        return entry

    def clear(self) -> None:
        self._entries.clear()
        logger.info("Blackboard cleared")

    @property
    def entry_count(self) -> int:
        return len(self._entries)

    @property
    def hot_count(self) -> int:
        return sum(1 for e in self._entries.values() if e.is_hot())

    def get_stats(self) -> Dict[str, Any]:
        cat_counts: Dict[str, int] = {}
        for entry in self._entries.values():
            cat = entry.category.value
            cat_counts[cat] = cat_counts.get(cat, 0) + 1
        return {
            "total_entries": self.entry_count,
            "hot_entries": self.hot_count,
            "categories": cat_counts,
            "last_decay": self._last_decay,
        }

    def get_context_for_agent(self, agent_name: str, max_entries: int = 20) -> str:
        """Get formatted context string from blackboard for an agent.

        Other agents' hot findings are formatted as context that can be
        injected into prompts. This enables inter-agent context sharing.
        """
        entries = self.query(min_pheromone=0.2, limit=max_entries)
        lines = [f"[Blackboard Context for {agent_name}]"]
        lines.append(f"Hot entries: {self.hot_count}/{self.entry_count}")
        lines.append("")

        for entry in entries:
            if entry.source_agent == agent_name:
                continue
            cat = entry.category.value
            data_preview = str(entry.data.get("description", "") or entry.data.get("url", "") or entry.key)[:100]
            lines.append(f"  [{cat}] from {entry.source_agent}: {data_preview}")

        return "\n".join(lines)

    def subscribe(self, event_type: str, handler: Callable) -> None:
        if event_type not in self._subscribers:
            self._subscribers[event_type] = []
        self._subscribers[event_type].append(handler)

    def _notify(self, event_type: str, entry: BlackboardEntry) -> None:
        for handler in self._subscribers.get(event_type, []):
            try:
                handler(entry)
            except Exception as e:
                logger.debug(f"Blackboard subscriber error: {e}")


_blackboard: Optional[Blackboard] = None


def get_blackboard() -> Blackboard:
    global _blackboard
    if _blackboard is None:
        _blackboard = Blackboard()
    return _blackboard


def set_blackboard(bb: Blackboard) -> None:
    global _blackboard
    _blackboard = bb
