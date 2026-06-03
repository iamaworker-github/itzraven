"""
AttackSurfaceManager — global attack surface tracking for agent coordination.

XBOW-inspired: maintains a live view of what's been explored, what's remaining,
and coordinates agent activities by prioritizing unexplored paths.
"""

import time
import math
from typing import Any, Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict

from itzraven.core.logger import get_logger
from itzraven.core.blackboard import Blackboard, FindingCategory, get_blackboard

logger = get_logger()


class SurfaceCategory(Enum):
    DOMAIN = "domain"
    IP_RANGE = "ip_range"
    PORT = "port"
    ENDPOINT = "endpoint"
    PARAMETER = "parameter"
    AUTH_MECHANISM = "auth_mechanism"
    TECHNOLOGY = "technology"
    SUBDOMAIN = "subdomain"
    API_ROUTE = "api_route"
    CLOUD_ASSET = "cloud_asset"


@dataclass
class SurfaceEntry:
    category: SurfaceCategory
    value: str
    discovered_at: float = field(default_factory=time.time)
    last_checked: float = field(default_factory=time.time)
    checked_count: int = 0
    status: str = "pending"
    priority: float = 0.5
    tags: List[str] = field(default_factory=list)
    parent: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def age_seconds(self) -> float:
        return time.time() - self.last_checked

    def to_dict(self) -> Dict[str, Any]:
        return {
            "category": self.category.value,
            "value": self.value,
            "status": self.status,
            "priority": round(self.priority, 2),
            "checked_count": self.checked_count,
            "age_seconds": round(self.age_seconds, 1),
            "tags": self.tags,
            "parent": self.parent,
        }


class AttackSurfaceManager:
    def __init__(self, target: str, blackboard: Optional[Blackboard] = None):
        self.target = target
        self._bb = blackboard or get_blackboard()
        self._entries: Dict[str, SurfaceEntry] = {}
        self._categories: Dict[SurfaceCategory, Set[str]] = defaultdict(set)
        self._dependency_graph: Dict[str, List[str]] = defaultdict(list)
        self._explored_paths: Set[str] = set()
        self._discovery_order: List[str] = []

    def register(
        self,
        category: SurfaceCategory,
        value: str,
        priority: float = 0.5,
        tags: Optional[List[str]] = None,
        parent: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        key = f"{category.value}:{value}"
        if key in self._entries:
            existing = self._entries[key]
            existing.last_checked = time.time()
            existing.checked_count += 1
            existing.priority = max(existing.priority, priority)
            return key

        entry = SurfaceEntry(
            category=category,
            value=value,
            priority=priority,
            tags=tags or [],
            parent=parent,
            metadata=metadata or {},
        )
        self._entries[key] = entry
        self._categories[category].add(key)
        self._discovery_order.append(key)

        if parent:
            self._dependency_graph[parent].append(key)

        cat_map = {
            SurfaceCategory.DOMAIN: FindingCategory.TARGET_REG,
            SurfaceCategory.SUBDOMAIN: FindingCategory.SUBDOMAIN,
            SurfaceCategory.PORT: FindingCategory.PORT_OPEN,
            SurfaceCategory.ENDPOINT: FindingCategory.HTTP_ENDPOINT,
            SurfaceCategory.TECHNOLOGY: FindingCategory.TECHNOLOGY,
        }
        bb_cat = cat_map.get(category, FindingCategory.TARGET_REG)
        self._bb.post(
            category=bb_cat,
            key=f"surface:{key}",
            data={
                "category": category.value,
                "value": value,
                "priority": priority,
                "status": "pending",
                "parent": parent or "",
            },
            source_agent="AttackSurfaceManager",
            pheromone=priority,
            tags=tags or [],
        )

        logger.debug(f"Surface registered: [{category.value}] {value}")
        return key

    def mark_checked(self, key: str, success: bool = True):
        entry = self._entries.get(key)
        if not entry:
            return
        entry.last_checked = time.time()
        entry.checked_count += 1
        if success:
            entry.status = "explored"
            self._explored_paths.add(key)
        else:
            entry.status = "failed"

    def get_pending(
        self,
        max_results: int = 20,
        min_priority: float = 0.0,
    ) -> List[SurfaceEntry]:
        candidates = [
            e for e in self._entries.values()
            if e.status == "pending" and e.priority >= min_priority
        ]
        candidates.sort(key=lambda e: (e.priority, -e.age_seconds), reverse=True)
        return candidates[:max_results]

    def get_unexplored(
        self,
        category: Optional[SurfaceCategory] = None,
        max_results: int = 20,
    ) -> List[SurfaceEntry]:
        if category:
            keys = self._categories.get(category, set())
            candidates = [
                self._entries[k] for k in keys
                if self._entries[k].status == "pending"
            ]
        else:
            candidates = [
                e for e in self._entries.values() if e.status == "pending"
            ]
        candidates.sort(key=lambda e: (e.priority, -e.age_seconds), reverse=True)
        return candidates[:max_results]

    def get_next_attack_path(self) -> Optional[SurfaceEntry]:
        pending = self.get_pending(min_priority=0.3)
        if not pending:
            return None

        for entry in pending:
            if entry.parent and entry.parent in self._explored_paths:
                return entry

        return pending[0]

    def get_priority_surface(
        self, category: Optional[SurfaceCategory] = None
    ) -> List[Dict[str, Any]]:
        if category:
            keys = self._categories.get(category, set())
            entries = [self._entries[k] for k in keys]
        else:
            entries = list(self._entries.values())
        entries.sort(key=lambda e: e.priority, reverse=True)
        return [e.to_dict() for e in entries[:30]]

    def get_attack_graph(
        self, depth: int = 3
    ) -> Dict[str, Any]:
        nodes = []
        edges = []
        for key, entry in self._entries.items():
            nodes.append({
                "id": key,
                "label": entry.value,
                "category": entry.category.value,
                "status": entry.status,
                "priority": entry.priority,
            })
            if entry.parent:
                edges.append({
                    "source": entry.parent,
                    "target": key,
                    "relation": "discovers",
                })
        return {"nodes": nodes, "edges": edges}

    def get_coverage_stats(self) -> Dict[str, Any]:
        stats = {}
        for cat in SurfaceCategory:
            keys = self._categories.get(cat, set())
            total = len(keys)
            explored = sum(1 for k in keys if self._entries[k].status == "explored")
            pending = total - explored
            if total > 0:
                stats[cat.value] = {
                    "total": total,
                    "explored": explored,
                    "pending": pending,
                    "coverage_pct": round(explored / total * 100, 1),
                }
        return stats

    def get_summary(self) -> Dict[str, Any]:
        total = len(self._entries)
        explored = len(self._explored_paths)
        return {
            "target": self.target,
            "total_surface": total,
            "explored": explored,
            "pending": total - explored,
            "coverage_pct": round(explored / max(total, 1) * 100, 1),
            "categories": {
                cat.value: len(keys)
                for cat, keys in self._categories.items()
            },
            "discovery_order_count": len(self._discovery_order),
        }


_surface_managers: Dict[str, AttackSurfaceManager] = {}


def get_attack_surface(target: str) -> AttackSurfaceManager:
    if target not in _surface_managers:
        _surface_managers[target] = AttackSurfaceManager(target=target)
    return _surface_managers[target]
