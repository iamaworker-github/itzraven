"""
MCTS Planner — Monte Carlo Tree Search for optimal attack path selection.

When multiple attack vectors exist (SQLi, XSS, SSRF, etc.),
MCTS explores the most promising ones first, allocating more
resources to high-confidence paths.
"""

import math
import time
import random
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from collections import defaultdict

from itzraven.core.logger import get_logger

logger = get_logger()


@dataclass
class MCTSNode:
    name: str
    technique: str
    visits: int = 0
    wins: float = 0.0
    parent: Optional["MCTSNode"] = None
    children: List["MCTSNode"] = field(default_factory=list)
    exploration_constant: float = 1.4

    @property
    def win_rate(self) -> float:
        return self.wins / max(self.visits, 1)

    @property
    def ucb1(self) -> float:
        if self.visits == 0:
            return float("inf")
        exploitation = self.win_rate
        exploration = self.exploration_constant * math.sqrt(
            math.log(max(self.parent.visits, 1)) / self.visits
        )
        return exploitation + exploration

    def best_child(self) -> Optional["MCTSNode"]:
        if not self.children:
            return None
        return max(self.children, key=lambda c: c.ucb1)

    def add_child(self, name: str, technique: str) -> "MCTSNode":
        child = MCTSNode(name=name, technique=technique, parent=self)
        self.children.append(child)
        return child

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "technique": self.technique,
            "visits": self.visits,
            "wins": self.wins,
            "win_rate": round(self.win_rate, 3),
            "children": [c.name for c in self.children],
        }


class MCTSPlanner:
    _instance = None

    def __init__(self):
        self.root: Optional[MCTSNode] = None
        self.max_iterations: int = 30
        self.results: Dict[str, float] = {}

    @classmethod
    def get_instance(cls) -> "MCTSPlanner":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def plan(self, technique_reliabilities: Dict[str, float],
             max_iterations: int = 30) -> List[Dict[str, Any]]:
        self.max_iterations = max_iterations
        self.root = MCTSNode(name="root", technique="root")

        for technique, reliability in technique_reliabilities.items():
            initial_wins = reliability * 2
            initial_visits = 2
            child = self.root.add_child(name=technique, technique=technique)
            child.wins = initial_wins
            child.visits = initial_visits

        for _ in range(max_iterations):
            node = self._select(self.root)
            if node is None:
                continue
            result = self._simulate(node)
            self._backpropagate(node, result)

        rankings = sorted(
            self.root.children,
            key=lambda c: c.win_rate * math.sqrt(c.visits),
            reverse=True,
        )

        ordered = []
        for rank, child in enumerate(rankings):
            ordered.append({
                "technique": child.technique,
                "priority": rank + 1,
                "confidence": round(child.win_rate, 3),
                "visits": child.visits,
                "recommended": child.win_rate >= 0.3,
            })
            self.results[child.technique] = child.win_rate

        logger.debug(f"MCTS: {len(ordered)} techniques ranked, top={ordered[0]['technique'] if ordered else 'none'}")
        return ordered

    def _select(self, node: MCTSNode) -> Optional[MCTSNode]:
        current = node
        depth = 0
        while current.children and depth < 10:
            best = current.best_child()
            if best is None:
                return current
            current = best
            depth += 1
        return current

    def _simulate(self, node: MCTSNode) -> float:
        return node.win_rate + random.uniform(-0.1, 0.1)

    def _backpropagate(self, node: MCTSNode, result: float):
        current = node
        while current:
            current.visits += 1
            current.wins += result
            current = current.parent

    def get_best_technique(self) -> Optional[str]:
        if not self.root or not self.root.children:
            return None
        return max(self.root.children, key=lambda c: c.win_rate * math.sqrt(c.visits)).technique

    def get_priority(self, technique: str) -> float:
        return self.results.get(technique, 0.5)

    def record_outcome(self, technique: str, success: bool):
        for child in (self.root.children if self.root else []):
            if child.technique == technique:
                child.wins += 1.0 if success else 0.0
                child.visits += 1
                break


get_mcts_planner = MCTSPlanner.get_instance
