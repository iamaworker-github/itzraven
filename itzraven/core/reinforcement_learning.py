"""
Reinforcement Learning Engine — scan outcomes se learn kare.
Uses epsilon-greedy exploration + Q-learning style updates.
"""

import json
import math
import random
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field

from itzraven.core.logger import get_logger

logger = get_logger()

RL_STORE = Path.home() / ".itzraven" / "reinforcement_learning.json"


@dataclass
class StateAction:
    state: str
    action: str
    q_value: float = 0.0
    visits: int = 0
    rewards: List[float] = field(default_factory=list)

    def update(self, reward: float, alpha: float = 0.1, gamma: float = 0.9):
        self.visits += 1
        self.rewards.append(reward)
        old_q = self.q_value
        self.q_value = old_q + alpha * (reward + gamma * self.q_value - old_q)

    @property
    def avg_reward(self) -> float:
        return sum(self.rewards) / max(len(self.rewards), 1)


@dataclass
class RLState:
    target_tech: str
    open_ports: str
    has_waf: bool
    previous_findings: int
    scan_depth: str

    def to_key(self) -> str:
        return f"{self.target_tech}|{self.open_ports}|{self.has_waf}|{min(self.previous_findings, 10)}|{self.scan_depth}"


class ReinforcementLearningEngine:
    _instance = None

    def __init__(self, epsilon: float = 0.2, alpha: float = 0.1, gamma: float = 0.9):
        self.epsilon = epsilon
        self.alpha = alpha
        self.gamma = gamma
        self.q_table: Dict[str, Dict[str, StateAction]] = {}
        self._episode_count = 0
        self._total_reward = 0.0
        self._load()

    @classmethod
    def get_instance(cls) -> "ReinforcementLearningEngine":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def get_action(self, state: RLState, available_actions: List[str]) -> str:
        state_key = state.to_key()
        if state_key not in self.q_table:
            self.q_table[state_key] = {}

        q_state = self.q_table[state_key]

        for action in available_actions:
            if action not in q_state:
                q_state[action] = StateAction(state=state_key, action=action)

        if random.random() < self.epsilon:
            return random.choice(available_actions)

        best_action = max(available_actions, key=lambda a: q_state.get(a, StateAction(state_key, a)).q_value)
        return best_action

    def update(self, state: RLState, action: str, reward: float):
        state_key = state.to_key()
        if state_key not in self.q_table:
            self.q_table[state_key] = {}

        if action not in self.q_table[state_key]:
            self.q_table[state_key][action] = StateAction(state=state_key, action=action)

        self.q_table[state_key][action].update(reward, self.alpha, self.gamma)
        self._total_reward += reward

    def record_scan_outcome(self, target_tech: str, ports: List[int],
                            has_waf: bool, findings_count: int,
                            technique: str, success: bool, scan_depth: str = "standard"):
        port_str = ",".join(str(p) for p in sorted(ports)[:5]) or "unknown"
        state = RLState(
            target_tech=target_tech,
            open_ports=port_str,
            has_waf=has_waf,
            previous_findings=findings_count,
            scan_depth=scan_depth,
        )
        reward = 1.0 if success else -0.5
        if findings_count > 0:
            reward += 0.3 * min(findings_count, 5)

        self.update(state, technique, reward)
        self._episode_count += 1
        self._save()

    def get_best_action(self, state: RLState) -> Optional[Tuple[str, float]]:
        state_key = state.to_key()
        q_state = self.q_table.get(state_key, {})
        if not q_state:
            return None
        best = max(q_state.items(), key=lambda x: x[1].q_value)
        return (best[0], best[1].q_value)

    def get_top_actions(self, state: RLState, top_k: int = 3) -> List[Tuple[str, float]]:
        state_key = state.to_key()
        q_state = self.q_table.get(state_key, {})
        sorted_actions = sorted(q_state.items(), key=lambda x: x[1].q_value, reverse=True)
        return [(a, sa.q_value) for a, sa in sorted_actions[:top_k]]

    def get_stats(self) -> dict:
        total_states = len(self.q_table)
        total_actions = sum(len(actions) for actions in self.q_table.values())
        return {
            "total_states": total_states,
            "total_actions": total_actions,
            "episodes": self._episode_count,
            "total_reward": round(self._total_reward, 2),
            "avg_reward_per_episode": round(self._total_reward / max(self._episode_count, 1), 3),
            "epsilon": self.epsilon,
            "alpha": self.alpha,
            "gamma": self.gamma,
            "top_states": sorted(
                [(k, len(v)) for k, v in self.q_table.items()],
                key=lambda x: x[1], reverse=True,
            )[:10],
        }

    def _save(self):
        RL_STORE.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "epsilon": self.epsilon,
            "alpha": self.alpha,
            "gamma": self.gamma,
            "episode_count": self._episode_count,
            "total_reward": self._total_reward,
            "q_table": {
                state: {
                    action: {"q_value": sa.q_value, "visits": sa.visits, "rewards": sa.rewards[-20:]}
                    for action, sa in actions.items()
                }
                for state, actions in self.q_table.items()
            },
        }
        RL_STORE.write_text(json.dumps(data, indent=2))

    def _load(self):
        try:
            if RL_STORE.exists():
                data = json.loads(RL_STORE.read_text())
                self.epsilon = data.get("epsilon", 0.2)
                self.alpha = data.get("alpha", 0.1)
                self.gamma = data.get("gamma", 0.9)
                self._episode_count = data.get("episode_count", 0)
                self._total_reward = data.get("total_reward", 0.0)
                for state, actions in data.get("q_table", {}).items():
                    self.q_table[state] = {}
                    for action, sa_data in actions.items():
                        sa = StateAction(state=state, action=action)
                        sa.q_value = sa_data.get("q_value", 0.0)
                        sa.visits = sa_data.get("visits", 0)
                        sa.rewards = sa_data.get("rewards", [])
                        self.q_table[state][action] = sa
                logger.info(f"RL: loaded {sum(len(v) for v in self.q_table.values())} actions across {len(self.q_table)} states")
        except Exception as e:
            logger.debug(f"Failed to load RL data: {e}")


get_rl_engine = ReinforcementLearningEngine.get_instance
