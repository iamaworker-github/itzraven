"""
Thinking Block Chaining — persist reasoning across agent steps.

Strix v0.6.0 inspired: Thinking blocks are preserved and chained across
agent steps, so agents can reuse prior reasoning instead of re-deriving
context every time.

Architecture:
  - ThinkingChain: ordered list of thinking blocks from all agents
  - Each block: agent_name, thought, phase, timestamp
  - Chained into next agent's context for continuity
  - Persisted to disk for resilience
"""

import json
import time
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field

from itzraven.core.logger import get_logger

logger = get_logger()


@dataclass
class ThinkingBlock:
    agent_name: str
    thought: str
    thought_type: str = "reasoning"
    phase: str = ""
    timestamp: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "agent_name": self.agent_name,
            "thought": self.thought,
            "thought_type": self.thought_type,
            "phase": self.phase,
            "timestamp": self.timestamp,
        }

    def summarize(self, max_length: int = 150) -> str:
        thought_trimmed = self.thought[:max_length]
        return f"[{self.agent_name}] ({self.thought_type}) {thought_trimmed}"


class ThinkingChain:
    def __init__(self, max_blocks: int = 100):
        self._blocks: List[ThinkingBlock] = []
        self._max_blocks = max_blocks

    def add_block(
        self,
        agent_name: str,
        thought: str,
        thought_type: str = "reasoning",
        phase: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> ThinkingBlock:
        block = ThinkingBlock(
            agent_name=agent_name,
            thought=thought,
            thought_type=thought_type,
            phase=phase,
            metadata=metadata or {},
        )
        self._blocks.append(block)
        if len(self._blocks) > self._max_blocks:
            self._blocks.pop(0)
        return block

    def get_chain(self, max_blocks: int = 20) -> List[ThinkingBlock]:
        return self._blocks[-max_blocks:]

    def get_context_for_agent(self, agent_name: str, max_blocks: int = 10) -> str:
        recent = self._blocks[-max_blocks:]
        lines = ["[Thinking Chain Context]", ""]
        for block in recent:
            if block.agent_name != agent_name:
                lines.append(f"  {block.summarize()}")
        return "\n".join(lines)

    def get_chain_by_phase(self, phase: str) -> List[ThinkingBlock]:
        return [b for b in self._blocks if b.phase == phase]

    def get_chain_for_agent(self, agent_name: str) -> List[ThinkingBlock]:
        return [b for b in self._blocks if b.agent_name == agent_name]

    def clear(self):
        self._blocks.clear()

    @property
    def count(self) -> int:
        return len(self._blocks)

    def persist(self, filepath: str):
        data = [b.to_dict() for b in self._blocks]
        Path(filepath).parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2)

    @classmethod
    def load(cls, filepath: str) -> "ThinkingChain":
        chain = cls()
        try:
            with open(filepath) as f:
                data = json.load(f)
            for item in data:
                chain._blocks.append(ThinkingBlock(**item))
            logger.info(f"Loaded {len(chain._blocks)} thinking blocks from {filepath}")
        except Exception:
            pass
        return chain


_thinking_chain: Optional[ThinkingChain] = None


def get_thinking_chain() -> ThinkingChain:
    global _thinking_chain
    if _thinking_chain is None:
        _thinking_chain = ThinkingChain()
    return _thinking_chain
