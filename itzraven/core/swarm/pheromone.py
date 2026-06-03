"""
Pheromone System — per-finding-type decay with configurable half-lives.
Inspired by Pentest-Swarm-AI: pheromone weight decays over time,
stale paths die naturally, exploration bias tunes aggression.
"""
import math
import time
from dataclasses import dataclass, field
from typing import Dict, Optional


@dataclass
class PheromoneConfig:
    base_weight: float = 1.0
    half_life_seconds: float = 300.0  # 5 min default
    min_threshold: float = 0.05
    exploration_bias: float = 1.0  # 0.5=conservative, 1.0=balanced, 2.0=aggressive

    @classmethod
    def for_finding_type(cls, finding_type: str) -> "PheromoneConfig":
        half_lives = {
            "PORT_OPEN": 600.0,
            "TECHNOLOGY": 900.0,
            "SUBDOMAIN": 1200.0,
            "HTTP_ENDPOINT": 600.0,
            "CVE_MATCH": 3600.0,
            "VULNERABILITY": 3600.0,
            "EXPLOIT_CHAIN": 7200.0,
            "EXPLOIT_RESULT": 1800.0,
            "SESSION": 120.0,
            "WAF_DETECTED": 300.0,
            "MISCONFIGURATION": 1800.0,
            "INFO": 300.0,
        }
        return cls(half_life_seconds=half_lives.get(finding_type, 300.0))

    @classmethod
    def from_bias(cls, bias: str) -> "PheromoneConfig":
        bias_map = {
            "low": 0.5,
            "med": 1.0,
            "high": 2.0,
        }
        return cls(exploration_bias=bias_map.get(bias, 1.0))


def pheromone_weight(base: float, created_at: float, half_life: float, bias: float = 1.0) -> float:
    """Calculate current pheromone weight with time decay.
    
    Formula: w(t) = base * bias * 2^(-t/half_life)
    - base: initial weight (0-1)
    - t: time elapsed since creation
    - half_life: time for weight to halve
    - bias: exploration multiplier
    """
    elapsed = time.time() - created_at
    if elapsed < 0:
        return base * bias
    decay = math.pow(2, -elapsed / max(half_life, 1.0))
    return min(1.0, base * bias * decay)


def effective_weight(entry: "BlackboardEntry", config: Optional[PheromoneConfig] = None) -> float:
    """Get effective pheromone weight considering decay."""
    cfg = config or PheromoneConfig.for_finding_type(entry.finding_type)
    return pheromone_weight(
        base=entry.pheromone_base,
        created_at=entry.created_at,
        half_life=cfg.half_life_seconds,
        bias=cfg.exploration_bias,
    )
