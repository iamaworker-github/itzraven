"""
Itzraven Swarm — Stigmergic blackboard architecture.

Pentest-Swarm-AI se inspired: agents coordinate via shared blackboard
with pheromone weights, NOT via central planner. Emergent attack paths.
"""
from itzraven.core.swarm.blackboard import (
    BlackboardEntry, BlackboardQuery, Blackboard,
    MemoryBlackboard, get_blackboard,
)
from itzraven.core.swarm.pheromone import PheromoneConfig, pheromone_weight
from itzraven.core.swarm.trigger import TriggerPredicate, agent_trigger
from itzraven.core.swarm.scheduler import SwarmScheduler, SwarmAgent, get_scheduler

__all__ = [
    "BlackboardEntry", "BlackboardQuery", "Blackboard",
    "MemoryBlackboard", "get_blackboard",
    "PheromoneConfig", "pheromone_weight",
    "TriggerPredicate", "agent_trigger",
    "SwarmScheduler", "SwarmAgent", "get_scheduler",
]
