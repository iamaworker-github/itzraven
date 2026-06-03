"""
Trigger Predicates — each agent ka trigger rule.
Agent tab chalega jab blackboard pe relevant state aayega.
"""
from dataclasses import dataclass, field
from typing import List, Optional, Callable, Any
from enum import Enum

from itzraven.core.swarm.blackboard import BlackboardEntry, BlackboardQuery, get_blackboard


class TriggerAction(Enum):
    CONTINUE = "continue"
    SHIFT = "shift"
    DEEP_DIVE = "deep_dive"
    ABORT = "abort"


@dataclass
class TriggerPredicate:
    """Agent trigger rule — kab agent ko wake karna hai."""
    finding_types: Optional[List[str]] = None
    min_pheromone: float = 0.2
    target: Optional[str] = None
    max_invocations: int = 10
    cooldown_seconds: float = 10.0
    custom_check: Optional[Callable[[BlackboardEntry], bool]] = None

    def should_trigger(self, entry: BlackboardEntry) -> bool:
        if self.finding_types and entry.finding_type not in self.finding_types:
            return False
        if entry.weight < self.min_pheromone:
            return False
        if self.target and entry.target != self.target:
            return False
        if self.custom_check and not self.custom_check(entry):
            return False
        return True

    def to_query(self) -> BlackboardQuery:
        return BlackboardQuery(
            finding_types=self.finding_types,
            min_weight=self.min_pheromone,
            target=self.target,
        )


@dataclass
class TriggerRule:
    name: str
    predicate: TriggerPredicate
    priority: int = 5
    description: str = ""


# Pre-built triggers for common agent types
RECON_TRIGGER = TriggerPredicate(
    finding_types=["TARGET_REGISTERED"],
    min_pheromone=0.8,
)

TECH_DISCOVERY_TRIGGER = TriggerPredicate(
    finding_types=["PORT_OPEN"],
    min_pheromone=0.3,
)

VULN_SCAN_TRIGGER = TriggerPredicate(
    finding_types=["TECHNOLOGY", "HTTP_ENDPOINT"],
    min_pheromone=0.4,
)

CVE_MATCH_TRIGGER = TriggerPredicate(
    finding_types=["CVE_MATCH"],
    min_pheromone=0.5,
)

EXPLOIT_TRIGGER = TriggerPredicate(
    finding_types=["VULNERABILITY"],
    min_pheromone=0.6,
)

CHAIN_TRIGGER = TriggerPredicate(
    finding_types=["EXPLOIT_RESULT"],
    min_pheromone=0.5,
)

REPORT_TRIGGER = TriggerPredicate(
    finding_types=["CAMPAIGN_COMPLETE"],
    min_pheromone=0.9,
)


def agent_trigger(finding_types: List[str], min_pheromone: float = 0.2):
    """Decorator to mark an agent's trigger predicate."""
    def decorator(func):
        func._trigger = TriggerPredicate(
            finding_types=finding_types,
            min_pheromone=min_pheromone,
        )
        return func
    return decorator
