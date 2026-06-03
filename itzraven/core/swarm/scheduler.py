"""
Swarm Scheduler — emergent agent dispatch.
No central planner. Agents trigger based on blackboard state + pheromones.
Pentest-Swarm-AI inspired decentralized coordination.
"""
import asyncio
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Callable, Set
from collections import defaultdict
from datetime import datetime

from itzraven.core.swarm.blackboard import (
    Blackboard, BlackboardEntry, BlackboardQuery, get_blackboard,
)
from itzraven.core.swarm.pheromone import PheromoneConfig, effective_weight
from itzraven.core.swarm.trigger import TriggerPredicate, TriggerRule
from itzraven.core.logger import get_logger

logger = get_logger()


@dataclass
class SwarmAgent:
    """A swarm agent — long-running worker with a trigger predicate."""
    name: str
    trigger: TriggerPredicate
    handler: Callable  # async (entry, context) -> List[BlackboardEntry]
    max_concurrency: int = 3
    cooldown: float = 5.0
    enabled: bool = True
    invocation_count: int = 0
    last_invocation: float = 0.0
    active_tasks: int = 0

    def can_run(self, entry: BlackboardEntry) -> bool:
        if not self.enabled:
            return False
        if self.active_tasks >= self.max_concurrency:
            return False
        if time.time() - self.last_invocation < self.cooldown:
            return False
        if self.invocation_count >= 50:
            return False
        return self.trigger.should_trigger(entry)

    async def run(self, entry: BlackboardEntry, context: dict) -> List[BlackboardEntry]:
        self.active_tasks += 1
        self.invocation_count += 1
        self.last_invocation = time.time()
        try:
            results = await self.handler(entry, context)
            return results or []
        except Exception as e:
            logger.debug(f"SwarmAgent {self.name} error: {e}")
            return []
        finally:
            self.active_tasks -= 1


@dataclass
class SwarmContext:
    target: str
    scan_id: str
    mode: str
    scan_depth: str
    blackboard: Blackboard
    findings: List = field(default_factory=list)
    start_time: float = field(default_factory=time.time)
    budget_seconds: float = 3600.0
    max_decisions: int = 20
    params: Dict[str, Any] = field(default_factory=dict)


class SwarmScheduler:
    """Emergent agent dispatcher.
    
    No phase loop. No central planner.
    Blackboard state + pheromone weights drive agent selection.
    """

    def __init__(self, blackboard: Optional[Blackboard] = None):
        self._board = blackboard or get_blackboard()
        self._agents: Dict[str, SwarmAgent] = {}
        self._running = False
        self._tasks: Set[asyncio.Task] = set()
        self._processed: Set[str] = set()  # (agent_name, entry_id) tuples

    def register_agent(self, agent: SwarmAgent):
        self._agents[agent.name] = agent
        logger.info(f"  🐝 Swarm agent registered: {agent.name}")

    def register_agents(self, agents: List[SwarmAgent]):
        for a in agents:
            self.register_agent(a)

    async def run(self, context: SwarmContext) -> List[dict]:
        """Run the swarm — keeps checking blackboard and dispatching agents."""
        self._running = True
        results = []
        iteration = 0

        # Write target registration
        self._board.write(BlackboardEntry(
            finding_type="TARGET_REGISTERED",
            agent_name="scheduler",
            target=context.target,
            title=f"Target registered: {context.target}",
            data={"target": context.target, "mode": context.mode, "depth": context.scan_depth},
            pheromone_base=1.0,
            half_life_sec=120.0,
            tags=["init", "target"],
        ))

        while self._running and iteration < context.max_decisions:
            iteration += 1

            # Check budget
            elapsed = time.time() - context.start_time
            if elapsed > context.budget_seconds:
                logger.info(f"⏱️ Swarm budget exhausted ({elapsed:.0f}s)")
                self._write_campaign_complete(context, "budget_exhausted")
                break

            # Query blackboard for active entries
            active = self._board.query(BlackboardQuery(
                min_weight=0.05,
                target=context.target,
                limit=100,
            ))

            if not active:
                logger.debug(f"Swarm iteration {iteration}: no active entries, sleeping...")
                await asyncio.sleep(2)
                continue

            # For each agent, check if any entry triggers it
            dispatched = 0
            for agent in self._agents.values():
                for entry in active:
                    key = (agent.name, entry.id)
                    if key in self._processed:
                        continue
                    if agent.can_run(entry):
                        self._processed.add(key)
                        logger.info(f"🐝 Swarm dispatch: {agent.name} triggered by {entry.finding_type} \"{entry.title[:50]}\"")
                        task = asyncio.create_task(self._run_agent(agent, entry, context, results))
                        self._tasks.add(task)
                        task.add_done_callback(self._tasks.discard)
                        dispatched += 1
                        break  # one trigger max per iteration per agent

            if not dispatched:
                await asyncio.sleep(2)

        # Write campaign complete
        self._write_campaign_complete(context, "completed")

        # Wait for remaining tasks
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)

        logger.info(f"🐝 Swarm completed: {iteration} iterations, {len(results)} results")
        return results

    async def _run_agent(self, agent: SwarmAgent, entry: BlackboardEntry,
                          context: SwarmContext, results: List):
        try:
            agent_results = await agent.run(entry, {
                "target": context.target,
                "scan_id": context.scan_id,
                "mode": context.mode,
                "scan_depth": context.scan_depth,
                "blackboard": self._board,
                "params": context.params,
            })
            for r in agent_results:
                if isinstance(r, dict):
                    results.append(r)
                elif isinstance(r, BlackboardEntry):
                    self._board.write(r)
        except Exception as e:
            logger.debug(f"Swarm agent {agent.name} crashed: {e}")

    def _write_campaign_complete(self, context: SwarmContext, reason: str):
        self._board.write(BlackboardEntry(
            finding_type="CAMPAIGN_COMPLETE",
            agent_name="scheduler",
            target=context.target,
            title=f"Campaign {reason}",
            data={"reason": reason, "elapsed": time.time() - context.start_time},
            pheromone_base=1.0,
            half_life_sec=3600.0,
            tags=["complete"],
        ))

    def stop(self):
        self._running = False

    def get_agent_stats(self) -> dict:
        return {
            name: {
                "invocations": a.invocation_count,
                "active": a.active_tasks,
                "enabled": a.enabled,
            }
            for name, a in self._agents.items()
        }


_instance_scheduler: Optional[SwarmScheduler] = None


def get_scheduler() -> SwarmScheduler:
    global _instance_scheduler
    if _instance_scheduler is None:
        _instance_scheduler = SwarmScheduler()
    return _instance_scheduler
