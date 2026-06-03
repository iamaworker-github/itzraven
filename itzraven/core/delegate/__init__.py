"""
ItzravenDelegate — Sub-agent spawning system.
Spawns isolated sub-agents with focused context for parallel pentesting.
Hermes-inspired delegate architecture.
"""
import asyncio
import json
import uuid
from typing import Any, Callable, Dict, List, Optional, Type
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor

from itzraven.core.logger import get_logger

logger = get_logger()


@dataclass
class DelegateTask:
    task_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    name: str = ""
    goal: str = ""
    target: str = ""
    category: str = ""
    skills: List[str] = field(default_factory=list)
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    status: str = "pending"  # pending, running, completed, failed


class SubAgent:
    def __init__(self, task: DelegateTask, execute_fn: Callable):
        self.task = task
        self.execute_fn = execute_fn

    async def run(self) -> Dict[str, Any]:
        logger.info(f"  Sub-agent [{self.task.task_id}]: {self.task.goal[:60]}...")
        self.task.status = "running"
        try:
            result = await self.execute_fn(self.task)
            self.task.result = result
            self.task.status = "completed"
            return result
        except Exception as e:
            self.task.error = str(e)
            self.task.status = "failed"
            return {"error": str(e)}


class ItzravenDelegate:
    def __init__(self, max_concurrent: int = 5):
        self.max_concurrent = max_concurrent
        self.tasks: List[DelegateTask] = []

    def spawn(self, name: str, goal: str, target: str, category: str = "", skills: Optional[List[str]] = None) -> DelegateTask:
        task = DelegateTask(
            name=name,
            goal=goal,
            target=target,
            category=category,
            skills=skills or [],
        )
        self.tasks.append(task)
        return task

    async def run_all(self, execute_fn: Callable) -> List[Dict[str, Any]]:
        semaphore = asyncio.Semaphore(self.max_concurrent)

        async def run_with_limit(task: DelegateTask) -> Dict[str, Any]:
            async with semaphore:
                agent = SubAgent(task, execute_fn)
                return await agent.run()

        tasks = [run_with_limit(t) for t in self.tasks if t.status == "pending"]
        if not tasks:
            return []

        logger.info(f"🚀 Delegating {len(tasks)} sub-agents (max {self.max_concurrent} concurrent)")
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [r for r in results if isinstance(r, dict)]

    def summary(self) -> Dict:
        completed = sum(1 for t in self.tasks if t.status == "completed")
        failed = sum(1 for t in self.tasks if t.status == "failed")
        return {"total": len(self.tasks), "completed": completed, "failed": failed}
