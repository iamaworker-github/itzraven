"""
Temporal Orchestration — production-grade distributed workflow engine.

Shannon-inspired: distributes agent execution across multiple worker processes
using Redis-backed task queues. Handles worker registration, task dispatch,
heartbeat monitoring, result collection, and failure recovery.

Architecture:
  - Coordinator publishes tasks to Redis streams
  - Workers consume tasks, execute agents, publish results
  - Heartbeat mechanism detects dead workers
  - Failed tasks are retried on healthy workers
  - Supports priority queues for urgent tasks
"""

import asyncio
import json
import os
import signal
import sys
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from itzraven.core.logger import get_logger

logger = get_logger()


class TaskStatus(Enum):
    PENDING = "pending"
    ASSIGNED = "assigned"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"
    RETRY = "retry"


class TaskPriority(Enum):
    LOW = 0
    NORMAL = 1
    HIGH = 2
    CRITICAL = 3


@dataclass
class WorkflowTask:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    agent_name: str = ""
    target: str = ""
    mode: str = ""
    params: Dict[str, Any] = field(default_factory=dict)
    priority: TaskPriority = TaskPriority.NORMAL
    status: TaskStatus = TaskStatus.PENDING
    worker_id: Optional[str] = None
    created_at: float = field(default_factory=time.time)
    assigned_at: Optional[float] = None
    completed_at: Optional[float] = None
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    retry_count: int = 0
    max_retries: int = 3
    timeout: float = 600.0  # 10 minutes default
    dependencies: List[str] = field(default_factory=list)
    parent_scan_id: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "agent_name": self.agent_name,
            "target": self.target,
            "mode": self.mode,
            "params": self.params,
            "priority": self.priority.value,
            "status": self.status.value,
            "worker_id": self.worker_id,
            "created_at": self.created_at,
            "assigned_at": self.assigned_at,
            "completed_at": self.completed_at,
            "result": self.result,
            "error": self.error,
            "retry_count": self.retry_count,
            "max_retries": self.max_retries,
            "timeout": self.timeout,
            "dependencies": self.dependencies,
            "parent_scan_id": self.parent_scan_id,
        }


@dataclass
class WorkerInfo:
    id: str
    hostname: str
    pid: int
    started_at: float
    last_heartbeat: float
    current_task: Optional[str] = None
    tasks_completed: int = 0
    tasks_failed: int = 0
    load: float = 0.0  # 0.0 to 1.0
    tags: List[str] = field(default_factory=list)

    @property
    def is_alive(self) -> bool:
        return (time.time() - self.last_heartbeat) < 30

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "hostname": self.hostname,
            "pid": self.pid,
            "started_at": self.started_at,
            "last_heartbeat": self.last_heartbeat,
            "current_task": self.current_task,
            "tasks_completed": self.tasks_completed,
            "tasks_failed": self.tasks_failed,
            "load": self.load,
            "is_alive": self.is_alive,
            "tags": self.tags,
        }


class TemporalCoordinator:
    """Central coordinator for distributed agent execution.

    Redis-backed pub/sub for task distribution across worker processes.
    Falls back to in-process queue when Redis is unavailable.
    """

    REDIS_PREFIX = "itzraven:temporal:"

    def __init__(
        self,
        scan_id: str,
        redis_url: str = "redis://localhost:6379/0",
        use_redis: bool = True,
    ):
        self.scan_id = scan_id
        self._use_redis = use_redis
        self._redis_url = redis_url
        self._redis = None
        self._tasks: Dict[str, WorkflowTask] = {}
        self._workers: Dict[str, WorkerInfo] = {}
        self._pending_queue: asyncio.Queue = asyncio.Queue()
        self._results: Dict[str, Any] = {}
        self._running = False
        self._worker_id: Optional[str] = None

    async def _connect_redis(self):
        if not self._use_redis:
            return
        try:
            import redis.asyncio as aioredis
            self._redis = await aioredis.from_url(
                self._redis_url, decode_responses=True,
                socket_connect_timeout=3,
            )
            await self._redis.ping()
            logger.info("Temporal: connected to Redis")
        except Exception as e:
            logger.warning(f"Temporal: Redis unavailable ({e}), using in-process queue")
            self._use_redis = False
            self._redis = None

    def _get_key(self, *parts: str) -> str:
        return f"{self.REDIS_PREFIX}{':'.join(parts)}"

    # ------------------------------------------------------------------
    # Task management
    # ------------------------------------------------------------------

    def create_task(
        self,
        agent_name: str,
        target: str,
        mode: str = "",
        params: Optional[Dict[str, Any]] = None,
        priority: TaskPriority = TaskPriority.NORMAL,
        timeout: float = 600.0,
        dependencies: Optional[List[str]] = None,
    ) -> WorkflowTask:
        task = WorkflowTask(
            agent_name=agent_name,
            target=target,
            mode=mode,
            params=params or {},
            priority=priority,
            timeout=timeout,
            dependencies=dependencies or [],
            parent_scan_id=self.scan_id,
        )
        self._tasks[task.id] = task
        return task

    def get_task(self, task_id: str) -> Optional[WorkflowTask]:
        return self._tasks.get(task_id)

    def get_pending_tasks(self) -> List[WorkflowTask]:
        deps_met = []
        for task in self._tasks.values():
            if task.status != TaskStatus.PENDING:
                continue
            if not task.dependencies:
                deps_met.append(task)
            else:
                all_deps_done = all(
                    self._tasks.get(dep_id) and
                    self._tasks[dep_id].status == TaskStatus.COMPLETED
                    for dep_id in task.dependencies
                )
                if all_deps_done:
                    deps_met.append(task)
        return sorted(deps_met, key=lambda t: t.priority.value, reverse=True)

    async def submit_task(self, task: WorkflowTask) -> None:
        task.status = TaskStatus.PENDING
        if self._use_redis and self._redis:
            await self._redis.rpush(
                self._get_key("queue", self.scan_id),
                json.dumps(task.to_dict()),
            )
        await self._pending_queue.put(task)

    async def complete_task(
        self, task_id: str, result: Dict[str, Any], worker_id: str
    ) -> None:
        task = self._tasks.get(task_id)
        if not task:
            return
        task.status = TaskStatus.COMPLETED
        task.completed_at = time.time()
        task.result = result
        task.worker_id = worker_id
        self._results[task_id] = result

        if self._use_redis and self._redis:
            await self._redis.publish(
                self._get_key("results", self.scan_id),
                json.dumps({"task_id": task_id, "result": result, "worker_id": worker_id}),
            )

    async def fail_task(
        self, task_id: str, error: str, worker_id: str
    ) -> None:
        task = self._tasks.get(task_id)
        if not task:
            return
        task.retry_count += 1
        if task.retry_count >= task.max_retries:
            task.status = TaskStatus.FAILED
            task.error = error
            task.completed_at = time.time()
            logger.error(f"Task {task_id} failed permanently: {error}")
        else:
            task.status = TaskStatus.RETRY
            logger.warning(f"Task {task_id} failed, retry {task.retry_count}/{task.max_retries}")
            await self.submit_task(task)

    # ------------------------------------------------------------------
    # Worker management
    # ------------------------------------------------------------------

    def register_worker(
        self,
        worker_id: str,
        hostname: str = "",
        pid: int = 0,
        tags: Optional[List[str]] = None,
    ) -> WorkerInfo:
        worker = WorkerInfo(
            id=worker_id,
            hostname=hostname or os.uname().nodename,
            pid=pid or os.getpid(),
            started_at=time.time(),
            last_heartbeat=time.time(),
            tags=tags or [],
        )
        self._workers[worker_id] = worker
        self._worker_id = worker_id
        logger.info(f"Worker registered: {worker_id} ({worker.hostname}:{worker.pid})")
        return worker

    def heartbeat(self, worker_id: Optional[str] = None) -> None:
        wid = worker_id or self._worker_id
        if wid and wid in self._workers:
            self._workers[wid].last_heartbeat = time.time()

    def get_alive_workers(self) -> List[WorkerInfo]:
        return [w for w in self._workers.values() if w.is_alive]

    def get_dead_workers(self) -> List[WorkerInfo]:
        return [w for w in self._workers.values() if not w.is_alive]

    async def purge_dead_workers(self):
        dead = self.get_dead_workers()
        for w in dead:
            logger.warning(f"Purging dead worker: {w.id}")
            if w.current_task:
                task = self._tasks.get(w.current_task)
                if task and task.status == TaskStatus.RUNNING:
                    await self.fail_task(w.current_task, "Worker died", w.id)
            del self._workers[w.id]

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    async def run_coordinator(self, workers: int = 1):
        """Run as coordinator: dispatch tasks to local workers."""
        self._running = True
        await self._connect_redis()

        tasks = list(self._tasks.values())
        logger.info(f"Temporal: coordinating {len(tasks)} tasks across {workers} workers")

        async def worker_loop(worker_id: str):
            while self._running:
                task = None
                try:
                    task = await asyncio.wait_for(
                        self._pending_queue.get(), timeout=1.0
                    )
                except asyncio.TimeoutError:
                    if self._running:
                        self.heartbeat(worker_id)
                    continue

                if not task:
                    continue

                task.status = TaskStatus.RUNNING
                task.assigned_at = time.time()
                task.worker_id = worker_id
                if worker_id in self._workers:
                    self._workers[worker_id].current_task = task.id

                logger.info(f"Worker {worker_id} executing: {task.agent_name}")
                try:
                    result = await asyncio.wait_for(
                        self._execute_task(task), timeout=task.timeout
                    )
                    await self.complete_task(task.id, result, worker_id)
                    if worker_id in self._workers:
                        self._workers[worker_id].tasks_completed += 1
                except asyncio.TimeoutError:
                    await self.fail_task(task.id, "Task timeout", worker_id)
                    if worker_id in self._workers:
                        self._workers[worker_id].tasks_failed += 1
                except Exception as e:
                    await self.fail_task(task.id, str(e), worker_id)
                    if worker_id in self._workers:
                        self._workers[worker_id].tasks_failed += 1
                finally:
                    if worker_id in self._workers:
                        self._workers[worker_id].current_task = None

        worker_ids = [f"worker-{i}-{uuid.uuid4().hex[:6]}" for i in range(workers)]
        for wid in worker_ids:
            self.register_worker(wid)

        tasks = [worker_loop(wid) for wid in worker_ids]

        heartbeat_task = asyncio.create_task(self._heartbeat_loop())
        purge_task = asyncio.create_task(self._purge_loop())

        await asyncio.gather(*tasks)
        heartbeat_task.cancel()
        purge_task.cancel()

    async def _execute_task(self, task: WorkflowTask) -> Dict[str, Any]:
        """Execute a single agent task. Override for custom logic."""
        raise NotImplementedError("Subclasses implement actual agent execution")

    async def _heartbeat_loop(self, interval: float = 5.0):
        while self._running:
            self.heartbeat()
            await asyncio.sleep(interval)

    async def _purge_loop(self, interval: float = 30.0):
        while self._running:
            await self.purge_dead_workers()
            await asyncio.sleep(interval)

    def stop(self):
        self._running = False

    # ------------------------------------------------------------------
    # Results
    # ------------------------------------------------------------------

    def get_results(self) -> Dict[str, Any]:
        return dict(self._results)

    def get_summary(self) -> Dict[str, Any]:
        total = len(self._tasks)
        completed = sum(1 for t in self._tasks.values() if t.status == TaskStatus.COMPLETED)
        failed = sum(1 for t in self._tasks.values() if t.status == TaskStatus.FAILED)
        running = sum(1 for t in self._tasks.values() if t.status == TaskStatus.RUNNING)
        pending = sum(1 for t in self._tasks.values() if t.status == TaskStatus.PENDING)

        return {
            "scan_id": self.scan_id,
            "total_tasks": total,
            "completed": completed,
            "failed": failed,
            "running": running,
            "pending": pending,
            "workers": len(self._workers),
            "alive_workers": len(self.get_alive_workers()),
            "uptime": time.time() - min(
                (w.started_at for w in self._workers.values()), default=time.time()
            ),
        }


class ScanWorker:
    """Worker process that pulls tasks from Redis and executes agents."""

    def __init__(
        self,
        coordinator_url: str = "redis://localhost:6379/0",
        worker_id: Optional[str] = None,
        tags: Optional[List[str]] = None,
    ):
        self._redis_url = coordinator_url
        self._worker_id = worker_id or f"worker-{uuid.uuid4().hex[:8]}"
        self._tags = tags or []
        self._redis = None
        self._running = False
        self._current_task: Optional[str] = None
        self._tasks_completed = 0
        self._tasks_failed = 0
        self._agent_registry: Dict[str, Callable] = {}

    def register_agent(self, name: str, factory: Callable):
        self._agent_registry[name] = factory

    async def connect(self):
        import redis.asyncio as aioredis
        self._redis = await aioredis.from_url(
            self._redis_url, decode_responses=True,
        )
        await self._redis.ping()
        logger.info(f"Worker {self._worker_id} connected to {self._redis_url}")

    async def run(self):
        self._running = True
        if not self._redis:
            await self.connect()

        pubsub = self._redis.pubsub()
        await pubsub.subscribe(f"itzraven:temporal:queue:*")

        heartbeat_task = asyncio.create_task(self._heartbeat_loop())

        logger.info(f"Worker {self._worker_id} ready. Registered agents: {list(self._agent_registry.keys())}")

        while self._running:
            try:
                message = await pubsub.get_message(
                    timeout=1.0, ignore_subscribe_messages=True
                )
                if message and message["type"] == "message":
                    task_data = json.loads(message["data"])
                    await self._process_task(task_data)
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"Worker error: {e}")
                await asyncio.sleep(1)

        heartbeat_task.cancel()

    async def _process_task(self, task_data: dict):
        task_id = task_data.get("id")
        agent_name = task_data.get("agent_name")
        self._current_task = task_id

        logger.info(f"Processing task {task_id}: {agent_name}")

        factory = self._agent_registry.get(agent_name)
        if not factory:
            logger.error(f"No agent registered: {agent_name}")
            await self._publish_result(task_id, {"error": f"Unknown agent: {agent_name}"}, failed=True)
            self._tasks_failed += 1
            self._current_task = None
            return

        try:
            agent = factory()
            result = await agent.run()
            await self._publish_result(task_id, result.to_dict(), failed=False)
            self._tasks_completed += 1
        except Exception as e:
            logger.error(f"Task {task_id} failed: {e}")
            await self._publish_result(task_id, {"error": str(e)}, failed=True)
            self._tasks_failed += 1

        self._current_task = None

    async def _publish_result(self, task_id: str, result: dict, failed: bool):
        payload = json.dumps({
            "task_id": task_id,
            "result": result,
            "worker_id": self._worker_id,
            "failed": failed,
            "timestamp": time.time(),
        })
        await self._redis.publish("itzraven:temporal:results", payload)

    async def _heartbeat_loop(self):
        while self._running:
            try:
                payload = json.dumps({
                    "worker_id": self._worker_id,
                    "timestamp": time.time(),
                    "current_task": self._current_task,
                    "tasks_completed": self._tasks_completed,
                    "tasks_failed": self._tasks_failed,
                    "tags": self._tags,
                })
                await self._redis.publish("itzraven:temporal:heartbeat", payload)
            except Exception:
                pass
            await asyncio.sleep(10)

    def stop(self):
        self._running = False


_temporal_coordinators: Dict[str, TemporalCoordinator] = {}


def get_temporal_coordinator(
    scan_id: str,
    redis_url: str = "redis://localhost:6379/0",
) -> TemporalCoordinator:
    if scan_id not in _temporal_coordinators:
        _temporal_coordinators[scan_id] = TemporalCoordinator(
            scan_id=scan_id, redis_url=redis_url,
        )
    return _temporal_coordinators[scan_id]
