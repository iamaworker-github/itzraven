"""
Enhanced Adaptive Concurrency — XBOW-inspired agent-level parallelism.

Extends basic HTTP concurrency to track agent-level performance,
dynamic scaling across targets, and intelligent work distribution.
"""

import asyncio
import time
import math
from typing import Dict, Optional, List, Tuple, Set
from dataclasses import dataclass, field

from itzraven.core.logger import get_logger

logger = get_logger()


@dataclass
class AgentMetrics:
    agent_name: str
    runs: int = 0
    successes: int = 0
    failures: int = 0
    total_duration: float = 0.0
    findings_produced: int = 0
    last_run: float = 0.0
    avg_latency: float = 0.0
    error_rate: float = 0.0

    @property
    def success_rate(self) -> float:
        return self.successes / max(self.runs, 1)

    @property
    def throughput(self) -> float:
        return self.findings_produced / max(self.total_duration, 0.001)

    def to_dict(self) -> dict:
        return {
            "agent_name": self.agent_name,
            "runs": self.runs,
            "successes": self.successes,
            "failures": self.failures,
            "success_rate": round(self.success_rate, 3),
            "findings_produced": self.findings_produced,
            "avg_latency": round(self.avg_latency, 2),
            "error_rate": round(self.error_rate, 3),
            "throughput": round(self.throughput, 3),
        }


@dataclass
class TargetMetrics:
    target: str
    success_count: int = 0
    error_count: int = 0
    timeout_count: int = 0
    total_latency_ms: float = 0.0
    min_latency_ms: float = float("inf")
    max_latency_ms: float = 0.0
    window_start: float = field(default_factory=time.time)
    request_count: int = 0
    consecutive_errors: int = 0
    agent_count: int = 0
    findings_count: int = 0

    @property
    def avg_latency_ms(self) -> float:
        return self.total_latency_ms / max(self.request_count, 1)

    @property
    def error_rate(self) -> float:
        total = self.success_count + self.error_count + self.timeout_count
        return (self.error_count + self.timeout_count) / max(total, 1)

    def record_success(self, latency_ms: float):
        self.success_count += 1
        self.request_count += 1
        self.total_latency_ms += latency_ms
        self.min_latency_ms = min(self.min_latency_ms, latency_ms)
        self.max_latency_ms = max(self.max_latency_ms, latency_ms)
        self.consecutive_errors = 0

    def record_error(self, latency_ms: float = 0):
        self.error_count += 1
        self.request_count += 1
        self.consecutive_errors += 1

    def record_timeout(self):
        self.timeout_count += 1
        self.request_count += 1
        self.consecutive_errors += 1

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "requests": self.request_count,
            "success": self.success_count,
            "errors": self.error_count,
            "timeouts": self.timeout_count,
            "avg_latency_ms": round(self.avg_latency_ms, 2),
            "error_rate": round(self.error_rate, 4),
            "consecutive_errors": self.consecutive_errors,
            "agents": self.agent_count,
            "findings": self.findings_count,
        }


class AdaptiveConcurrencyController:
    MIN_CONCURRENCY = 1
    MAX_CONCURRENCY = 50
    DEFAULT_CONCURRENCY = 5
    ADAPT_INTERVAL = 10.0
    ERROR_THRESHOLD = 0.1
    LATENCY_INCREASE_THRESHOLD = 2.0
    COOLDOWN_PERIOD = 30.0
    DEFAULT_AGENT_CONCURRENCY = 3
    MAX_AGENT_CONCURRENCY = 20

    def __init__(self, default_concurrency: int = 5):
        self._concurrency = max(self.MIN_CONCURRENCY, min(default_concurrency, self.MAX_CONCURRENCY))
        self._agent_concurrency = self.DEFAULT_AGENT_CONCURRENCY
        self._target_metrics: Dict[str, TargetMetrics] = {}
        self._agent_metrics: Dict[str, AgentMetrics] = {}
        self._semaphore: Optional[asyncio.Semaphore] = None
        self._agent_semaphore: Optional[asyncio.Semaphore] = None
        self._last_adapt = time.time()
        self._last_cooldown_reduction = time.time()
        self._task: Optional[asyncio.Task] = None
        self._running = False
        self._active_agents: Set[str] = set()

    async def start(self):
        self._running = True
        self._semaphore = asyncio.Semaphore(self._concurrency)
        self._agent_semaphore = asyncio.Semaphore(self._agent_concurrency)
        self._task = asyncio.create_task(self._adapt_loop())
        logger.info(f"AdaptiveConcurrency: started (req={self._concurrency}, agents={self._agent_concurrency})")

    async def stop(self):
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("AdaptiveConcurrency: stopped")

    async def acquire(self, target: str) -> bool:
        if self._semaphore is None:
            self._semaphore = asyncio.Semaphore(self._concurrency)
        await self._semaphore.acquire()
        return True

    def release(self, target: str, success: bool, latency_ms: float = 0, timeout: bool = False):
        if self._semaphore:
            self._semaphore.release()
        metrics = self._target_metrics.setdefault(target, TargetMetrics(target=target))
        if timeout:
            metrics.record_timeout()
        elif success:
            metrics.record_success(latency_ms)
        else:
            metrics.record_error(latency_ms)

    async def acquire_agent(self, agent_name: str) -> bool:
        if self._agent_semaphore is None:
            self._agent_semaphore = asyncio.Semaphore(self._agent_concurrency)
        self._active_agents.add(agent_name)
        await self._agent_semaphore.acquire()
        return True

    def release_agent(self, agent_name: str):
        if self._agent_semaphore:
            self._agent_semaphore.release()
        self._active_agents.discard(agent_name)

    def record_agent_run(
        self,
        agent_name: str,
        success: bool,
        duration: float,
        findings_count: int = 0,
    ):
        if agent_name not in self._agent_metrics:
            self._agent_metrics[agent_name] = AgentMetrics(agent_name=agent_name)
        rec = self._agent_metrics[agent_name]
        rec.runs += 1
        if success:
            rec.successes += 1
        else:
            rec.failures += 1
        rec.total_duration += duration
        rec.findings_produced += findings_count
        rec.last_run = time.time()

        for tm in self._target_metrics.values():
            tm.findings_count += findings_count

    async def _adapt_loop(self):
        while self._running:
            await asyncio.sleep(self.ADAPT_INTERVAL)
            self._adapt()

    def _adapt(self):
        if not self._target_metrics and not self._agent_metrics:
            return
        now = time.time()

        all_metrics = list(self._target_metrics.values())
        active = [m for m in all_metrics if m.request_count > 0]
        if active:
            avg_error_rate = sum(m.error_rate for m in active) / len(active)
            avg_latency = sum(m.avg_latency_ms for m in active) / len(active)
            max_consecutive_errors = max(m.consecutive_errors for m in active)

            old_concurrency = self._concurrency
            if max_consecutive_errors >= 3:
                self._concurrency = max(self.MIN_CONCURRENCY, self._concurrency // 2)
                logger.warning(f"AdaptiveConcurrency: reducing req concurrency to {self._concurrency}")
            elif avg_error_rate > self.ERROR_THRESHOLD:
                self._concurrency = max(self.MIN_CONCURRENCY, int(self._concurrency * (1.0 - avg_error_rate)))
            elif self._concurrency < self.MAX_CONCURRENCY and avg_error_rate < self.ERROR_THRESHOLD * 0.5:
                self._concurrency = min(self.MAX_CONCURRENCY, self._concurrency + 1)

            if self._concurrency != old_concurrency:
                self._semaphore = asyncio.Semaphore(self._concurrency)

        agent_records = list(self._agent_metrics.values())
        if agent_records:
            active_agent_count = len(self._active_agents)
            avg_success_rate = sum(a.success_rate for a in agent_records) / len(agent_records)
            avg_findings_per_run = sum(a.findings_produced for a in agent_records) / max(sum(a.runs for a in agent_records), 1)

            old_agent_conc = self._agent_concurrency
            if avg_success_rate < 0.3 and active_agent_count > 2:
                self._agent_concurrency = max(1, self._agent_concurrency - 1)
            elif avg_success_rate > 0.8 and self._agent_concurrency < self.MAX_AGENT_CONCURRENCY:
                self._agent_concurrency = min(self.MAX_AGENT_CONCURRENCY, self._agent_concurrency + 1)

            if self._agent_concurrency != old_agent_conc:
                self._agent_semaphore = asyncio.Semaphore(self._agent_concurrency)
                logger.info(f"AdaptiveConcurrency: agent concurrency {old_agent_conc} -> {self._agent_concurrency}")

        self._last_adapt = now

    def get_concurrency(self) -> int:
        return self._concurrency

    def get_agent_concurrency(self) -> int:
        return self._agent_concurrency

    def get_active_agent_count(self) -> int:
        return len(self._active_agents)

    def get_agent_metrics(self, agent_name: Optional[str] = None) -> List[dict]:
        if agent_name and agent_name in self._agent_metrics:
            return [self._agent_metrics[agent_name].to_dict()]
        return [m.to_dict() for a, m in self._agent_metrics.items()]

    def get_metrics(self, target: Optional[str] = None) -> List[dict]:
        if target:
            m = self._target_metrics.get(target)
            return [m.to_dict()] if m else []
        return [m.to_dict() for m in self._target_metrics.values()]

    def get_summary(self) -> dict:
        return {
            "current_concurrency": self._concurrency,
            "agent_concurrency": self._agent_concurrency,
            "min_concurrency": self.MIN_CONCURRENCY,
            "max_concurrency": self.MAX_CONCURRENCY,
            "targets_monitored": len(self._target_metrics),
            "agents_tracked": len(self._agent_metrics),
            "active_agents": len(self._active_agents),
            "last_adapt": self._last_adapt,
        }


_adaptive_concurrency: Optional[AdaptiveConcurrencyController] = None


def get_adaptive_concurrency() -> AdaptiveConcurrencyController:
    global _adaptive_concurrency
    if _adaptive_concurrency is None:
        _adaptive_concurrency = AdaptiveConcurrencyController()
    return _adaptive_concurrency
