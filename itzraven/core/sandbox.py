"""
Sandboxed Execution — Docker-isolated tool execution with resource caps.

Provides a clean per-job container where agents run tools without
affecting the host system. Supports:
- Resource limits (CPU, memory, timeout)
- Early-stopping when budget exceeded
- Result collection with output truncation
"""

import asyncio
import json
import os
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from itzraven.core.logger import get_logger

logger = get_logger()

SANDBOX_IMAGE = os.environ.get("ITZRAVEN_SANDBOX_IMAGE", "itzraven-security/sandbox:latest")
USE_SANDBOX = os.environ.get("USE_SANDBOX", "false").lower() in ("true", "1", "yes")
SANDBOX_MEMORY = os.environ.get("SANDBOX_MEMORY", "512m")
SANDBOX_CPU = os.environ.get("SANDBOX_CPU", "1.0")
SANDBOX_TIMEOUT = int(os.environ.get("SANDBOX_TIMEOUT", "120"))
EARLY_STOP_TOOL_COST = int(os.environ.get("EARLY_STOP_TOOL_COST", "40"))


@dataclass
class SandboxResult:
    exit_code: int
    stdout: str
    stderr: str
    duration: float
    tool_cost: int = 0
    truncated: bool = False


class SandboxPool:
    """Manages a pool of reusable sandbox containers."""

    _instance: Optional["SandboxPool"] = None

    def __init__(self, max_containers: int = 3):
        self._containers: List[str] = []
        self._max = max_containers
        self._job_counter = 0

    async def acquire(self, job_id: str) -> Optional[str]:
        if not USE_SANDBOX:
            return None
        try:
            container_name = f"itzraven-sandbox-{job_id}"
            proc = await asyncio.create_subprocess_exec(
                "docker", "run", "-d", "--rm",
                "--memory", SANDBOX_MEMORY,
                "--cpus", SANDBOX_CPU,
                "--network", "host",
                "--name", container_name,
                SANDBOX_IMAGE,
                "sleep", "infinity",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=60)
            if proc.returncode != 0:
                logger.warning(f"Sandbox start failed: {stderr.decode()[:200]}")
                return None
            self._containers.append(container_name)
            logger.info(f"Sandbox created: {container_name}")
            return container_name
        except Exception as e:
            logger.debug(f"Sandbox acquire failed: {e}")
            return None

    async def exec(self, container: str, cmd: str, timeout: int = SANDBOX_TIMEOUT) -> SandboxResult:
        start = time.time()
        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "exec", container,
                "sh", "-c", cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            duration = time.time() - start
            stdout_str = stdout.decode("utf-8", errors="replace")
            stderr_str = stderr.decode("utf-8", errors="replace")
            truncated = False
            if len(stdout_str) > 100_000:
                stdout_str = stdout_str[:100_000] + "\n... (truncated)"
                truncated = True
            tool_cost = 1 + (duration // 10)
            return SandboxResult(
                exit_code=proc.returncode or 0,
                stdout=stdout_str,
                stderr=stderr_str,
                duration=duration,
                tool_cost=int(tool_cost),
                truncated=truncated,
            )
        except asyncio.TimeoutError:
            return SandboxResult(exit_code=-1, stdout="", stderr="timeout", duration=time.time() - start, tool_cost=5)
        except Exception as e:
            return SandboxResult(exit_code=-1, stdout="", stderr=str(e), duration=time.time() - start, tool_cost=1)

    async def release(self, container: str):
        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "rm", "-f", container,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await proc.communicate()
            if container in self._containers:
                self._containers.remove(container)
            logger.info(f"Sandbox released: {container}")
        except Exception as e:
            logger.debug(f"Sandbox release failed: {e}")

    async def release_all(self):
        for c in list(self._containers):
            await self.release(c)

    @classmethod
    def get_instance(cls) -> "SandboxPool":
        if cls._instance is None:
            cls._instance = SandboxPool()
        return cls._instance


_sandbox_pool: Optional[SandboxPool] = None


def get_sandbox_pool() -> SandboxPool:
    global _sandbox_pool
    if _sandbox_pool is None:
        _sandbox_pool = SandboxPool()
    return _sandbox_pool


class BudgetTracker:
    """Tracks tool execution cost for early-stopping."""

    def __init__(self, max_cost: int = EARLY_STOP_TOOL_COST):
        self._cost = 0
        self._max = max_cost
        self._history: List[Dict[str, Any]] = []

    def record(self, action: str, cost: int, success: bool):
        self._cost += cost
        self._history.append({"action": action, "cost": cost, "success": success, "total": self._cost})

    @property
    def exhausted(self) -> bool:
        return self._cost >= self._max

    @property
    def total_cost(self) -> int:
        return self._cost

    def reset(self):
        self._cost = 0
        self._history.clear()
