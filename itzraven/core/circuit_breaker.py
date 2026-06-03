import asyncio
import time
from enum import Enum
from typing import Callable, Awaitable, Optional, Any, Dict
from dataclasses import dataclass, field

from itzraven.core.logger import get_logger

logger = get_logger()


class CircuitState(Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


@dataclass
class CircuitBreakerConfig:
    failure_threshold: int = 5
    recovery_timeout: float = 30.0
    half_open_max_calls: int = 3
    success_threshold: int = 2


class CircuitBreaker:
    def __init__(
        self,
        name: str,
        config: Optional[CircuitBreakerConfig] = None,
    ):
        self.name = name
        self.config = config or CircuitBreakerConfig()
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._last_failure_time = 0.0
        self._half_open_calls = 0
        self._total_calls = 0
        self._total_failures = 0
        self._total_successes = 0
        self._total_rejects = 0
        self._lock = asyncio.Lock()

    @property
    def state(self) -> CircuitState:
        return self._state

    async def call(
        self,
        fn: Callable[..., Awaitable[Any]],
        *args: Any,
        fallback: Optional[Callable[..., Awaitable[Any]]] = None,
        **kwargs: Any,
    ) -> Any:
        async with self._lock:
            if self._state == CircuitState.OPEN:
                if time.time() - self._last_failure_time >= self.config.recovery_timeout:
                    self._state = CircuitState.HALF_OPEN
                    self._half_open_calls = 0
                    self._success_count = 0
                    logger.info(f"CircuitBreaker[{self.name}]: half-open (recovery timeout elapsed)")
                else:
                    self._total_rejects += 1
                    logger.warning(f"CircuitBreaker[{self.name}]: OPEN, rejecting call")
                    if fallback:
                        return await fallback(*args, **kwargs)
                    raise CircuitBreakerOpenError(f"Circuit breaker [{self.name}] is OPEN")

            if self._state == CircuitState.HALF_OPEN:
                if self._half_open_calls >= self.config.half_open_max_calls:
                    self._total_rejects += 1
                    if fallback:
                        return await fallback(*args, **kwargs)
                    raise CircuitBreakerOpenError(
                        f"Circuit breaker [{self.name}] is HALF-OPEN (max probe calls reached)"
                    )
                self._half_open_calls += 1

        try:
            result = await fn(*args, **kwargs)
            async with self._lock:
                self._total_calls += 1
                self._total_successes += 1
                self._success_count += 1
                if self._state == CircuitState.HALF_OPEN and self._success_count >= self.config.success_threshold:
                    self._state = CircuitState.CLOSED
                    self._failure_count = 0
                    self._success_count = 0
                    logger.info(f"CircuitBreaker[{self.name}]: CLOSED (recovered)")
            return result
        except Exception as e:
            async with self._lock:
                self._total_calls += 1
                self._total_failures += 1
                self._failure_count += 1
                self._last_failure_time = time.time()
                if self._failure_count >= self.config.failure_threshold:
                    self._state = CircuitState.OPEN
                    self._success_count = 0
                    logger.error(
                        f"CircuitBreaker[{self.name}]: OPEN (failure_count={self._failure_count})"
                    )
            if fallback:
                return await fallback(*args, **kwargs)
            raise

    def get_stats(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "state": self._state.value,
            "total_calls": self._total_calls,
            "total_successes": self._total_successes,
            "total_failures": self._total_failures,
            "total_rejects": self._total_rejects,
            "failure_count": self._failure_count,
            "success_count": self._success_count,
            "failure_threshold": self.config.failure_threshold,
            "recovery_timeout": self.config.recovery_timeout,
        }


class CircuitBreakerOpenError(Exception):
    pass


class CircuitBreakerRegistry:
    _instance: Optional["CircuitBreakerRegistry"] = None

    def __init__(self):
        self._breakers: Dict[str, CircuitBreaker] = {}

    def get(
        self,
        name: str,
        config: Optional[CircuitBreakerConfig] = None,
    ) -> CircuitBreaker:
        if name not in self._breakers:
            self._breakers[name] = CircuitBreaker(name, config)
        return self._breakers[name]

    def get_all_stats(self) -> Dict[str, Any]:
        return {
            name: cb.get_stats() for name, cb in self._breakers.items()
        }

    def reset(self, name: Optional[str] = None):
        if name:
            self._breakers.pop(name, None)
        else:
            self._breakers.clear()

    @classmethod
    def get_instance(cls) -> "CircuitBreakerRegistry":
        if cls._instance is None:
            cls._instance = CircuitBreakerRegistry()
        return cls._instance


_circuit_breaker_registry: Optional[CircuitBreakerRegistry] = None


def get_circuit_breaker_registry() -> CircuitBreakerRegistry:
    global _circuit_breaker_registry
    if _circuit_breaker_registry is None:
        _circuit_breaker_registry = CircuitBreakerRegistry()
    return _circuit_breaker_registry
