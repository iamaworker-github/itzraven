"""
Token-bucket rate limiter for controlling request rates to targets.
"""

import asyncio
import time
from typing import Dict, Optional
from collections import defaultdict
from itzraven.core.logger import get_logger
from itzraven.core.config import get_config

logger = get_logger()
config = get_config()


class TokenBucket:
    def __init__(self, rate: float, burst: int):
        self.rate = rate
        self.burst = burst
        self.tokens = float(burst)
        self.last_refill = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self, tokens: float = 1.0) -> float:
        async with self._lock:
            self._refill()
            if self.tokens < tokens:
                wait = (tokens - self.tokens) / self.rate
                await asyncio.sleep(wait)
                self._refill()
            self.tokens -= tokens
            return self.tokens

    def _refill(self):
        now = time.monotonic()
        elapsed = now - self.last_refill
        self.tokens = min(self.burst, self.tokens + elapsed * self.rate)
        self.last_refill = now


class RateLimiter:
    """Per-target rate limiter using token buckets with adaptive mode."""

    def __init__(self, default_rate: Optional[float] = None, default_burst: Optional[int] = None):
        self.default_rate = default_rate or float(config.get("requests_per_second") or 10)
        self.default_burst = default_burst or int(config.get("burst_size") or 20)
        self._buckets: Dict[str, TokenBucket] = defaultdict(
            lambda: TokenBucket(self.default_rate, self.default_burst)
        )
        self._target_rates: Dict[str, Dict[str, float]] = {}
        self._adaptive_mode = False

    def enable_adaptive(self, enabled: bool = True):
        self._adaptive_mode = enabled
        if enabled:
            logger.info("RateLimiter: adaptive mode enabled")

    async def acquire(self, target: str, tokens: float = 1.0) -> float:
        return await self._buckets[target].acquire(tokens)

    def set_rate(self, target: str, rate: float, burst: int):
        self._buckets[target] = TokenBucket(rate, burst)

    def record_response(self, target: str, latency_ms: float, success: bool):
        if not self._adaptive_mode:
            return
        if target not in self._target_rates:
            self._target_rates[target] = {"latency_sum": 0.0, "count": 0, "error_count": 0}
        stats = self._target_rates[target]
        stats["latency_sum"] += latency_ms
        stats["count"] += 1
        if not success:
            stats["error_count"] += 1
        if stats["count"] >= 10:
            avg_latency = stats["latency_sum"] / stats["count"]
            error_rate = stats["error_count"] / stats["count"]
            if error_rate > 0.2 or avg_latency > 5000:
                bucket = self._buckets.get(target)
                if bucket:
                    new_rate = max(1, bucket.rate * 0.5)
                    new_burst = max(1, bucket.burst // 2)
                    self.set_rate(target, new_rate, new_burst)
                    logger.debug(f"RateLimiter: reduced rate for {target} to {new_rate}/s (error_rate={error_rate:.2f}, latency={avg_latency:.0f}ms)")
            elif error_rate < 0.05 and avg_latency < 1000:
                bucket = self._buckets.get(target)
                if bucket:
                    new_rate = min(self.default_rate * 2, bucket.rate * 1.2)
                    new_burst = min(self.default_burst * 2, int(bucket.burst * 1.2))
                    self.set_rate(target, new_rate, new_burst)
            stats["latency_sum"] = 0.0
            stats["count"] = 0
            stats["error_count"] = 0

    def reset(self, target: Optional[str] = None):
        if target:
            self._buckets.pop(target, None)
            self._target_rates.pop(target, None)
        else:
            self._buckets.clear()
            self._target_rates.clear()

    def get_stats(self, target: str) -> dict:
        bucket = self._buckets.get(target)
        if not bucket:
            return {"tokens": 0, "rate": 0, "burst": 0}
        return {
            "tokens": round(bucket.tokens, 2),
            "rate": bucket.rate,
            "burst": bucket.burst,
        }

    def get_all_stats(self) -> dict:
        return {
            "adaptive_mode": self._adaptive_mode,
            "buckets": {
                target: self.get_stats(target) for target in list(self._buckets.keys())
            },
        }


_rate_limiter: Optional[RateLimiter] = None


def get_rate_limiter() -> RateLimiter:
    global _rate_limiter
    if _rate_limiter is None:
        _rate_limiter = RateLimiter()
    return _rate_limiter
