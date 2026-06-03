"""
Distributed scanning support via Redis Streams.

Extends the in-process EventBus with a Redis-backed backend for multi-machine
agent coordination. Uses Redis Streams for persistent, ordered event delivery
with consumer groups.
"""

import json
import time
from typing import Optional, Any, Dict, List, Callable
from dataclasses import dataclass, field

from itzraven.core.logger import get_logger
from itzraven.core.config import get_config

logger = get_logger()
config = get_config()

REDIS_AVAILABLE = False
try:
    import redis.asyncio as aioredis
    REDIS_AVAILABLE = True
except ImportError:
    aioredis = None


@dataclass
class RedisStreamConfig:
    host: str = "127.0.0.1"
    port: int = 6379
    db: int = 0
    password: Optional[str] = None
    stream_name: str = "itzraven:events"
    consumer_group: str = "itzraven-workers"
    consumer_name: str = ""
    maxlen: int = 10000


class RedisEventBackend:
    """Redis Streams backend for distributed event distribution."""

    def __init__(self, cfg: Optional[RedisStreamConfig] = None):
        self.cfg = cfg or RedisStreamConfig()
        self.cfg.consumer_name = self.cfg.consumer_name or f"worker-{int(time.time())}"
        self._redis: Optional[Any] = None
        self._available = REDIS_AVAILABLE
        self._handlers: Dict[str, List[Callable]] = {}

    async def connect(self) -> bool:
        if not self._available:
            logger.warning("Redis not available. Install with: pip install redis")
            return False
        try:
            self._redis = aioredis.Redis(
                host=self.cfg.host,
                port=self.cfg.port,
                db=self.cfg.db,
                password=self.cfg.password,
                decode_responses=True,
            )
            await self._redis.ping()
            # Create stream and consumer group
            try:
                await self._redis.xgroup_create(
                    self.cfg.stream_name, self.cfg.consumer_group,
                    id="0", mkstream=True,
                )
            except Exception:
                pass  # Group already exists
            logger.info(f"Connected to Redis at {self.cfg.host}:{self.cfg.port}")
            return True
        except Exception as e:
            logger.warning(f"Redis connection failed: {e}")
            self._available = False
            return False

    async def publish(self, event_type: str, data: dict):
        if not self._available or not self._redis:
            return
        try:
            await self._redis.xadd(
                self.cfg.stream_name,
                {"type": event_type, "data": json.dumps(data), "timestamp": str(time.time())},
                maxlen=self.cfg.maxlen,
            )
        except Exception as e:
            logger.debug(f"Redis publish failed: {e}")

    async def consume(self, callback: Callable, block_ms: int = 2000):
        if not self._available or not self._redis:
            return
        try:
            results = await self._redis.xreadgroup(
                self.cfg.consumer_group, self.cfg.consumer_name,
                {self.cfg.stream_name: ">"},
                count=10, block=block_ms,
            )
            if not results:
                return
            for stream_name, messages in results:
                for msg_id, msg_data in messages:
                    try:
                        event_type = msg_data.get("type", "unknown")
                        data = json.loads(msg_data.get("data", "{}"))
                        await callback(event_type, data)
                        await self._redis.xack(self.cfg.stream_name, self.cfg.consumer_group, msg_id)
                    except Exception as e:
                        logger.debug(f"Redis message handler error: {e}")
        except Exception as e:
            logger.debug(f"Redis consume error: {e}")

    async def get_pending_count(self) -> int:
        if not self._available or not self._redis:
            return 0
        try:
            info = await self._redis.xpending(self.cfg.stream_name, self.cfg.consumer_group)
            return info.get("pending", 0) if isinstance(info, dict) else 0
        except Exception:
            return 0

    async def close(self):
        if self._redis:
            await self._redis.close()


_distributed_backend: Optional[RedisEventBackend] = None


def get_distributed_backend() -> Optional[RedisEventBackend]:
    global _distributed_backend
    if _distributed_backend is None:
        _distributed_backend = RedisEventBackend()
    return _distributed_backend
