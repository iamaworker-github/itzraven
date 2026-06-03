import asyncio
import time
from typing import Optional, Dict, Any, Tuple
from dataclasses import dataclass, field

import httpx

from itzraven.core.logger import get_logger
from itzraven.core.config import get_config

logger = get_logger()
config = get_config()


@dataclass
class HttpClientStats:
    total_requests: int = 0
    total_bytes: int = 0
    total_time_ms: float = 0.0
    errors: int = 0
    timeouts: int = 0
    pool_hits: int = 0

    @property
    def avg_latency_ms(self) -> float:
        return self.total_time_ms / max(self.total_requests, 1)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_requests": self.total_requests,
            "total_bytes": self.total_bytes,
            "total_time_ms": round(self.total_time_ms, 2),
            "avg_latency_ms": round(self.avg_latency_ms, 2),
            "errors": self.errors,
            "timeouts": self.timeouts,
            "pool_hits": self.pool_hits,
        }


class SharedHttpClient:
    _instances: Dict[str, "SharedHttpClient"] = {}
    _lock = asyncio.Lock()

    def __init__(
        self,
        name: str = "default",
        max_connections: int = 100,
        max_keepalive: int = 20,
        timeout: float = 30.0,
        proxy: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
    ):
        self.name = name
        self._max_connections = max_connections
        self._max_keepalive = max_keepalive
        self._timeout = timeout
        self._proxy = proxy
        self._headers = headers or {}
        self._client: Optional[httpx.AsyncClient] = None
        self._stats = HttpClientStats()
        self._semaphore = asyncio.Semaphore(max_connections * 2)

    async def get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            limits = httpx.Limits(
                max_connections=self._max_connections,
                max_keepalive_connections=self._max_keepalive,
                keepalive_expiry=30.0,
            )
            timeout_cfg = httpx.Timeout(
                connect=self._timeout,
                read=self._timeout,
                write=self._timeout,
                pool=self._timeout,
            )
            client_kwargs: Dict[str, Any] = {
                "limits": limits,
                "timeout": timeout_cfg,
                "follow_redirects": True,
            }
            if self._proxy:
                client_kwargs["proxy"] = self._proxy
            if self._headers:
                client_kwargs["headers"] = self._headers
            self._client = httpx.AsyncClient(**client_kwargs)
            logger.debug(f"HttpClient[{self.name}]: created pool ({self._max_connections} max)")
        return self._client

    async def request(
        self,
        method: str,
        url: str,
        **kwargs: Any,
    ) -> httpx.Response:
        start = time.monotonic()
        async with self._semaphore:
            client = await self.get_client()
            try:
                response = await client.request(method, url, **kwargs)
                elapsed = (time.monotonic() - start) * 1000
                self._stats.total_requests += 1
                self._stats.total_bytes += len(response.content)
                self._stats.total_time_ms += elapsed
                return response
            except httpx.TimeoutException:
                self._stats.timeouts += 1
                raise
            except Exception:
                self._stats.errors += 1
                raise

    async def get(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("POST", url, **kwargs)

    async def close(self):
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None
            logger.debug(f"HttpClient[{self.name}]: closed")

    @property
    def stats(self) -> Dict[str, Any]:
        return self._stats.to_dict()

    @classmethod
    async def get_instance(cls, name: str = "default", **kwargs: Any) -> "SharedHttpClient":
        async with cls._lock:
            if name not in cls._instances:
                cls._instances[name] = SharedHttpClient(name, **kwargs)
            return cls._instances[name]

    @classmethod
    async def close_all(cls):
        for name, instance in cls._instances.items():
            await instance.close()
        cls._instances.clear()
        logger.info("All HTTP clients closed")


_http_client: Optional[SharedHttpClient] = None


async def get_http_client(
    max_connections: int = 100,
    max_keepalive: int = 20,
    timeout: float = 30.0,
) -> SharedHttpClient:
    global _http_client
    if _http_client is None:
        proxy = config.get("http_proxy") or config.get("https_proxy")
        _http_client = SharedHttpClient(
            name="default",
            max_connections=max_connections,
            max_keepalive=max_keepalive,
            timeout=timeout,
            proxy=proxy,
        )
        await _http_client.get_client()
    return _http_client
