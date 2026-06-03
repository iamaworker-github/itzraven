"""Tests for Distributed Scanning (Redis Streams backend)."""

from itzraven.core.distributed import RedisStreamConfig, RedisEventBackend


def test_redis_config_defaults():
    cfg = RedisStreamConfig()
    assert cfg.host == "127.0.0.1"
    assert cfg.port == 6379
    assert cfg.stream_name == "itzraven:events"
    assert cfg.consumer_group == "itzraven-workers"
    assert cfg.maxlen == 10000


def test_redis_config_custom():
    cfg = RedisStreamConfig(host="10.0.0.1", port=6380, password="secret", stream_name="custom:stream")
    assert cfg.host == "10.0.0.1"
    assert cfg.port == 6380
    assert cfg.password == "secret"
    assert cfg.stream_name == "custom:stream"


def test_backend_init():
    backend = RedisEventBackend()
    assert backend._available is False or backend._available is True
    assert backend.cfg is not None


def test_backend_not_connected_returns_false():
    import asyncio
    backend = RedisEventBackend(RedisStreamConfig(host="255.255.255.255", port=1))
    result = asyncio.run(backend.connect())
    assert result is False


def test_backend_publish_no_connect():
    import asyncio
    backend = RedisEventBackend()
    # Should not crash without connection
    asyncio.run(backend.publish("test.event", {"key": "value"}))
