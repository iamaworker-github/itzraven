"""Tests for the token-bucket rate limiter."""

import pytest
from itzraven.core.rate_limiter import RateLimiter, TokenBucket


@pytest.mark.asyncio
async def test_token_bucket_basic():
    bucket = TokenBucket(rate=100, burst=50)
    assert bucket.tokens == 50
    await bucket.acquire(10)
    assert bucket.tokens == 40


@pytest.mark.asyncio
async def test_token_bucket_refill():
    bucket = TokenBucket(rate=1000, burst=100)
    await bucket.acquire(100)
    assert bucket.tokens == pytest.approx(0, abs=1)
    import asyncio
    await asyncio.sleep(0.05)
    bucket._refill()
    assert bucket.tokens > 0


@pytest.mark.asyncio
async def test_rate_limiter_per_target():
    limiter = RateLimiter(default_rate=50, default_burst=25)
    await limiter.acquire("https://example.com")
    stats = limiter.get_stats("https://example.com")
    assert stats["rate"] == 50
    assert stats["burst"] == 25


@pytest.mark.asyncio
async def test_rate_limiter_set_rate():
    limiter = RateLimiter(default_rate=10, default_burst=5)
    limiter.set_rate("https://test.com", rate=100, burst=50)
    stats = limiter.get_stats("https://test.com")
    assert stats["rate"] == 100
    assert stats["burst"] == 50


def test_rate_limiter_reset():
    limiter = RateLimiter()
    import asyncio
    asyncio.run(limiter.acquire("https://example.com"))
    assert "https://example.com" in limiter._buckets
    limiter.reset("https://example.com")
    assert "https://example.com" not in limiter._buckets


def test_rate_limiter_global_singleton():
    from itzraven.core.rate_limiter import get_rate_limiter
    r1 = get_rate_limiter()
    r2 = get_rate_limiter()
    assert r1 is r2
