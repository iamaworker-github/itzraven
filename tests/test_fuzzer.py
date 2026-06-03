"""Tests for the Fuzzing Engine."""

import pytest
from itzraven.toolkit.fuzzer import FuzzerEngine, FuzzResult


def test_fuzz_result_creation():
    result = FuzzResult(
        parameter="id",
        payload="<script>alert(1)</script>",
        url="https://example.com?id=test",
        status_code=200,
        response_size=1024,
        response_time=0.5,
        match_type="reflected",
    )
    assert result.parameter == "id"
    assert result.match_type == "reflected"
    d = result.to_dict()
    assert d["parameter"] == "id"
    assert d["status_code"] == 200


@pytest.mark.asyncio
async def test_fuzzer_initialization():
    fuzzer = FuzzerEngine(timeout=5.0, max_concurrent=5)
    assert fuzzer.timeout == 5.0
    assert fuzzer.max_concurrent == 5


@pytest.mark.asyncio
async def test_fuzz_paths():
    fuzzer = FuzzerEngine(timeout=5.0, max_concurrent=10)
    results = await fuzzer.fuzz_paths("https://httpbin.org", paths=["/get"])
    # At minimum should not crash; httpbin.org/get returns 200
    assert isinstance(results, list)


def test_fuzzer_imports():
    from itzraven.toolkit import FuzzerEngine as FE, FuzzResult as FR
    assert FE is not None
    assert FR is not None
