"""Tests for the Typed Tool System (OpenHands Action/Observation pattern)."""

import pytest
from itzraven.core.tool_system import (
    ToolRegistry, ToolSpec, ToolAction, ToolObservation,
    RiskLevel, SecurityMiddleware,
    get_tool_registry, create_default_tools,
)


def test_tool_spec():
    spec = ToolSpec(name="test_tool", description="A test tool",
                    parameters={"target": {"type": "string", "required": True}},
                    risk_level=RiskLevel.LOW, category="testing")
    assert spec.name == "test_tool"
    assert spec.risk_level == RiskLevel.LOW


def test_tool_spec_openai_schema():
    spec = ToolSpec(name="nmap", description="Port scanner",
                    parameters={"target": {"type": "string", "description": "Target IP", "required": True},
                                "ports": {"type": "string", "description": "Ports"}},
                    risk_level=RiskLevel.MEDIUM, category="scanning")
    schema = spec.to_openai_schema()
    assert schema["function"]["name"] == "nmap"
    assert "target" in schema["function"]["parameters"]["properties"]


def test_tool_registry():
    registry = ToolRegistry()
    spec = ToolSpec(name="echo", description="Echo a message",
                    parameters={"msg": {"type": "string", "required": True}},
                    risk_level=RiskLevel.SAFE, category="utility")
    registry.register(spec, lambda msg: msg)
    assert registry.get_spec("echo") is not None
    assert len(registry.list_tools()) == 1


@pytest.mark.asyncio
async def test_tool_execution():
    registry = ToolRegistry()
    async def search(query: str):
        return f"Results for: {query}"

    registry.register(ToolSpec("search", "Search", {"query": {"type": "string", "required": True}},
                               RiskLevel.LOW, "utility"), search)
    action = ToolAction(tool_name="search", params={"query": "test"})
    obs = await registry.execute(action)
    assert obs.success is True
    assert "Results for: test" in obs.output


@pytest.mark.asyncio
async def test_tool_timeout():
    registry = ToolRegistry()

    async def slow():
        import asyncio
        await asyncio.sleep(10)

    registry.register(ToolSpec("slow", "Slow tool", {}, RiskLevel.HIGH, "test", timeout_seconds=1), slow)
    action = ToolAction(tool_name="slow")
    obs = await registry.execute(action)
    assert obs.success is False
    assert "Timeout" in (obs.error or "")


def test_default_tools():
    registry = ToolRegistry()
    create_default_tools(registry)
    tools = registry.list_tools()
    assert len(tools) >= 4
    schemas = registry.get_openai_schemas()
    assert len(schemas) >= 4


def test_security_middleware():
    mw = SecurityMiddleware(max_risk=RiskLevel.MEDIUM)
    safe_spec = ToolSpec("safe_tool", "Safe", {}, RiskLevel.LOW, "test")
    action = ToolAction(tool_name="safe_tool")
    assert mw.validate(action, safe_spec) is None

    risky_spec = ToolSpec("risky_tool", "Risky", {}, RiskLevel.CRITICAL, "test")
    result = mw.validate(action, risky_spec)
    assert result is not None
    assert "exceeds" in result


def test_security_blocked_tool():
    mw = SecurityMiddleware()
    mw.block_tool("danger")
    action = ToolAction(tool_name="danger")
    result = mw.validate(action)
    assert result is not None
    assert "blocked" in result


def test_registry_stats():
    registry = ToolRegistry()
    create_default_tools(registry)

    import asyncio
    action = ToolAction(tool_name="web_search", params={"query": "test"})
    asyncio.run(registry.execute(action))

    stats = registry.get_stats()
    assert stats["tools_registered"] >= 4
    assert stats["total_executions"] >= 1


def test_tool_registry_history():
    registry = ToolRegistry()
    registry._execution_history = [
        ToolObservation("a1", "nmap", True, output="open", duration_ms=100),
        ToolObservation("a2", "httpx", False, error="fail", duration_ms=50),
    ]
    history = registry.get_history(limit=5)
    assert len(history) == 2
    registry.clear_history()
    assert len(registry.get_history()) == 0


def test_singleton():
    r1 = get_tool_registry()
    r2 = get_tool_registry()
    assert r1 is r2
