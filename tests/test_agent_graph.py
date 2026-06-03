"""Tests for Graph-based Agent Orchestration Runtime."""

import pytest
from itzraven.core.agent_graph import (
    StateGraph, GraphState, GraphNode, NodeType,
    GroupChat, AgentSpec, Swarm, Condenser,
    ToolAction, ToolObservation, ToolExecutor,
)


def test_graph_state():
    state = GraphState()
    assert state.step_count == 0
    assert state.messages == []
    d = state.to_dict()
    assert "step_count" in d


def test_graph_node():
    def handler(state):
        state.messages.append({"role": "assistant", "content": "hello"})
        return state
    node = GraphNode(name="test", node_type=NodeType.AGENT, handler=handler)
    assert node.name == "test"
    assert node.node_type == NodeType.AGENT


@pytest.mark.asyncio
async def test_graph_node_run():
    def handler(state):
        state.step_count += 1
        return state
    node = GraphNode(name="increment", node_type=NodeType.AGENT, handler=handler)
    state = GraphState()
    result = await node.run(state)
    assert result.step_count == 1


@pytest.mark.asyncio
async def test_stategraph_simple():
    graph = StateGraph(name="test")

    def node_a(state):
        state.messages.append({"role": "assistant", "content": "A"})
        return state
    def node_b(state):
        state.messages.append({"role": "assistant", "content": "B"})
        return state

    graph.add_node("a", node_a)
    graph.add_node("b", node_b)
    graph.add_edge("a", "b")
    graph.set_entry("a")

    result = await graph.run()
    assert len(result.messages) == 2
    assert result.messages[0]["content"] == "A"
    assert result.messages[1]["content"] == "B"


@pytest.mark.asyncio
async def test_stategraph_conditional():
    graph = StateGraph(name="conditional")

    def node_a(state):
        state.metadata["score"] = 85
        return state
    def node_high(state):
        state.messages.append({"role": "assistant", "content": "HIGH"})
        return state
    def node_low(state):
        state.messages.append({"role": "assistant", "content": "LOW"})
        return state

    def route_by_score(state):
        return "high" if state.metadata.get("score", 0) > 50 else "low"

    graph.add_node("start", node_a)
    graph.add_node("high", node_high)
    graph.add_node("low", node_low)
    graph.add_edge("start", "high", condition=route_by_score)
    graph.add_edge("start", "low", condition=route_by_score)
    graph.set_entry("start")

    result = await graph.run()
    assert result.messages[0]["content"] == "HIGH"


def test_group_chat():
    agents = [
        AgentSpec(name="agent1", system_prompt="You are a scanner",
                  tools=["nmap", "httpx"]),
        AgentSpec(name="agent2", system_prompt="You are an analyzer",
                  tools=["nuclei"]),
    ]
    chat = GroupChat(agents=agents, max_turns=10)
    assert len(chat.agents) == 2
    chat.add_message("user", "Scan example.com")
    assert len(chat._messages) == 1
    context = chat.get_context()
    assert "Scan example.com" in context


def test_swarm():
    agents = [
        AgentSpec(name="port_scanner", system_prompt="Scan ports"),
        AgentSpec(name="web_analyzer", system_prompt="Analyze web apps"),
    ]
    swarm = Swarm(agents=agents)
    swarm.register_capability("port_scanner", "port scan")
    swarm.register_capability("web_analyzer", "web")

    routes = swarm.route_task("Run a port scan on 10.0.0.1")
    assert "port_scanner" in routes

    swarm.share_context("target", "10.0.0.1")
    assert swarm._shared_context["target"] == "10.0.0.1"


def test_condenser():
    condenser = Condenser(max_messages=5, summarize_threshold=2)
    messages = [{"role": "user", "content": f"msg {i}"} for i in range(20)]
    compressed = condenser.compress(messages)
    assert len(compressed) < 20
    assert compressed[0] == messages[0]


def test_tool_action():
    action = ToolAction(tool_name="nmap", params={"target": "10.0.0.1", "ports": "80,443"})
    assert action.tool_name == "nmap"
    assert action.params["target"] == "10.0.0.1"


def test_tool_observation():
    obs = ToolObservation(action_id="a1", tool_name="nmap", success=True,
                          output="80/tcp open", duration_ms=1500)
    assert obs.success is True


@pytest.mark.asyncio
async def test_tool_executor():
    executor = ToolExecutor()

    def scan_handler(target: str, ports: str = "80"):
        return f"Scanned {target}:{ports}"

    executor.register("scan", scan_handler)
    action = ToolAction(tool_name="scan", params={"target": "10.0.0.1"})
    obs = await executor.execute(action)
    assert obs.success is True
    assert "Scanned" in obs.output


def test_graph_visualize():
    graph = StateGraph(name="viz_test")
    graph.add_node("a", lambda s: s)
    graph.add_node("b", lambda s: s)
    graph.add_edge("a", "b")
    dot = graph.visualize()
    assert "digraph" in dot
    assert "a" in dot
    assert "b" in dot


def test_agent_spec():
    spec = AgentSpec(name="pentest_agent", system_prompt="Pentest", tools=["nmap", "sqlmap"],
                     skills=["recon", "exploit"], config={"depth": "deep"})
    assert spec.name == "pentest_agent"
    assert len(spec.tools) == 2
    assert len(spec.skills) == 2
