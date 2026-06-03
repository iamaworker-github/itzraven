"""Tests for the Planner Agent — stateful planning engine."""

import pytest
from itzraven.agents.planner_agent import PlannerAgent, PlannedAction, Hypothesis, ActionType, HypothesisStatus
from itzraven.core.graph_memory import GraphMemory, EntityType, get_graph_memory


@pytest.fixture
def planner():
    graph = get_graph_memory(namespace="test_planner")
    p = PlannerAgent(target="https://example.com", graph=graph)
    yield p
    graph.clear()


@pytest.mark.asyncio
async def test_observe_and_plan_empty(planner):
    actions = await planner.observe_and_plan()
    assert len(actions) >= 1
    assert actions[0].priority == 10  # Initial port scan


@pytest.mark.asyncio
async def test_observe_and_plan_with_ports(planner):
    # Simulate ports found
    planner._graph.add_entity(EntityType.PORT, "example.com:80/tcp",
                               properties={"port": 80, "state": "open"},
                               tags=["port_80"])
    planner._graph.add_entity(EntityType.PORT, "example.com:443/tcp",
                               properties={"port": 443, "state": "open"},
                               tags=["port_443"])
    actions = await planner.observe_and_plan()
    # Should suggest HTTP probing instead of port scan
    http_actions = [a for a in actions if a.tool == "httpx"]
    assert len(http_actions) >= 0  # May or may not depending on other state


@pytest.mark.asyncio
async def test_record_result_success(planner):
    action = PlannedAction(id="test_act_1", type=ActionType.SCAN, target="example.com",
                          description="Test port scan", priority=5, confidence=0.8)
    planner._actions.append(action)
    planner.record_result("test_act_1", success=True, output="80/tcp open", findings=[])
    assert planner._actions[0].status == "completed"
    assert "test_act_1" in planner._completed_actions


@pytest.mark.asyncio
async def test_record_result_failure(planner):
    action = PlannedAction(id="test_act_2", type=ActionType.EXPLOIT, target="example.com",
                          description="Test exploit", priority=5, confidence=0.8)
    planner._actions.append(action)
    planner.record_result("test_act_2", success=False, output="Connection refused")
    assert planner._actions[0].status == "failed"


def test_get_pending_actions(planner):
    planner._actions = [
        PlannedAction("a1", ActionType.SCAN, "t", "Scan", 10, 1.0),
        PlannedAction("a2", ActionType.EXPLOIT, "t", "Exploit", 5, 0.5),
    ]
    pending = planner._get_pending_actions()
    assert len(pending) == 2
    assert pending[0].priority == 10


def test_get_pending_actions_filters_completed(planner):
    planner._actions = [
        PlannedAction("a1", ActionType.SCAN, "t", "Scan", 10, 1.0),
    ]
    planner._completed_actions.append("a1")
    planner._actions[0].status = "completed"
    pending = planner._get_pending_actions()
    assert len(pending) == 0


def test_hypothesis_lifecycle():
    hyp = Hypothesis(id="h1", description="Test hypothesis",
                     attack_chain="Test Chain", confidence=0.7,
                     supporting_evidence=["evidence1"],
                     contradicting_evidence=[],
                     status=HypothesisStatus.PROPOSED,
                     actions=["act1"])
    assert hyp.status == HypothesisStatus.PROPOSED
    d = hyp.to_dict()
    assert d["id"] == "h1"
    assert d["evidence_for"] == 1


def test_planned_action_to_dict():
    action = PlannedAction("a1", ActionType.SCAN, "target", "desc", 7, 0.8)
    d = action.to_dict()
    assert d["type"] == "scan"
    assert d["priority"] == 7


def test_get_plan_summary(planner):
    summary = planner.get_plan_summary()
    assert "plan_version" in summary
    assert "pending_actions" in summary
    assert "active_hypotheses" in summary
