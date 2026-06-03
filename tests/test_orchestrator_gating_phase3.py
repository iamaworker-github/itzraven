import asyncio

from itzraven.agents.base_agent import AgentResult, AgentStatus
from itzraven.agents.orchestrator import AgentOrchestrator


class _DummyAgent:
    def __init__(self, name: str):
        self.name = name
        self.context = {}
        self.run_called = False

    async def run(self) -> AgentResult:
        self.run_called = True
        return AgentResult(
            agent_name=self.name,
            status=AgentStatus.COMPLETED,
            findings=[],
            execution_time=0.0,
            metadata={},
        )


def test_phase3_enforced_mode_skips_ssrf_and_auth_agents_without_signals():
    orchestrator = AgentOrchestrator("https://example.com", gating_mode="enforced")
    ssrf_agent = _DummyAgent("SSRF Agent")
    auth_agent = _DummyAgent("Authentication Agent")
    orchestrator.agents = [ssrf_agent, auth_agent]

    result = asyncio.run(orchestrator.run_sequential())

    assert ssrf_agent.run_called is False
    assert auth_agent.run_called is False
    skipped_names = {
        agent_result.agent_name
        for agent_result in result.agent_results
        if (agent_result.metadata or {}).get("gating_enforced_skipped")
    }
    assert "SSRF Agent" in skipped_names
    assert "Authentication Agent" in skipped_names


def test_phase3_enforced_mode_does_not_skip_non_enforced_agents():
    orchestrator = AgentOrchestrator("https://example.com", gating_mode="enforced")
    command_agent = _DummyAgent("Command Injection Agent")
    orchestrator.agents = [command_agent]

    asyncio.run(orchestrator.run_sequential())

    assert command_agent.run_called is True


def test_phase3_enforced_mode_can_skip_idor_if_in_enforced_map():
    orchestrator = AgentOrchestrator("https://example.com", gating_mode="enforced")
    idor_agent = _DummyAgent("IDOR Agent")
    orchestrator.agents = [idor_agent]

    asyncio.run(orchestrator.run_sequential())

    # IDOR is now in the enforced gating map, so it may be skipped without signals
    assert idor_agent.run_called is False
    skipped_names = {
        agent_result.agent_name
        for agent_result in orchestrator.results
        if (agent_result.metadata or {}).get("gating_enforced_skipped")
    }
    assert "IDOR Agent" in skipped_names


def test_phase3_enforced_agent_map_includes_idor():
    orchestrator = AgentOrchestrator("https://example.com", gating_mode="enforced")

    assert "IDOR Agent" in orchestrator._ENFORCED_GATING_DECISION_MAP
    assert orchestrator._ENFORCED_GATING_DECISION_MAP["IDOR Agent"] == "IDOR Agent"


def test_phase3_enforced_mode_skips_idor_without_signals():
    orchestrator = AgentOrchestrator("https://example.com", gating_mode="enforced")

    assert orchestrator._should_skip_enforced_agent("IDOR Agent") is True
