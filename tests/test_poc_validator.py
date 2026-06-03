import asyncio
from types import SimpleNamespace

from itzraven.agents.base_agent import Finding
from itzraven.agents.orchestrator import AgentOrchestrator
from itzraven.agents.poc_validator_agent import PoCValidatorAgent


class _RuntimeOK:
    async def execute_exploit(self, exploit_code: str, target_url: str):
        return SimpleNamespace(exception=None)


class _RuntimeFail:
    async def execute_exploit(self, exploit_code: str, target_url: str):
        return SimpleNamespace(exception="RuntimeError: boom")


def test_add_default_agents_includes_poc_validator_for_pentest_and_bugbounty():
    pentest = AgentOrchestrator("https://example.com", mode="pentest")
    pentest.add_default_agents()
    assert any(isinstance(a, PoCValidatorAgent) for a in pentest.agents)

    bugbounty = AgentOrchestrator("https://example.com", mode="bugbounty")
    bugbounty.add_default_agents()
    assert any(isinstance(a, PoCValidatorAgent) for a in bugbounty.agents)

    osint = AgentOrchestrator("https://example.com", mode="osint")
    osint.add_default_agents()
    assert not any(isinstance(a, PoCValidatorAgent) for a in osint.agents)


def test_high_severity_without_poc_is_marked_unvalidated_missing():
    agent = PoCValidatorAgent("https://example.com")
    finding = Finding(
        title="SQLi",
        description="desc",
        severity="high",
        category="injection",
        evidence="evidence",
        proof_of_concept=None,
    )

    status = asyncio.run(agent._validate_finding(finding))

    assert status == "unvalidated_poc_missing"
    assert finding.validation_status == "unvalidated_poc_missing"


def test_executable_poc_success_marks_validated():
    agent = PoCValidatorAgent("https://example.com")
    agent.python = _RuntimeOK()
    finding = Finding(
        title="XSS",
        description="desc",
        severity="medium",
        category="xss",
        evidence="evidence",
        proof_of_concept="result = 1 + 1",
    )

    status = asyncio.run(agent._validate_finding(finding))

    assert status == "validated"
    assert finding.validation_status == "validated"


def test_executable_poc_failure_marks_failed_validation():
    agent = PoCValidatorAgent("https://example.com")
    agent.python = _RuntimeFail()
    finding = Finding(
        title="CMDi",
        description="desc",
        severity="medium",
        category="command_injection",
        evidence="evidence",
        proof_of_concept="result = 1 / 0",
    )

    status = asyncio.run(agent._validate_finding(finding))

    assert status == "failed_validation"
    assert finding.validation_status == "failed_validation"


def test_non_executable_poc_marked_non_executable():
    agent = PoCValidatorAgent("https://example.com")
    finding = Finding(
        title="HTTP repro",
        description="desc",
        severity="low",
        category="info",
        evidence="evidence",
        proof_of_concept="GET https://example.com?q=' OR 1=1 --",
    )

    status = asyncio.run(agent._validate_finding(finding))

    assert status == "unvalidated_poc_non_executable"
    assert finding.validation_status == "unvalidated_poc_non_executable"
