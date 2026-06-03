"""Tests for LLM Security Testing Agent."""

from itzraven.agents.llm_security_agent import (
    LLMSecurityAgent, LLMSecurityTest, LLM_TESTS, PROMPT_INJECTION_PAYLOADS,
)


def test_llm_security_test():
    test = LLMSecurityTest("Test", "prompt_injection", ["payload"], ["keyword"], "high")
    assert test.name == "Test"
    assert test.severity == "high"


def test_llm_tests_defined():
    assert len(LLM_TESTS) >= 5
    names = [t.name for t in LLM_TESTS]
    assert "Direct Prompt Injection" in names
    assert "System Prompt Leakage" in names
    assert "Training Data Extraction" in names
    assert "Denial of Service" in names
    assert "Excessive Agency" in names


def test_prompt_injection_payloads():
    assert len(PROMPT_INJECTION_PAYLOADS) >= 10
    assert any("Ignore previous" in p for p in PROMPT_INJECTION_PAYLOADS)
    assert any("DAN" in p for p in PROMPT_INJECTION_PAYLOADS)


def test_agent_creation():
    agent = LLMSecurityAgent(target="https://example.com/chat")
    assert agent.name == "LLMSecurity"
    assert agent.llm_endpoint == "https://example.com/chat"


def test_detect_anomaly():
    assert LLMSecurityAgent._detect_anomaly("I will ignore previous instructions", "test") is True
    assert LLMSecurityAgent._detect_anomaly("Hello, how are you?", "test") is False
