"""Tests for enhanced OSINT agents with full methodology integration."""

import pytest
from itzraven.agents.osint import (
    OSINTBaseAgent,
    DomainIntelAgent,
    EmailIntelAgent,
    TechIntelAgent,
    SocialIntelAgent,
    DNSIntelAgent,
    CloudIntelAgent,
    LeakIntelAgent,
    ShodanIntelAgent,
    VisualIntelAgent,
)


def test_osint_agent_imports():
    """All 10 OSINT agents should be importable."""
    assert OSINTBaseAgent is not None
    assert DomainIntelAgent is not None
    assert EmailIntelAgent is not None
    assert TechIntelAgent is not None
    assert SocialIntelAgent is not None
    assert DNSIntelAgent is not None
    assert CloudIntelAgent is not None
    assert LeakIntelAgent is not None
    assert ShodanIntelAgent is not None
    assert VisualIntelAgent is not None


def test_osint_base_passive_only():
    assert OSINTBaseAgent.passive_only is True


@pytest.mark.asyncio
async def test_osint_base_initialization():
    agent = OSINTBaseAgent(name="TestAgent", target="https://example.com")
    assert agent.name == "TestAgent"
    assert agent.target == "https://example.com"
    assert agent.passive_only is True
    assert agent._findings == []


@pytest.mark.asyncio
async def test_osint_base_check_passive():
    agent = OSINTBaseAgent(name="TestAgent", target="https://example.com")
    with pytest.raises(RuntimeError, match="passive-only"):
        agent.check_passive()


def test_osint_base_methodology_loading():
    agent = OSINTBaseAgent.__new__(OSINTBaseAgent)
    agent._findings = []
    methodology = agent._load_methodology()
    assert isinstance(methodology, str)
    # Should have content from osint_methodology.md
    if methodology:
        assert "OSINT" in methodology or "Reconnaissance" in methodology or "Phase" in methodology


def test_domain_intel_creation():
    agent = DomainIntelAgent(target="https://example.com")
    assert agent.domain == "example.com"


def test_tech_intel_creation():
    agent = TechIntelAgent(target="https://example.com")
    assert agent.domain == "example.com"


def test_social_intel_creation():
    agent = SocialIntelAgent(target="https://example.com")
    assert agent.domain == "example.com"


def test_dns_intel_creation():
    agent = DNSIntelAgent(target="https://example.com")
    assert agent.domain == "example.com"


def test_cloud_intel_creation():
    agent = CloudIntelAgent(target="https://example.com")
    assert agent.domain == "example.com"


def test_leak_intel_creation():
    agent = LeakIntelAgent(target="https://example.com")
    assert agent.domain == "example.com"


def test_email_intel_creation():
    agent = EmailIntelAgent(target="https://example.com")
    assert agent is not None


def test_shodan_intel_creation():
    agent = ShodanIntelAgent(target="https://example.com")
    assert agent is not None


def test_visual_intel_creation():
    agent = VisualIntelAgent(target="https://example.com")
    assert agent is not None


@pytest.mark.asyncio
async def test_domain_intel_run():
    """Verify DomainIntelAgent runs without errors."""
    agent = DomainIntelAgent(target="https://example.com")
    result = await agent.execute()
    assert result is not None
    assert result.agent_name == "DomainIntel"
    assert result.status == "completed"


@pytest.mark.asyncio
async def test_tech_intel_run():
    """Verify TechIntelAgent runs without errors."""
    agent = TechIntelAgent(target="https://example.com")
    result = await agent.execute()
    assert result is not None
    assert result.status == "completed"


@pytest.mark.asyncio
async def test_dns_intel_run():
    """Verify DNSIntelAgent runs without errors."""
    agent = DNSIntelAgent(target="https://example.com")
    result = await agent.execute()
    assert result is not None
    assert result.status == "completed"


@pytest.mark.asyncio
async def test_cloud_intel_run():
    """Verify CloudIntelAgent runs without errors."""
    agent = CloudIntelAgent(target="https://example.com")
    result = await agent.execute()
    assert result is not None
    assert result.status == "completed"


@pytest.mark.asyncio
async def test_leak_intel_run():
    """Verify LeakIntelAgent runs without errors."""
    agent = LeakIntelAgent(target="https://example.com")
    result = await agent.execute()
    assert result is not None
    assert result.status == "completed"


@pytest.mark.asyncio
async def test_social_intel_run():
    """Verify SocialIntelAgent runs without errors."""
    agent = SocialIntelAgent(target="https://example.com")
    result = await agent.execute()
    assert result is not None
    assert result.status == "completed"
