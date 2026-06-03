"""Tests for the Exploit Chain Matrix."""

from itzraven.core.chain_matrix import (
    ExploitChain, ChainStep, ChainCategory,
    CHAINS, get_chain, find_chains_by_tag,
    find_chains_by_prerequisite, find_matching_chains, get_next_suggestions,
)


def test_chains_exist():
    assert len(CHAINS) >= 6


def test_get_chain():
    chain = get_chain("SSRF → Cloud Metadata → Credentials → Lateral Movement")
    assert chain is not None
    assert chain.category == ChainCategory.CLOUD


def test_chain_steps():
    chain = get_chain("SSRF → Cloud Metadata → Credentials → Lateral Movement")
    assert chain is not None
    assert len(chain.steps) >= 3
    assert all(isinstance(s, ChainStep) for s in chain.steps)


def test_find_chains_by_tag():
    chains = find_chains_by_tag("ssrf")
    assert len(chains) >= 1


def test_find_matching_chains():
    findings = ["SSRF vulnerability identified", "Target is cloud-hosted",
                "IMDS Access", "Credential Extraction"]
    matches = find_matching_chains(findings)
    assert len(matches) >= 1
    ssrf_chains = [m for m in matches if "SSRF" in m["chain"]]
    assert len(ssrf_chains) >= 1


def test_get_next_suggestions():
    # Use a pattern that matches chain steps
    findings = ["SSRF Detection", "IMDS Access", "Credential Extraction"]
    suggestions = get_next_suggestions(findings)
    assert len(suggestions) >= 1
    assert all("next_step" in s for s in suggestions)
    assert all("tools" in s for s in suggestions)


def test_chain_step_attributes():
    step = ChainStep(name="Test", description="Testing",
                     tools=["tool1"], techniques=["tech1"],
                     detection_patterns=["pattern1"],
                     success_indicators=["success"],
                     confidence_threshold=0.7)
    assert step.name == "Test"
    assert step.confidence_threshold == 0.7


def test_chain_to_dict():
    chain = ExploitChain(name="Test Chain", category=ChainCategory.WEB_APP,
                         description="Test", prerequisites=["test"],
                         steps=[ChainStep(name="Step1", description="First step")],
                         success_condition="done")
    d = chain.to_dict()
    assert d["name"] == "Test Chain"
    assert d["step_count"] == 1


def test_categories():
    categories = set(c.category for c in CHAINS)
    assert ChainCategory.WEB_APP in categories
    assert ChainCategory.CLOUD in categories
    assert ChainCategory.AD in categories
    assert ChainCategory.CONTAINER in categories
    assert ChainCategory.OSINT in categories


def test_find_chains_by_prerequisite():
    chains = find_chains_by_prerequisite("SSRF")
    assert len(chains) >= 1
