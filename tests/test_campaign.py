"""Tests for Campaign Manager."""

import pytest
from itzraven.core.campaign import CampaignManager, CrossCorrelation
from itzraven.core.graph_memory import GraphMemory, EntityType, RelationType, get_graph_memory


def test_cross_correlation():
    c = CrossCorrelation(type="shared_ip", description="Same IP", targets=["a.com", "b.com"],
                         evidence="IP: 1.2.3.4", confidence=0.9, severity="medium")
    assert c.type == "shared_ip"
    d = c.to_dict()
    assert d["confidence"] == 0.9


def test_campaign_add_remove():
    camp = CampaignManager(name="test_campaign")
    camp.add_target("example.com")
    camp.add_target("test.org")
    assert "example.com" in camp._targets
    assert len(camp.list_targets()) >= 2
    assert camp.remove_target("example.com") is True
    assert camp.remove_target("nonexistent") is False


@pytest.mark.asyncio
async def test_correlate_shared_ips():
    graph = get_graph_memory(namespace="test_campaign")
    camp = CampaignManager(name="test_corr", graph=graph)

    # Add entities with IDs that match the domain: prefix used in graph memory
    src1 = graph.add_entity(EntityType.DOMAIN, "a.com")
    src2 = graph.add_entity(EntityType.DOMAIN, "b.com")
    tgt = graph.add_entity(EntityType.IP_ADDRESS, "10.0.0.1")
    if src1 and src2 and tgt:
        graph.add_relation(src1.id, tgt.id, RelationType.RESOLVES_TO)
        graph.add_relation(src2.id, tgt.id, RelationType.RESOLVES_TO)

    # Add targets with names matching entity names
    camp.add_target("a.com")
    camp.add_target("b.com")

    correlations = await camp.correlate_all()
    shared_ip = [c for c in correlations if c.type == "shared_ip"]
    graph.clear()


def test_get_correlations():
    camp = CampaignManager(name="test_get")
    camp._correlations = [
        CrossCorrelation("a", "desc", ["t1"], "ev", 0.5, "low"),
        CrossCorrelation("b", "desc", ["t2"], "ev", 0.9, "high"),
    ]
    high = camp.get_correlations(min_confidence=0.7)
    assert len(high) == 1
    assert high[0].type == "b"


def test_persist(tmp_path):
    camp = CampaignManager(name="test_persist")
    persist_dir = tmp_path / "campaigns" / "test_persist"
    persist_dir.mkdir(parents=True, exist_ok=True)
    camp._campaign_dir = persist_dir
    camp.add_target("example.com")
    camp.persist()
    assert (persist_dir / "state.json").exists()
