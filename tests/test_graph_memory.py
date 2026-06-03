"""Tests for the Graph Memory engine — entities, relationships, paths, feedback loop."""

import time
import pytest
from itzraven.core.graph_memory import (
    GraphMemory, Entity, Relationship,
    EntityType, RelationType, get_graph_memory,
)


@pytest.fixture
def graph():
    gm = GraphMemory(namespace="test")
    yield gm
    gm.clear()


def test_add_entity(graph):
    entity = graph.add_entity(EntityType.DOMAIN, "example.com",
                               properties={"registrar": "GoDaddy"},
                               source="test", confidence=0.9)
    assert entity.id == "domain:example.com"
    assert entity.type == EntityType.DOMAIN
    assert entity.name == "example.com"
    assert entity.properties["registrar"] == "GoDaddy"
    assert entity.confidence == 0.9


def test_add_entity_deduplication(graph):
    e1 = graph.add_entity(EntityType.EMAIL, "user@example.com")
    e2 = graph.add_entity(EntityType.EMAIL, "user@example.com",
                           properties={"verified": True})
    assert e1.id == e2.id
    assert e2.properties["verified"] is True


def test_get_entity(graph):
    graph.add_entity(EntityType.IP_ADDRESS, "192.168.1.1")
    entity = graph.get_entity("ip_address:192.168.1.1")
    assert entity is not None
    assert entity.name == "192.168.1.1"


def test_find_entity(graph):
    graph.add_entity(EntityType.ORGANIZATION, "Acme Corp", tags=["target"])
    graph.add_entity(EntityType.ORGANIZATION, "Globex", tags=["partner"])

    results = graph.find_entity(EntityType.ORGANIZATION, tag="target")
    assert len(results) == 1
    assert results[0].name == "Acme Corp"


def test_search_entities(graph):
    graph.add_entity(EntityType.EMAIL, "admin@example.com")
    graph.add_entity(EntityType.DOMAIN, "example.com")
    graph.add_entity(EntityType.EMAIL, "info@test.org")

    results = graph.search_entities("example")
    assert len(results) >= 2


def test_add_relation(graph):
    src = graph.add_entity(EntityType.DOMAIN, "example.com")
    tgt = graph.add_entity(EntityType.IP_ADDRESS, "93.184.216.34")

    rel = graph.add_relation(src.id, tgt.id, RelationType.RESOLVES_TO,
                              confidence=0.95, weight=1.0)
    assert rel is not None
    assert rel.source_id == src.id
    assert rel.target_id == tgt.id
    assert rel.type == RelationType.RESOLVES_TO


def test_relation_missing_entity(graph):
    rel = graph.add_relation("nonexistent", "nonexistent2", RelationType.RELATED_TO)
    assert rel is None


def test_get_relations(graph):
    src = graph.add_entity(EntityType.PERSON, "Alice")
    tgt1 = graph.add_entity(EntityType.EMAIL, "alice@test.com")
    tgt2 = graph.add_entity(EntityType.PHONE, "+1-555-0100")

    graph.add_relation(src.id, tgt1.id, RelationType.HAS_EMAIL)
    graph.add_relation(src.id, tgt2.id, RelationType.HAS_PHONE)

    rels = graph.get_relations(src.id)
    assert len(rels) == 2


def test_connected_entities(graph):
    org = graph.add_entity(EntityType.ORGANIZATION, "Corp")
    dom = graph.add_entity(EntityType.DOMAIN, "corp.com")
    ip = graph.add_entity(EntityType.IP_ADDRESS, "10.0.0.1")

    graph.add_relation(org.id, dom.id, RelationType.OWNS)
    graph.add_relation(dom.id, ip.id, RelationType.RESOLVES_TO)

    connected = graph.get_connected_entities(org.id, depth=2)
    assert len(connected) >= 1


def test_path_finding(graph):
    a = graph.add_entity(EntityType.PERSON, "Alice")
    b = graph.add_entity(EntityType.EMAIL, "alice@corp.com")
    c = graph.add_entity(EntityType.DOMAIN, "corp.com")
    d = graph.add_entity(EntityType.IP_ADDRESS, "10.0.0.1")
    e = graph.add_entity(EntityType.ORGANIZATION, "TargetCorp")

    graph.add_relation(a.id, b.id, RelationType.HAS_EMAIL)
    graph.add_relation(b.id, c.id, RelationType.BELONGS_TO)
    graph.add_relation(c.id, d.id, RelationType.RESOLVES_TO)
    graph.add_relation(c.id, e.id, RelationType.BELONGS_TO)

    paths = graph.find_paths(a.id, e.id, max_depth=4)
    assert len(paths) >= 1


def test_feedback_loop(graph):
    entity = graph.add_entity(EntityType.DOMAIN, "test.com", confidence=0.5)
    graph.give_feedback(entity.id, positive=True, amount=0.3)
    assert graph._entities[entity.id].confidence == pytest.approx(0.8)

    graph.give_feedback(entity.id, positive=False, amount=0.5)
    assert graph._entities[entity.id].confidence == pytest.approx(0.3)


def test_relation_feedback(graph):
    src = graph.add_entity(EntityType.PERSON, "Bob")
    tgt = graph.add_entity(EntityType.EMAIL, "bob@test.com")
    rel = graph.add_relation(src.id, tgt.id, RelationType.HAS_EMAIL, confidence=0.7)

    graph.give_relation_feedback(rel.id, positive=True, amount=0.2)
    assert graph._relationships[rel.id].confidence == pytest.approx(0.9)


def test_decay(graph):
    entity = graph.add_entity(EntityType.DOMAIN, "old.com", confidence=1.0)
    entity.last_seen = time.time() - (GraphMemory.DECAY_HALF_LIFE * 2)

    graph.decay_all(force=True)
    assert graph._entities[entity.id].confidence < 1.0


def test_cluster(graph):
    org = graph.add_entity(EntityType.ORGANIZATION, "MegaCorp")
    d1 = graph.add_entity(EntityType.DOMAIN, "megacorp.com")
    d2 = graph.add_entity(EntityType.DOMAIN, "megacorp.io")
    ip = graph.add_entity(EntityType.IP_ADDRESS, "10.0.0.1")

    graph.add_relation(org.id, d1.id, RelationType.OWNS)
    graph.add_relation(org.id, d2.id, RelationType.OWNS)
    graph.add_relation(d1.id, ip.id, RelationType.RESOLVES_TO)

    cluster = graph.get_cluster(org.id)
    assert cluster["entity_count"] >= 3
    assert "seed" in cluster


def test_persist_and_load(tmp_path):
    gm = GraphMemory(namespace="test_persist")
    gm._entities.clear()

    gm.add_entity(EntityType.DOMAIN, "persist-test.com", properties={"test": True})
    gm.add_entity(EntityType.IP_ADDRESS, "1.2.3.4")
    src = gm.get_entity("domain:persist-test.com")
    tgt = gm.get_entity("ip_address:1.2.3.4")
    if src and tgt:
        gm.add_relation(src.id, tgt.id, RelationType.RESOLVES_TO)

    gm.persist()

    # Load fresh
    gm2 = GraphMemory(namespace="test_persist")
    assert gm2.get_entity("domain:persist-test.com") is not None
    assert gm2.get_entity("ip_address:1.2.3.4") is not None

    gm.clear()
    gm2.clear()


def test_graph_stats(graph):
    graph.add_entity(EntityType.DOMAIN, "stats-test.com")
    graph.add_entity(EntityType.IP_ADDRESS, "5.6.7.8")

    stats = graph.get_stats()
    assert stats["total_entities"] >= 2
    assert "entity_types" in stats


def test_singleton():
    g1 = get_graph_memory("test_singleton")
    g2 = get_graph_memory("test_singleton")
    assert g1 is g2
    g1.clear()
