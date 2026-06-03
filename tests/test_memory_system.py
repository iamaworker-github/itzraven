"""
Unit tests for Memory System

Tests cover:
- Neo4j operations (CRUD, queries, relationships)
- Qdrant operations (storage, semantic search)
- Redis operations (state, cache, locks)
- Memory Manager integration
- Event Bus integration
- Performance characteristics
"""

import asyncio
import pytest
from datetime import datetime
from typing import List

from itzraven.core.memory_manager import (
    MemoryManager,
    Vulnerability,
    VulnerabilitySeverity,
    Target,
    Exploit,
    ExploitType,
    ScanState,
    AttackPath,
)
from itzraven.core.event_bus import EventBus
from itzraven.core.events import FindingDiscoveredEvent, ScanStartedEvent


@pytest.fixture
async def memory_manager():
    """Create memory manager for testing"""
    manager = MemoryManager(
        neo4j_uri="bolt://localhost:7687",
        neo4j_user="neo4j",
        neo4j_password="test_password",
        qdrant_host="localhost",
        qdrant_port=6333,
        redis_url="redis://localhost:6379/1",  # Use DB 1 for testing
    )
    await manager.initialize()
    yield manager
    await manager.close()


@pytest.fixture
async def event_bus():
    """Create event bus for testing"""
    bus = EventBus()
    await bus.start()
    yield bus
    await bus.stop()


@pytest.fixture
def sample_vulnerability():
    """Create sample vulnerability for testing"""
    return Vulnerability(
        id="vuln-test-001",
        title="SQL Injection in login form",
        description="Time-based blind SQL injection vulnerability",
        severity=VulnerabilitySeverity.HIGH,
        category="sql_injection",
        cwe_id="CWE-89",
        cvss_score=8.5,
        confidence=0.95,
        evidence="Sleep delay observed: 5 seconds",
        proof_of_concept="' OR SLEEP(5)--",
        remediation="Use parameterized queries",
    )


# ============================================================================
# NEO4J TESTS
# ============================================================================

@pytest.mark.asyncio
async def test_store_vulnerability_neo4j(memory_manager, sample_vulnerability):
    """Test storing vulnerability in Neo4j"""
    target_url = "https://example.com"

    vuln_id = await memory_manager.store_vulnerability(
        sample_vulnerability,
        target_url
    )

    assert vuln_id == sample_vulnerability.id

    # Verify it was stored
    retrieved = await memory_manager.get_vulnerability(vuln_id)
    assert retrieved is not None
    assert retrieved.title == sample_vulnerability.title
    assert retrieved.severity == sample_vulnerability.severity


@pytest.mark.asyncio
async def test_create_vulnerability_relationship(memory_manager, sample_vulnerability):
    """Test creating target-vulnerability relationship"""
    target_url = "https://example.com"

    await memory_manager.store_vulnerability(sample_vulnerability, target_url)

    # Query relationship
    async with memory_manager.neo4j_driver.session() as session:
        result = await session.run(
            """
            MATCH (t:Target {url: $url})-[:HAS_VULNERABILITY]->(v:Vulnerability {id: $vuln_id})
            RETURN t, v
            """,
            url=target_url,
            vuln_id=sample_vulnerability.id,
        )
        record = await result.single()
        assert record is not None


@pytest.mark.asyncio
async def test_find_attack_paths(memory_manager):
    """Test finding attack paths in graph"""
    # Create chain of vulnerabilities
    vuln1 = Vulnerability(
        id="vuln-001",
        title="Initial Access",
        description="SQL Injection",
        severity=VulnerabilitySeverity.HIGH,
        category="sql_injection",
        confidence=0.9,
    )

    vuln2 = Vulnerability(
        id="vuln-002",
        title="Privilege Escalation",
        description="Sudo misconfiguration",
        severity=VulnerabilitySeverity.CRITICAL,
        category="privilege_escalation",
        confidence=0.85,
        metadata={"impact": "privilege_escalation"},
    )

    # Store vulnerabilities
    await memory_manager.store_vulnerability(vuln1, "https://example.com")
    await memory_manager.store_vulnerability(vuln2, "https://example.com")

    # Create relationship
    async with memory_manager.neo4j_driver.session() as session:
        await session.run(
            """
            MATCH (v1:Vulnerability {id: $id1})
            MATCH (v2:Vulnerability {id: $id2})
            MERGE (v1)-[:LEADS_TO]->(v2)
            """,
            id1=vuln1.id,
            id2=vuln2.id,
        )

    # Find paths
    paths = await memory_manager.find_attack_paths(
        from_severity="high",
        to_impact="privilege_escalation",
        max_depth=5,
    )

    assert len(paths) > 0
    assert paths[0].length >= 1


# ============================================================================
# QDRANT TESTS
# ============================================================================

@pytest.mark.asyncio
async def test_store_vulnerability_qdrant(memory_manager, sample_vulnerability):
    """Test storing vulnerability in Qdrant"""
    await memory_manager._store_vulnerability_qdrant(sample_vulnerability)

    # Verify it was stored
    results = memory_manager.qdrant_client.scroll(
        collection_name="findings",
        limit=1,
        with_payload=True,
        with_vectors=False,
    )

    assert len(results[0]) > 0


@pytest.mark.asyncio
async def test_semantic_search(memory_manager):
    """Test semantic search for similar vulnerabilities"""
    # Store multiple vulnerabilities
    vulns = [
        Vulnerability(
            id=f"vuln-{i}",
            title=f"SQL Injection variant {i}",
            description="SQL injection in login form",
            severity=VulnerabilitySeverity.HIGH,
            category="sql_injection",
            confidence=0.9,
            evidence="Error-based SQL injection",
        )
        for i in range(5)
    ]

    for vuln in vulns:
        await memory_manager.store_vulnerability(vuln, "https://example.com")

    # Search for similar
    query_vuln = Vulnerability(
        id="query-001",
        title="SQL Injection",
        description="SQL injection vulnerability in authentication",
        severity=VulnerabilitySeverity.HIGH,
        category="sql_injection",
        confidence=0.9,
        evidence="Time-based blind SQL injection",
    )

    similar = await memory_manager.search_similar_vulnerabilities(
        query_vuln,
        limit=3,
        min_confidence=0.7,
    )

    assert len(similar) > 0
    assert all(v.category == "sql_injection" for v in similar)


@pytest.mark.asyncio
async def test_semantic_search_filters(memory_manager):
    """Test semantic search with filters"""
    # Store vulnerabilities with different severities
    high_vuln = Vulnerability(
        id="vuln-high",
        title="Critical XSS",
        description="Stored XSS in admin panel",
        severity=VulnerabilitySeverity.HIGH,
        category="xss",
        confidence=0.95,
        evidence="XSS payload executed",
    )

    low_vuln = Vulnerability(
        id="vuln-low",
        title="Minor XSS",
        description="Reflected XSS in search",
        severity=VulnerabilitySeverity.LOW,
        category="xss",
        confidence=0.6,
        evidence="XSS in non-critical page",
    )

    await memory_manager.store_vulnerability(high_vuln, "https://example.com")
    await memory_manager.store_vulnerability(low_vuln, "https://example.com")

    # Search with confidence filter
    query = Vulnerability(
        id="query",
        title="XSS vulnerability",
        description="Cross-site scripting",
        severity=VulnerabilitySeverity.MEDIUM,
        category="xss",
        confidence=0.8,
        evidence="XSS test",
    )

    results = await memory_manager.search_similar_vulnerabilities(
        query,
        limit=10,
        min_confidence=0.9,  # Should only return high_vuln
    )

    assert len(results) == 1
    assert results[0].id == "vuln-high"


# ============================================================================
# REDIS TESTS
# ============================================================================

@pytest.mark.asyncio
async def test_store_scan_state(memory_manager):
    """Test storing scan state in Redis"""
    scan_state = ScanState(
        scan_id="scan-001",
        target="https://example.com",
        mode="pentest",
        status="running",
        start_time=datetime.now(),
        agents_total=5,
        agents_completed=2,
        findings_count=10,
        current_phase="exploitation",
    )

    await memory_manager.store_scan_state(scan_state)

    # Retrieve and verify
    retrieved = await memory_manager.get_scan_state("scan-001")
    assert retrieved is not None
    assert retrieved.target == scan_state.target
    assert retrieved.agents_total == 5
    assert retrieved.findings_count == 10


@pytest.mark.asyncio
async def test_scan_lock_acquire_release(memory_manager):
    """Test distributed scan locking"""
    target = "https://example.com"
    scan_id = "scan-001"

    # Acquire lock
    acquired = await memory_manager.acquire_scan_lock(target, scan_id)
    assert acquired is True

    # Try to acquire again (should fail)
    acquired_again = await memory_manager.acquire_scan_lock(target, "scan-002")
    assert acquired_again is False

    # Release lock
    released = await memory_manager.release_scan_lock(target, scan_id)
    assert released is True

    # Now should be able to acquire
    acquired_new = await memory_manager.acquire_scan_lock(target, "scan-002")
    assert acquired_new is True


@pytest.mark.asyncio
async def test_vulnerability_caching(memory_manager, sample_vulnerability):
    """Test vulnerability caching in Redis"""
    # Store vulnerability (should cache it)
    await memory_manager.store_vulnerability(
        sample_vulnerability,
        "https://example.com"
    )

    # First retrieval (cache hit)
    vuln1 = await memory_manager.get_vulnerability(sample_vulnerability.id)
    cache_hits_1 = memory_manager.stats["cache_hits"]

    # Second retrieval (should also be cache hit)
    vuln2 = await memory_manager.get_vulnerability(sample_vulnerability.id)
    cache_hits_2 = memory_manager.stats["cache_hits"]

    assert vuln1 is not None
    assert vuln2 is not None
    assert cache_hits_2 > cache_hits_1


# ============================================================================
# EVENT BUS INTEGRATION TESTS
# ============================================================================

@pytest.mark.asyncio
async def test_event_integration_finding_discovered(event_bus):
    """Test automatic storage when finding.discovered event is published"""
    memory_manager = MemoryManager(event_bus=event_bus)
    await memory_manager.initialize()

    # Publish finding discovered event
    event = FindingDiscoveredEvent(
        finding_id="test-finding-001",
        agent_name="SQL Agent",
        title="SQL Injection",
        description="SQL injection in login",
        severity="high",
        category="sql_injection",
        evidence="Error message",
        confidence=0.9,
        target="https://example.com",
    )

    await event_bus.publish_event(event)

    # Wait for event processing
    await asyncio.sleep(0.5)

    # Verify it was stored
    vuln = await memory_manager.get_vulnerability("test-finding-001")
    assert vuln is not None
    assert vuln.title == "SQL Injection"

    await memory_manager.close()


@pytest.mark.asyncio
async def test_event_integration_scan_started(event_bus):
    """Test automatic state initialization when scan.started event is published"""
    memory_manager = MemoryManager(event_bus=event_bus)
    await memory_manager.initialize()

    # Publish scan started event
    event = ScanStartedEvent(
        scan_id="test-scan-001",
        target="https://example.com",
        mode="pentest",
        agent_count=5,
    )

    await event_bus.publish_event(event)

    # Wait for event processing
    await asyncio.sleep(0.5)

    # Verify state was stored
    state = await memory_manager.get_scan_state("test-scan-001")
    assert state is not None
    assert state.target == "https://example.com"
    assert state.agents_total == 5

    await memory_manager.close()


# ============================================================================
# PERFORMANCE TESTS
# ============================================================================

@pytest.mark.asyncio
async def test_performance_bulk_storage(memory_manager):
    """Test bulk storage performance"""
    import time

    # Create 100 vulnerabilities
    vulns = [
        Vulnerability(
            id=f"perf-vuln-{i}",
            title=f"Vulnerability {i}",
            description=f"Test vulnerability {i}",
            severity=VulnerabilitySeverity.MEDIUM,
            category="test",
            confidence=0.8,
            evidence=f"Evidence {i}",
        )
        for i in range(100)
    ]

    # Store all
    start = time.time()
    for vuln in vulns:
        await memory_manager.store_vulnerability(vuln, "https://example.com")
    duration = time.time() - start

    # Should handle 100 vulnerabilities in reasonable time
    assert duration < 30  # 30 seconds for 100 items
    throughput = 100 / duration
    print(f"Storage throughput: {throughput:.1f} vulns/second")


@pytest.mark.asyncio
async def test_performance_semantic_search(memory_manager):
    """Test semantic search performance"""
    import time

    # Store some vulnerabilities
    for i in range(50):
        vuln = Vulnerability(
            id=f"search-vuln-{i}",
            title=f"SQL Injection {i}",
            description="SQL injection vulnerability",
            severity=VulnerabilitySeverity.HIGH,
            category="sql_injection",
            confidence=0.9,
            evidence="SQL error",
        )
        await memory_manager.store_vulnerability(vuln, "https://example.com")

    # Perform searches
    query = Vulnerability(
        id="query",
        title="SQL Injection",
        description="SQL injection test",
        severity=VulnerabilitySeverity.HIGH,
        category="sql_injection",
        confidence=0.9,
        evidence="Test",
    )

    start = time.time()
    for _ in range(10):
        await memory_manager.search_similar_vulnerabilities(query, limit=10)
    duration = time.time() - start

    avg_latency = (duration / 10) * 1000  # ms
    assert avg_latency < 100  # <100ms per search
    print(f"Average search latency: {avg_latency:.1f}ms")


@pytest.mark.asyncio
async def test_performance_neo4j_queries(memory_manager):
    """Test Neo4j query performance"""
    import time

    # Create vulnerability chain
    for i in range(10):
        vuln = Vulnerability(
            id=f"chain-vuln-{i}",
            title=f"Vulnerability {i}",
            description=f"Part of chain {i}",
            severity=VulnerabilitySeverity.HIGH,
            category="test",
            confidence=0.9,
            evidence=f"Evidence {i}",
        )
        await memory_manager.store_vulnerability(vuln, "https://example.com")

    # Create relationships
    async with memory_manager.neo4j_driver.session() as session:
        for i in range(9):
            await session.run(
                """
                MATCH (v1:Vulnerability {id: $id1})
                MATCH (v2:Vulnerability {id: $id2})
                MERGE (v1)-[:LEADS_TO]->(v2)
                """,
                id1=f"chain-vuln-{i}",
                id2=f"chain-vuln-{i+1}",
            )

    # Query paths
    start = time.time()
    paths = await memory_manager.find_attack_paths(
        from_severity="high",
        to_impact="privilege_escalation",
        max_depth=10,
    )
    duration = time.time() - start

    assert duration < 1.0  # <1 second
    print(f"Path finding latency: {duration*1000:.1f}ms")


# ============================================================================
# INTEGRATION TESTS
# ============================================================================

@pytest.mark.asyncio
async def test_full_workflow(memory_manager, event_bus):
    """Test complete workflow: store, search, query paths"""
    # 1. Store multiple vulnerabilities
    vulns = [
        Vulnerability(
            id="workflow-001",
            title="SQL Injection",
            description="SQL injection in login",
            severity=VulnerabilitySeverity.HIGH,
            category="sql_injection",
            confidence=0.95,
            evidence="Error-based",
        ),
        Vulnerability(
            id="workflow-002",
            title="XSS",
            description="Stored XSS in comments",
            severity=VulnerabilitySeverity.MEDIUM,
            category="xss",
            confidence=0.85,
            evidence="Script executed",
        ),
        Vulnerability(
            id="workflow-003",
            title="Privilege Escalation",
            description="Sudo misconfiguration",
            severity=VulnerabilitySeverity.CRITICAL,
            category="privilege_escalation",
            confidence=0.9,
            evidence="Root access gained",
            metadata={"impact": "privilege_escalation"},
        ),
    ]

    for vuln in vulns:
        await memory_manager.store_vulnerability(vuln, "https://example.com")

    # 2. Search for similar
    similar = await memory_manager.search_similar_vulnerabilities(
        vulns[0],
        limit=5,
    )
    assert len(similar) > 0

    # 3. Create attack chain
    async with memory_manager.neo4j_driver.session() as session:
        await session.run(
            """
            MATCH (v1:Vulnerability {id: 'workflow-001'})
            MATCH (v2:Vulnerability {id: 'workflow-003'})
            MERGE (v1)-[:LEADS_TO]->(v2)
            """
        )

    # 4. Find attack paths
    paths = await memory_manager.find_attack_paths(
        from_severity="high",
        to_impact="privilege_escalation",
    )
    assert len(paths) > 0

    # 5. Check statistics
    stats = await memory_manager.get_stats()
    assert stats["findings_stored"] >= 3
    assert stats["queries_executed"] > 0


if __name__ == "__main__":
    # Run tests with pytest
    pytest.main([__file__, "-v", "-s"])
