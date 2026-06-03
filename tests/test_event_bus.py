"""Unit tests for Event Bus system

Tests cover:
- Event publishing and delivery
- Subscriptions and pattern matching
- Event filtering
- Priority handling
- Error isolation
- Performance characteristics
"""

import asyncio
import pytest
from datetime import datetime
from typing import List

from itzraven.core.event_bus import EventBus, Subscription
from itzraven.core.events import (
    BaseEvent,
    EventPriority,
    AgentStartedEvent,
    FindingDiscoveredEvent,
    ScanCompletedEvent,
)


@pytest.fixture
async def event_bus():
    """Create and start an event bus for testing"""
    bus = EventBus()
    await bus.start()
    yield bus
    await bus.stop()


@pytest.mark.asyncio
async def test_publish_and_receive_event(event_bus):
    """Test basic event publishing and receiving"""
    received_events = []

    @event_bus.subscribe("test.event")
    async def handler(event):
        received_events.append(event)

    # Publish event
    await event_bus.publish("test.event", {"data": "test"})

    # Wait for delivery
    await asyncio.sleep(0.1)

    assert len(received_events) == 1
    assert received_events[0].event_type == "test.event"
    assert received_events[0].metadata.get("data") == "test"


@pytest.mark.asyncio
async def test_multiple_subscribers(event_bus):
    """Test multiple subscribers receive the same event"""
    received_1 = []
    received_2 = []

    @event_bus.subscribe("test.event")
    async def handler1(event):
        received_1.append(event)

    @event_bus.subscribe("test.event")
    async def handler2(event):
        received_2.append(event)

    await event_bus.publish("test.event", {})
    await asyncio.sleep(0.1)

    assert len(received_1) == 1
    assert len(received_2) == 1
    assert received_1[0].event_id == received_2[0].event_id


@pytest.mark.asyncio
async def test_wildcard_pattern_matching(event_bus):
    """Test wildcard pattern matching in subscriptions"""
    received_events = []

    @event_bus.subscribe("agent.*")
    async def handler(event):
        received_events.append(event)

    # Publish different agent events
    await event_bus.publish("agent.started", {})
    await event_bus.publish("agent.completed", {})
    await event_bus.publish("finding.discovered", {})  # Should not match

    await asyncio.sleep(0.1)

    assert len(received_events) == 2
    assert all(e.event_type.startswith("agent.") for e in received_events)


@pytest.mark.asyncio
async def test_event_filtering(event_bus):
    """Test event filtering with filter function"""
    critical_findings = []

    @event_bus.subscribe(
        "finding.discovered",
        filter_func=lambda e: e.severity == "critical"
    )
    async def handler(event):
        critical_findings.append(event)

    # Publish findings with different severities
    await event_bus.publish("finding.discovered", {"severity": "low"})
    await event_bus.publish("finding.discovered", {"severity": "critical"})
    await event_bus.publish("finding.discovered", {"severity": "medium"})
    await event_bus.publish("finding.discovered", {"severity": "critical"})

    await asyncio.sleep(0.1)

    assert len(critical_findings) == 2
    assert all(e.severity == "critical" for e in critical_findings)


@pytest.mark.asyncio
async def test_priority_handling(event_bus):
    """Test that high priority subscribers are called first"""
    call_order = []

    @event_bus.subscribe("test.event", priority=EventPriority.LOW)
    async def low_priority(event):
        call_order.append("low")

    @event_bus.subscribe("test.event", priority=EventPriority.HIGH)
    async def high_priority(event):
        call_order.append("high")

    @event_bus.subscribe("test.event", priority=EventPriority.NORMAL)
    async def normal_priority(event):
        call_order.append("normal")

    await event_bus.publish("test.event", {})
    await asyncio.sleep(0.1)

    # High priority should be called first
    assert call_order[0] == "high"
    assert "low" in call_order


@pytest.mark.asyncio
async def test_error_isolation(event_bus):
    """Test that subscriber errors don't affect other subscribers"""
    received_events = []

    @event_bus.subscribe("test.event")
    async def failing_handler(event):
        raise ValueError("Intentional error")

    @event_bus.subscribe("test.event")
    async def working_handler(event):
        received_events.append(event)

    await event_bus.publish("test.event", {})
    await asyncio.sleep(0.1)

    # Working handler should still receive event despite failing handler
    assert len(received_events) == 1
    assert event_bus.get_stats()["subscriber_errors"] == 1


@pytest.mark.asyncio
async def test_unsubscribe(event_bus):
    """Test unsubscribing from events"""
    received_events = []

    @event_bus.subscribe("test.event")
    async def handler(event):
        received_events.append(event)

    # Publish first event
    await event_bus.publish("test.event", {})
    await asyncio.sleep(0.1)
    assert len(received_events) == 1

    # Unsubscribe
    event_bus.unsubscribe(handler)

    # Publish second event
    await event_bus.publish("test.event", {})
    await asyncio.sleep(0.1)

    # Should still be 1 (not received after unsubscribe)
    assert len(received_events) == 1


@pytest.mark.asyncio
async def test_agent_context_manager(event_bus):
    """Test agent context manager for lifecycle events"""
    received_events = []

    @event_bus.subscribe("agent.*")
    async def handler(event):
        received_events.append(event)

    # Use context manager
    async with event_bus.agent_context(
        agent_name="Test Agent",
        agent_type="test",
        target="example.com"
    ):
        await asyncio.sleep(0.05)

    await asyncio.sleep(0.1)

    # Should receive started and completed events
    assert len(received_events) == 2
    assert received_events[0].event_type == "agent.started"
    assert received_events[1].event_type == "agent.completed"


@pytest.mark.asyncio
async def test_agent_context_manager_with_error(event_bus):
    """Test agent context manager publishes failed event on exception"""
    received_events = []

    @event_bus.subscribe("agent.*")
    async def handler(event):
        received_events.append(event)

    # Use context manager with error
    try:
        async with event_bus.agent_context(
            agent_name="Test Agent",
            agent_type="test",
            target="example.com"
        ):
            raise ValueError("Test error")
    except ValueError:
        pass

    await asyncio.sleep(0.1)

    # Should receive started and failed events
    assert len(received_events) == 2
    assert received_events[0].event_type == "agent.started"
    assert received_events[1].event_type == "agent.failed"
    assert "Test error" in received_events[1].error_message


@pytest.mark.asyncio
async def test_publish_event_object(event_bus):
    """Test publishing event objects directly"""
    received_events = []

    @event_bus.subscribe("agent.started")
    async def handler(event):
        received_events.append(event)

    # Create and publish event object
    event = AgentStartedEvent(
        agent_name="Test Agent",
        agent_type="test",
        target="example.com",
        mode="pentest"
    )
    await event_bus.publish_event(event)

    await asyncio.sleep(0.1)

    assert len(received_events) == 1
    assert received_events[0].agent_name == "Test Agent"
    assert received_events[0].target == "example.com"


@pytest.mark.asyncio
async def test_correlation_id_propagation(event_bus):
    """Test correlation ID is propagated through events"""
    received_events = []

    @event_bus.subscribe("test.*")
    async def handler(event):
        received_events.append(event)

    correlation_id = "test-correlation-123"

    await event_bus.publish("test.event1", {}, correlation_id=correlation_id)
    await event_bus.publish("test.event2", {}, correlation_id=correlation_id)

    await asyncio.sleep(0.1)

    assert len(received_events) == 2
    assert all(e.correlation_id == correlation_id for e in received_events)


@pytest.mark.asyncio
async def test_event_history(event_bus):
    """Test event history tracking"""
    # Publish some events
    for i in range(5):
        await event_bus.publish("test.event", {"index": i})

    await asyncio.sleep(0.1)

    history = event_bus.get_event_history(limit=10)
    assert len(history) == 5
    # History should be newest first
    assert history[0].metadata["index"] == 4
    assert history[-1].metadata["index"] == 0


@pytest.mark.asyncio
async def test_statistics(event_bus):
    """Test event bus statistics"""
    @event_bus.subscribe("test.event")
    async def handler(event):
        pass

    # Publish some events
    for _ in range(3):
        await event_bus.publish("test.event", {})

    await asyncio.sleep(0.1)

    stats = event_bus.get_stats()
    assert stats["events_published"] == 3
    assert stats["events_delivered"] == 3
    assert stats["running"] is True


@pytest.mark.asyncio
async def test_backpressure(event_bus):
    """Test backpressure when queue is full"""
    # Create bus with small queue
    small_bus = EventBus(max_queue_size=2)
    await small_bus.start()

    try:
        # Fill the queue
        await small_bus.publish("test.event", {})
        await small_bus.publish("test.event", {})

        # This should timeout due to full queue
        with pytest.raises(asyncio.QueueFull):
            await small_bus.publish("test.event", {})

    finally:
        await small_bus.stop()


@pytest.mark.asyncio
async def test_sync_handler(event_bus):
    """Test that synchronous handlers work"""
    received_events = []

    @event_bus.subscribe("test.event")
    def sync_handler(event):  # Not async
        received_events.append(event)

    await event_bus.publish("test.event", {})
    await asyncio.sleep(0.1)

    assert len(received_events) == 1


@pytest.mark.asyncio
async def test_performance_throughput():
    """Test event throughput performance"""
    bus = EventBus()
    await bus.start()

    received_count = 0

    @bus.subscribe("test.event")
    async def handler(event):
        nonlocal received_count
        received_count += 1

    # Publish many events
    event_count = 1000
    start_time = asyncio.get_event_loop().time()

    for i in range(event_count):
        await bus.publish("test.event", {"index": i})

    # Wait for all to be delivered
    await asyncio.sleep(1.0)

    duration = asyncio.get_event_loop().time() - start_time
    throughput = event_count / duration

    await bus.stop()

    assert received_count == event_count
    assert throughput > 500  # Should handle >500 events/second
    print(f"Throughput: {throughput:.0f} events/second")


@pytest.mark.asyncio
async def test_performance_latency():
    """Test event delivery latency"""
    bus = EventBus()
    await bus.start()

    latencies = []

    @bus.subscribe("test.event")
    async def handler(event):
        latency = (datetime.now() - event.timestamp).total_seconds() * 1000
        latencies.append(latency)

    # Publish events and measure latency
    for _ in range(100):
        await bus.publish("test.event", {})

    await asyncio.sleep(0.5)
    await bus.stop()

    avg_latency = sum(latencies) / len(latencies)
    p95_latency = sorted(latencies)[int(len(latencies) * 0.95)]

    assert avg_latency < 10  # <10ms average
    assert p95_latency < 20  # <20ms p95
    print(f"Average latency: {avg_latency:.2f}ms, P95: {p95_latency:.2f}ms")


@pytest.mark.asyncio
async def test_finding_discovered_event():
    """Test FindingDiscoveredEvent creation and serialization"""
    event = FindingDiscoveredEvent(
        agent_name="SQL Injection Agent",
        title="SQL Injection in login form",
        description="Time-based blind SQL injection",
        severity="high",
        category="sql_injection",
        evidence="Sleep delay observed",
        confidence=0.95,
        target="example.com/login",
        proof_of_concept="' OR SLEEP(5)--"
    )

    # Test serialization
    event_dict = event.to_dict()
    assert event_dict["event_type"] == "finding.discovered"
    assert event_dict["title"] == "SQL Injection in login form"
    assert event_dict["severity"] == "high"
    assert event_dict["confidence"] == 0.95

    # Test priority is set for high severity
    assert event.priority == EventPriority.HIGH


@pytest.mark.asyncio
async def test_scan_completed_event():
    """Test ScanCompletedEvent creation"""
    event = ScanCompletedEvent(
        scan_id="scan-123",
        target="example.com",
        mode="pentest",
        duration=45.5,
        total_findings=12,
        findings_by_severity={
            "critical": 2,
            "high": 3,
            "medium": 5,
            "low": 2
        },
        agents_executed=["Recon", "SQL", "XSS"],
        success=True
    )

    event_dict = event.to_dict()
    assert event_dict["total_findings"] == 12
    assert event_dict["duration"] == 45.5
    assert len(event_dict["agents_executed"]) == 3


if __name__ == "__main__":
    # Run tests with pytest
    pytest.main([__file__, "-v", "-s"])
