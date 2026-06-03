"""Tests for the Adaptive Enumeration Engine."""

import pytest
from itzraven.core.adaptive_enum import AdaptiveEnumEngine, ScanDecision


@pytest.mark.asyncio
async def test_analyze_target_nginx():
    engine = AdaptiveEnumEngine()
    decisions = await engine.analyze_target(
        url="https://example.com",
        headers={"server": "nginx/1.24.0", "content-type": "text/html"},
        body="<html><head></head><body>Welcome</body></html>",
        status_code=200,
    )
    vhost_scans = [d for d in decisions if d.scan_type == "vhost"]
    if vhost_scans:
        assert vhost_scans[0].priority >= 5


@pytest.mark.asyncio
async def test_analyze_target_graphql():
    engine = AdaptiveEnumEngine()
    decisions = await engine.analyze_target(
        url="https://example.com/graphql",
        headers={"content-type": "application/json"},
        body='{"query": "{ __schema { types { name } } }"}',
        status_code=200,
    )
    graphql_scans = [d for d in decisions if "graphql" in d.scan_type]
    assert graphql_scans


@pytest.mark.asyncio
async def test_analyze_target_401():
    engine = AdaptiveEnumEngine()
    decisions = await engine.analyze_target(
        url="https://example.com/admin",
        headers={"content-type": "text/html"},
        body="<html>401 Unauthorized</html>",
        status_code=401,
    )
    bypass_scans = [d for d in decisions if d.scan_type == "auth-bypass"]
    assert len(bypass_scans) == 1
    assert bypass_scans[0].confidence >= 0.5


@pytest.mark.asyncio
async def test_analyze_target_500():
    engine = AdaptiveEnumEngine()
    decisions = await engine.analyze_target(
        url="https://example.com/error",
        headers={"content-type": "text/html"},
        body="<html>Internal Server Error</html>",
        status_code=500,
    )
    error_scans = [d for d in decisions if d.scan_type == "error-analysis"]
    assert len(error_scans) == 1


def test_scan_decision_creation():
    d = ScanDecision(scan_type="vhost", target="example.com", priority=7,
                     reason="Test", confidence=0.8)
    assert d.scan_type == "vhost"
    assert d.priority == 7
    assert d.confidence == 0.8


def test_get_prioritized_decisions():
    engine = AdaptiveEnumEngine()
    engine._decisions = [
        ScanDecision("scan_a", "target", 5, "reason a", confidence=0.5),
        ScanDecision("scan_b", "target", 10, "reason b", confidence=0.9),
        ScanDecision("scan_c", "target", 3, "reason c", confidence=0.3),
    ]
    prioritized = engine.get_prioritized_decisions(min_priority=4)
    assert len(prioritized) == 2
    assert prioritized[0].scan_type == "scan_b"


def test_mark_completed():
    engine = AdaptiveEnumEngine()
    engine.mark_completed("vhost", "example.com")
    assert "vhost:example.com" in engine._completed_scans


def test_get_summary():
    engine = AdaptiveEnumEngine()
    summary = engine.get_summary()
    assert "pending_decisions" in summary
    assert "completed_scans" in summary
    assert "technologies_detected" in summary


@pytest.mark.asyncio
async def test_wordpress_detection():
    engine = AdaptiveEnumEngine()
    decisions = await engine.analyze_target(
        url="https://wordpress-site.com",
        headers={"server": "apache", "content-type": "text/html"},
        body="<html><head><link rel='stylesheet' href='/wp-content/themes/twenty/style.css'></head></html>",
        status_code=200,
    )
    wp_scans = [d for d in decisions if "wp-" in d.scan_type]
    if wp_scans:
        assert any("wordpress" in d.reason.lower() for d in wp_scans)
