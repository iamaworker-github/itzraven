"""Tests for the Context Compression Layer."""

import time
from itzraven.core.context_compression import ContextCompressor, ScoredFinding, SEVERITY_WEIGHTS


def test_add_finding():
    comp = ContextCompressor(max_findings=10)
    sf = comp.add_finding("f1", "SQL Injection", "SQLi in login",
                          severity="critical", confidence=0.95, category="vulnerability")
    assert sf.importance_score > 0
    assert sf.finding_id == "f1"
    assert sf.severity == "critical"


def test_importance_calculation():
    comp = ContextCompressor()
    critical = comp.add_finding("c1", "Critical Vuln", "", "critical", 1.0, "vulnerability")
    info = comp.add_finding("i1", "Info Finding", "", "info", 0.2, "default")
    assert critical.importance_score > info.importance_score


def test_get_active_context():
    comp = ContextCompressor(max_findings=20)
    comp.add_finding("f1", "SQL Injection", "", "critical", 0.95, "vulnerability")
    comp.add_finding("f2", "XSS Found", "", "high", 0.8, "vulnerability")
    comp.add_finding("f3", "Server Header", "", "info", 0.3, "tech_fingerprint")

    context = comp.get_active_context(max_tokens=100)
    assert "SQL Injection" in context
    assert "XSS Found" in context
    assert "CONTEXT:" in context


def test_compression():
    comp = ContextCompressor(max_findings=5)
    for i in range(30):
        comp.add_finding(f"f{i}", f"DNS Record {i}", "", "info", 0.2, "dns_record")
    # Should compress but keep some — max_findings + compressed summaries
    assert len(comp._findings) < 30  # Should have compressed at least some
    assert len(comp._compressed_groups) >= 0


def test_get_high_importance():
    comp = ContextCompressor()
    comp.add_finding("c1", "Critical", "", "critical", 1.0, "vulnerability")
    comp.add_finding("i1", "Info", "", "info", 0.1, "default")
    high = comp.get_high_importance(min_score=5.0)
    assert len(high) >= 1


def test_get_top_findings():
    comp = ContextCompressor()
    for i in range(30):
        comp.add_finding(f"f{i}", f"Finding {i}", "", "info", 0.3, "default")
    top = comp.get_top_findings(n=5)
    assert len(top) == 5


def test_reinforce():
    comp = ContextCompressor()
    comp.add_finding("f1", "Important", "", "medium", 0.5, "default")
    original_score = comp._findings[0].importance_score
    comp.reinforce("f1", amount=3.0)
    assert comp._findings[0].importance_score > original_score


def test_decay_importance():
    comp = ContextCompressor()
    comp.add_finding("old1", "Old Finding", "", "high", 0.9, "vulnerability")
    orig_score = comp._findings[0].importance_score
    # Manually set old timestamp
    comp._findings[0].timestamp = time.time() - 86400 * 7  # 7 days ago
    comp.decay_importance(half_life_hours=24.0)
    assert comp._findings[0].importance_score < orig_score


def test_scored_finding_to_dict():
    sf = ScoredFinding(finding_id="f1", title="Test", description="Desc",
                       severity="high", confidence=0.8, importance_score=7.5,
                       category="vulnerability")
    d = sf.to_dict()
    assert d["finding_id"] == "f1"
    assert d["importance"] == 7.5


def test_clear():
    comp = ContextCompressor()
    comp.add_finding("f1", "Test", "", "info", 0.5, "default")
    comp.clear()
    assert len(comp._findings) == 0
    assert len(comp._compressed_groups) == 0
