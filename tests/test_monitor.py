"""Tests for Continuous Monitoring."""

import pytest
from itzraven.core.monitor import ContinuousMonitor, MonitorTarget, MonitorDiff


def test_monitor_target():
    mt = MonitorTarget(target="example.com", interval_hours=24, mode="osint")
    assert mt.target == "example.com"
    d = mt.to_dict()
    assert d["target"] == "example.com"


def test_monitor_diff():
    diff = MonitorDiff(target="example.com", scan_id="s1", timestamp=0,
                       new_findings=[{"type": "vuln", "name": "SQLi"}],
                       resolved_findings=[], new_subdomains=["admin.example.com"],
                       changed_ips=[], new_ports=["443"], expired_certs=[])
    assert diff.has_changes() is True
    assert "new findings" in diff.summary()
    assert "new subdomains" in diff.summary()


def test_monitor_diff_no_changes():
    diff = MonitorDiff(target="example.com", scan_id="s1", timestamp=0,
                       new_findings=[], resolved_findings=[],
                       new_subdomains=[], changed_ips=[], new_ports=[], expired_certs=[])
    assert diff.has_changes() is False
    assert "No changes" in diff.summary()


def test_add_remove_target():
    monitor = ContinuousMonitor()
    monitor.add_target("https://test.com", interval_hours=12)
    assert "https://test.com" in monitor._targets
    assert monitor.remove_target("https://test.com") is True
    assert monitor.remove_target("nonexistent") is False


def test_list_targets():
    monitor = ContinuousMonitor()
    monitor.add_target("a.com", 24, "osint")
    monitor.add_target("b.com", 48, "pentest")
    targets = monitor.list_targets()
    assert len(targets) >= 2


def test_get_history():
    monitor = ContinuousMonitor()
    monitor._history["test.com"] = [{"scan_id": "s1", "timestamp": 0, "new_findings": 5}]
    history = monitor.get_history("test.com")
    assert len(history) == 1
