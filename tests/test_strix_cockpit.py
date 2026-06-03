"""Tests for STRIX Cockpit v2."""

import pytest
from itzraven.ui.strix_cockpit import (
    StrixCockpit, THEMES, AgentTree, FindSum,
    ThinkStream, GraphViz,
)


def test_app():
    app = StrixCockpit(target="https://x.com")
    assert app.target == "https://x.com"


def test_themes():
    assert "pentest" in THEMES
    assert THEMES["osint"]["p"] == "#ef4444"


def test_agent_tree():
    p = AgentTree()
    p.set("Recon", "running", 50, ["Sub"], sync=True)
    assert "Recon" in p._a
    assert p._a["Recon"][3] is True


def test_findings():
    p = FindSum()
    p.add("SSRF", "critical", 0.91)
    assert len(p._f) == 1


def test_thinking():
    p = ThinkStream()
    p.add("[OBJECTIVE]", "test")
    assert len(p._b) == 1


def test_graph():
    p = GraphViz()
    p.add("root")
    p.add("child", "root")
    assert len(p._n) == 2


def test_modal():
    from itzraven.ui.strix_cockpit import QuitModal
    assert QuitModal() is not None


def test_bindings():
    app = StrixCockpit()
    keys = {b.action: b.key for b in app.BINDINGS}
    assert keys["quit"] == "q"
    assert keys["mode"] == "f2"
    assert keys["cmd"] == "/"
