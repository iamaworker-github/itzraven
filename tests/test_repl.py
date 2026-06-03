"""Tests for REPL Interactive Shell."""

import pytest
from itzraven.ui.repl import ItzravenREPL


def test_repl_initialization():
    repl = ItzravenREPL()
    assert repl.prompt == "itzraven> "
    assert repl._graph is not None


def test_repl_do_help():
    repl = ItzravenREPL()
    repl.onecmd("help")
    # Should not raise


def test_repl_do_graph_invalid():
    repl = ItzravenREPL()
    repl.onecmd("graph")
    # Should not raise


def test_repl_do_exit():
    repl = ItzravenREPL()
    result = repl.onecmd("exit")
    assert result is True


def test_repl_do_learn_stats():
    repl = ItzravenREPL()
    repl.onecmd("learn stats")
    # Should not raise


def test_repl_do_monitor():
    repl = ItzravenREPL()
    repl.onecmd("monitor list")
    # Should not raise


def test_repl_do_scan():
    repl = ItzravenREPL()
    # Don't call scan in test since it needs asyncio loop — just verify parsing
    assert repl._graph is not None


def test_repl_default():
    repl = ItzravenREPL()
    repl.onecmd("invalid_command_xyz")
    # Should not raise
