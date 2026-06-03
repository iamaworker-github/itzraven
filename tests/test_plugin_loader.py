"""Tests for the plugin loader system."""

import os
import tempfile
from pathlib import Path
from itzraven.core.plugin_loader import PluginLoader, PLUGIN_DIRS


def test_plugin_loader_initialization():
    loader = PluginLoader()
    assert loader is not None
    loaded = loader.list_loaded()
    assert "agents" in loaded
    assert "tools" in loaded
    assert "scanners" in loaded


def test_plugin_dirs_exist():
    for dir_path in PLUGIN_DIRS.values():
        assert dir_path.exists()


def test_plugin_loader_singleton():
    from itzraven.core.plugin_loader import get_plugin_loader
    p1 = get_plugin_loader()
    p2 = get_plugin_loader()
    assert p1 is p2


def test_discover_agents_from_directory(tmp_path):
    loader = PluginLoader()
    agents_dir = PLUGIN_DIRS["agents"]

    # Create a test plugin file
    plugin_code = '''
class TestAgent:
    def __init__(self):
        self.name = "test"
    async def run(self):
        return []
'''
    plugin_file = agents_dir / "test_agent.py"
    try:
        plugin_file.write_text(plugin_code)
        agents = loader.discover_agents()
        assert "TestAgent" in agents
    finally:
        if plugin_file.exists():
            plugin_file.unlink()
