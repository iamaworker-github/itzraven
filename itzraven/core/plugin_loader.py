"""
Plugin loader for dynamically discovering and loading third-party agents, tools, and scanners.

Supports loading via:
1. Python entry_points (setuptools) — `itzraven.plugins.agents`, `itzraven.plugins.tools`
2. Plugin directories — `~/.itzraven/plugins/agents/`, `~/.itzraven/plugins/tools/`
"""

import importlib
import inspect
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional, Type, Any
from itzraven.core.logger import get_logger

logger = get_logger()

PLUGIN_DIRS = {
    "agents": Path.home() / ".itzraven" / "plugins" / "agents",
    "tools": Path.home() / ".itzraven" / "plugins" / "tools",
    "scanners": Path.home() / ".itzraven" / "plugins" / "scanners",
}


class PluginLoader:
    """Discovers and loads plugins from entry points and directories."""

    def __init__(self):
        self._loaded: Dict[str, Dict[str, Any]] = {
            "agents": {},
            "tools": {},
            "scanners": {},
        }
        for dir_path in PLUGIN_DIRS.values():
            dir_path.mkdir(parents=True, exist_ok=True)

    def discover_agents(self, base_class: Optional[Type] = None) -> Dict[str, Type]:
        return self._discover("agents", "itzraven.plugins.agents", base_class)

    def discover_tools(self, base_class: Optional[Type] = None) -> Dict[str, Type]:
        return self._discover("tools", "itzraven.plugins.tools", base_class)

    def discover_scanners(self, base_class: Optional[Type] = None) -> Dict[str, Type]:
        return self._discover("scanners", "itzraven.plugins.scanners", base_class)

    def load_agent(self, name: str) -> Optional[Type]:
        return self._load_single("agents", name)

    def load_tool(self, name: str) -> Optional[Type]:
        return self._load_single("tools", name)

    def _discover(self, kind: str, entry_point_group: str, base_class: Optional[Type] = None) -> Dict[str, Type]:
        results = {}

        # 1. Entry points
        try:
            from pkg_resources import iter_entry_points
            for ep in iter_entry_points(entry_point_group):
                try:
                    cls = ep.load()
                    if base_class is None or (inspect.isclass(cls) and issubclass(cls, base_class)):
                        results[ep.name] = cls
                except Exception as e:
                    logger.debug(f"Failed to load entry point {ep.name}: {e}")
        except Exception:
            try:
                from importlib.metadata import entry_points
                for ep in entry_points(group=entry_point_group):
                    try:
                        cls = ep.load()
                        if base_class is None or (inspect.isclass(cls) and issubclass(cls, base_class)):
                            results[ep.name] = cls
                    except Exception as e:
                        logger.debug(f"Failed to load entry point {ep.name}: {e}")
            except Exception:
                pass

        # 2. Plugin directories
        plugin_dir = PLUGIN_DIRS.get(kind)
        if plugin_dir and plugin_dir.exists():
            for pyfile in sorted(plugin_dir.glob("*.py")):
                mod_name = f"_itzraven_plugin_{kind}_{pyfile.stem}"
                try:
                    spec = importlib.util.spec_from_file_location(mod_name, pyfile)
                    if spec and spec.loader:
                        mod = importlib.util.module_from_spec(spec)
                        spec.loader.exec_module(mod)
                        for name, obj in inspect.getmembers(mod, inspect.isclass):
                            if base_class is None or issubclass(obj, base_class):
                                results[name] = obj
                except Exception as e:
                    logger.warning(f"Failed to load plugin {pyfile}: {e}")

        self._loaded[kind].update(results)
        return results

    def _load_single(self, kind: str, name: str) -> Optional[Type]:
        if name in self._loaded.get(kind, {}):
            return self._loaded[kind][name]

        plugin_dir = PLUGIN_DIRS.get(kind)
        if plugin_dir:
            pyfile = plugin_dir / f"{name}.py"
            if pyfile.exists():
                try:
                    mod_name = f"_itzraven_plugin_{kind}_{name}"
                    spec = importlib.util.spec_from_file_location(mod_name, pyfile)
                    if spec and spec.loader:
                        mod = importlib.util.module_from_spec(spec)
                        spec.loader.exec_module(mod)
                        for cls_name, cls in inspect.getmembers(mod, inspect.isclass):
                            if cls_name.lower() == name.lower():
                                self._loaded[kind][name] = cls
                                return cls
                except Exception as e:
                    logger.error(f"Failed to load plugin {name}: {e}")
        return None

    def list_loaded(self, kind: Optional[str] = None) -> Dict[str, list]:
        if kind:
            return {kind: list(self._loaded.get(kind, {}).keys())}
        return {k: list(v.keys()) for k, v in self._loaded.items()}


_plugin_loader: Optional[PluginLoader] = None


def get_plugin_loader() -> PluginLoader:
    global _plugin_loader
    if _plugin_loader is None:
        _plugin_loader = PluginLoader()
    return _plugin_loader
