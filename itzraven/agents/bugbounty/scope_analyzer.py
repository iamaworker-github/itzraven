"""
Scope Analyzer - reads program scope from YAML and checks target inclusion
"""

import fnmatch
from pathlib import Path
from typing import List, Optional, Dict, Any

import yaml

from itzraven.core.logger import get_logger
from itzraven.core.config import get_config

logger = get_logger()


DEFAULT_SCOPE_YAML = """
target:
  - *.example.com
exclude:
  - admin.example.com
"""


class ScopeAnalyzer:
    def __init__(self, scope_file: Optional[str] = None, scope_data: Optional[Dict[str, Any]] = None):
        self._scope: Dict[str, Any] = {}
        self._allowed_targets: List[str] = []
        self._excluded_targets: List[str] = []

        if scope_data:
            self.load_scope_data(scope_data)
        elif scope_file:
            self.load_scope_file(scope_file)

    def load_scope_file(self, path: str) -> None:
        p = Path(path)
        if not p.exists():
            logger.warning(f"Scope file not found: {path}, using defaults")
            self.load_scope_data(yaml.safe_load(DEFAULT_SCOPE_YAML))
            return
        with open(p, "r") as f:
            data = yaml.safe_load(f)
        self.load_scope_data(data or {})

    def load_scope_data(self, data: Dict[str, Any]) -> None:
        self._scope = data
        raw_allowed = data.get("target", data.get("allowed", []))
        if isinstance(raw_allowed, str):
            raw_allowed = [raw_allowed]
        self._allowed_targets = list(raw_allowed)

        raw_excluded = data.get("exclude", data.get("excluded", []))
        if isinstance(raw_excluded, str):
            raw_excluded = [raw_excluded]
        self._excluded_targets = list(raw_excluded)

        logger.info(f"Loaded scope: {len(self._allowed_targets)} allowed, {len(self._excluded_targets)} excluded")

    def is_in_scope(self, target: str, scope_rules: Optional[List[str]] = None) -> bool:
        rules = scope_rules if scope_rules is not None else self._allowed_targets
        if not rules:
            return True

        target = target.lower().rstrip("/")

        for exclude_pattern in self._excluded_targets:
            if self._match_pattern(target, exclude_pattern.lower()):
                logger.debug(f"Target {target} excluded by pattern: {exclude_pattern}")
                return False

        for pattern in rules:
            if self._match_pattern(target, pattern.lower()):
                logger.debug(f"Target {target} in scope (matches: {pattern})")
                return True

        logger.debug(f"Target {target} out of scope")
        return False

    def get_excluded_targets(self) -> List[str]:
        return list(self._excluded_targets)

    def get_allowed_targets(self) -> List[str]:
        return list(self._allowed_targets)

    def get_scope_summary(self) -> Dict[str, Any]:
        return {
            "allowed_targets": self._allowed_targets,
            "excluded_targets": self._excluded_targets,
            "total_allowed": len(self._allowed_targets),
            "total_excluded": len(self._excluded_targets),
        }

    @staticmethod
    def _match_pattern(target: str, pattern: str) -> bool:
        if pattern.startswith("*."):
            domain_part = pattern[2:]
            return target == domain_part or target.endswith(f".{domain_part}")
        if pattern.startswith("*"):
            return fnmatch.fnmatch(target, pattern)
        return target == pattern
