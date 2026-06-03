import os
import yaml
from typing import Dict, Any, List, Optional
from pathlib import Path

PATTERNS_DIR = Path(__file__).parent


class PatternLibrary:
    _instances: Dict[str, "PatternLibrary"] = {}

    def __init__(self, vuln_class: str):
        self.vuln_class = vuln_class
        self.data: Dict[str, Any] = {}
        self._load()

    def _load(self):
        path = PATTERNS_DIR / f"{self.vuln_class}.yaml"
        if path.exists():
            with open(path) as f:
                self.data = yaml.safe_load(f) or {}

    @classmethod
    def get(cls, vuln_class: str) -> "PatternLibrary":
        if vuln_class not in cls._instances:
            cls._instances[vuln_class] = cls(vuln_class)
        return cls._instances[vuln_class]

    @property
    def payloads(self) -> List[str]:
        return (self.data.get("payloads") or []) + (self.data.get("basic_payloads") or [])

    @property
    def bypass_techniques(self) -> List[Dict[str, Any]]:
        return self.data.get("bypass_techniques") or []

    @property
    def detection_patterns(self) -> List[str]:
        return self.data.get("detection_patterns") or []

    @property
    def chain_templates(self) -> List[Dict[str, Any]]:
        return self.data.get("chain_templates") or []

    @property
    def h1_references(self) -> List[Dict[str, str]]:
        return self.data.get("h1_references") or []

    # WAF bypass-specific properties
    @property
    def categories(self) -> List[Dict[str, Any]]:
        return self.data.get("categories") or []

    @property
    def hunting_tactics(self) -> List[Dict[str, Any]]:
        return self.data.get("hunting_tactics") or []

    @property
    def waf_signatures(self) -> Dict[str, Any]:
        return self.data.get("waf_signatures") or {}

    def get_technique_names(self) -> List[str]:
        return [t.get("name", "") for t in self.bypass_techniques]

    def get_chain_descriptions(self) -> List[str]:
        return [c.get("description", "") for c in self.chain_templates]

    def get_all_payloads(self) -> List[str]:
        """Get ALL payloads including nested category payloads."""
        payloads = list(self.payloads)
        for cat in self.categories:
            payloads.extend(cat.get("payloads", []))
        for tactic in self.hunting_tactics:
            payloads.extend(tactic.get("payloads", []))
        return list(set(payloads))

    def get_bypass_payloads_for_waf(self, waf_type: str) -> List[str]:
        """Get bypass payloads targeting a specific WAF vendor."""
        payloads = []
        for cat in self.categories:
            wafs = cat.get("wafs", [])
            if "all" in wafs or waf_type in wafs:
                payloads.extend(cat.get("payloads", [])[:5])
        return list(set(payloads))


def load_pattern(agent_name: str, vuln_class: str) -> Dict[str, Any]:
    lib = PatternLibrary.get(vuln_class)
    return lib.data
