"""
WAF Bypass Engine — 263+ WAF bypass techniques from src-hunter.

Provides agents with WAF detection, fingerprinting, and intelligent
bypass selection based on the detected WAF type and target context.

Integrated into the agent pipeline via WAFBypassEngine class.
"""

import random
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field

from itzraven.patterns import PatternLibrary
from itzraven.core.logger import get_logger

logger = get_logger()


@dataclass
class BypassTechnique:
    """A WAF bypass technique with selection metadata."""
    name: str
    category: str
    payloads: List[str]
    wafs: List[str]  # Which WAFs this targets
    description: str = ""
    success_rate: float = 0.5
    stealth_level: int = 3  # 1-5 (5 = most stealthy)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name, "category": self.category,
            "payloads": self.payloads[:3], "wafs": self.wafs,
            "description": self.description,
            "success_rate": self.success_rate,
            "stealth_level": self.stealth_level,
        }


class WAFBypassEngine:
    """Intelligent WAF bypass engine with technique selection."""

    WAF_VENDORS = {
        "cloudflare": ["CF-RAY", "Server: cloudflare", "cloudflare"],
        "modsecurity": ["ModSecurity", "X-Sec-Request-ID"],
        "aws_waf": ["x-amz-id-2", "x-amz-request-id"],
        "f5_asm": ["X-ASM-Policy", "X-ASM-Version"],
        "akamai": ["X-Akamai-Transformed", "AkamaiGHost"],
        "imperva": ["Incapsula", "X-Iinfo", "X-CDN: Incapsula"],
        "sucuri": ["X-Sucuri-ID", "Sucuri"],
        "wordfence": ["Wordfence"],
        "barracuda": ["Barracuda"],
        "unknown": [],
    }

    def __init__(self):
        self._library = PatternLibrary.get("waf_bypass")
        self._techniques: List[BypassTechnique] = []
        self._load_techniques()

    def _load_techniques(self):
        """Load bypass techniques from pattern library."""
        categories = self._library.data.get("categories", [])
        for cat in categories:
            wafs = cat.get("wafs", ["unknown"])
            payloads = cat.get("payloads", [])
            self._techniques.append(BypassTechnique(
                name=cat["name"],
                category=cat.get("name", ""),
                payloads=payloads,
                wafs=wafs,
                description=cat.get("description", ""),
                stealth_level=5 if "stealth" in cat.get("name", "").lower() else 3,
            ))

        # Add hunting tactics as techniques
        for tactic in self._library.data.get("hunting_tactics", []):
            self._techniques.append(BypassTechnique(
                name=tactic["name"],
                category="hunting_tactic",
                payloads=tactic.get("payloads", []),
                wafs=tactic.get("wafs", ["cloudflare", "modsec", "aws", "f5", "akamai", "imperva"]),
                description=tactic.get("description", ""),
                stealth_level=4,
            ))

        logger.info(f"WAF Bypass Engine loaded: {len(self._techniques)} techniques across "
                    f"{len(self.WAF_VENDORS)} WAF vendors")

    def fingerprint_headers(self, headers: Dict[str, str]) -> List[str]:
        """Fingerprint WAF vendor from response headers.

        Args:
            headers: Response headers dict

        Returns:
            List of detected WAF vendor names
        """
        detected = []
        for vendor, signatures in self.WAF_VENDORS.items():
            for sig in signatures:
                key, _, val = sig.partition(": ")
                if key in headers:
                    if not val or val.lower() in headers.get(key, "").lower():
                        detected.append(vendor)
                        break
        return detected

    def select_techniques(self, waf_type: str = "unknown", count: int = 5,
                          stealth: bool = False) -> List[BypassTechnique]:
        """Select best bypass techniques for a given WAF.

        Args:
            waf_type: Detected WAF vendor (cloudflare, modsec, etc.)
            count: Number of techniques to return
            stealth: Prefer stealthier techniques

        Returns:
            List of selected BypassTechnique objects
        """
        candidates = [
            t for t in self._techniques
            if waf_type in t.wafs or "all" in t.wafs or waf_type == "unknown"
        ]

        if stealth:
            candidates = [t for t in candidates if t.stealth_level >= 4]

        # Prioritize by success rate, then variety of categories
        candidates.sort(key=lambda t: (-t.success_rate, t.stealth_level))
        seen_categories = set()
        selected = []
        for t in candidates:
            if t.category not in seen_categories or len(selected) < count:
                selected.append(t)
                seen_categories.add(t.category)
            if len(selected) >= count:
                break
        return selected[:count]

    def get_payloads(self, waf_type: str = "unknown", technique_name: Optional[str] = None,
                     count: int = 3) -> List[str]:
        """Get concrete payloads for bypass.

        Args:
            waf_type: WAF vendor name
            technique_name: Specific technique (or None for all)
            count: Number of payloads

        Returns:
            List of payload strings
        """
        techniques = self._techniques
        if technique_name:
            techniques = [t for t in techniques if t.name == technique_name]
        elif waf_type != "unknown":
            techniques = [t for t in techniques if waf_type in t.wafs]

        payloads = []
        for t in techniques[:count]:
            if t.payloads:
                # Pick best payloads from each technique
                for p in t.payloads[:3]:
                    if p not in payloads:
                        payloads.append(p)
        return payloads[:count]

    def get_bypass_context(self, waf_type: str = "unknown", stealth: bool = False) -> str:
        """Build LLM context string with WAF bypass strategies.

        Returns formatted string for agent prompt injection.
        """
        techniques = self.select_techniques(waf_type, count=5, stealth=stealth)
        if not techniques:
            return ""

        lines = [
            f"[WAF BYPASS STRATEGIES — Detected: {waf_type}]",
            "",
        ]
        for t in techniques:
            lines.append(f"• {t.name} ({', '.join(t.wafs)})")
            lines.append(f"  Stealth: {'★' * t.stealth_level}{'☆' * (5-t.stealth_level)}")
            if t.payloads:
                lines.append(f"  Example: {t.payloads[0]}")
            lines.append("")
        return "\n".join(lines)

    def all_techniques_summary(self) -> List[Dict[str, Any]]:
        """Return summary of all techniques for reporting."""
        categories = {}
        for t in self._techniques:
            if t.category not in categories:
                categories[t.category] = {"count": 0, "wafs": set()}
            categories[t.category]["count"] += 1
            categories[t.category]["wafs"].update(t.wafs)
        return [
            {"category": cat, "count": info["count"], "wafs": list(info["wafs"])}
            for cat, info in sorted(categories.items())
        ]


_waf_bypass: Optional[WAFBypassEngine] = None


def get_waf_bypass() -> WAFBypassEngine:
    """Singleton accessor for WAFBypassEngine."""
    global _waf_bypass
    if _waf_bypass is None:
        _waf_bypass = WAFBypassEngine()
    return _waf_bypass
