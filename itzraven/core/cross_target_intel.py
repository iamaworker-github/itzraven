"""
Cross-Target Intelligence — learns vulnerability patterns across targets.
Target X pe SQLi pattern mila → Target Y pe auto-check.
Pattern: target feature → finding type → success rate → auto-apply to new targets.
"""
import json
import os
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from collections import defaultdict
from datetime import datetime

from itzraven.core.logger import get_logger

logger = get_logger()

_INTEL_DIR = Path.home() / ".itzraven" / "cross_target_intel"
_INTEL_DIR.mkdir(parents=True, exist_ok=True)


@dataclass
class CrossTargetPattern:
    technique: str
    target_tech: str
    endpoint_pattern: str
    vulnerability_type: str
    success_count: int
    fail_count: int
    payload_template: Optional[str] = None
    waf_bypass_method: Optional[str] = None
    first_seen: str = ""
    last_seen: str = ""
    tags: List[str] = field(default_factory=list)

    @property
    def confidence(self) -> float:
        total = self.success_count + self.fail_count
        if total == 0:
            return 0.0
        return round(self.success_count / total, 2)

    @property
    def is_reliable(self) -> bool:
        return self.confidence >= 0.6 and self.success_count >= 2


class CrossTargetIntel:
    def __init__(self):
        self._patterns: Dict[str, List[CrossTargetPattern]] = defaultdict(list)
        self._target_profiles: Dict[str, Dict[str, Any]] = {}
        self._pattern_file = _INTEL_DIR / "patterns.json"
        self._profile_file = _INTEL_DIR / "target_profiles.json"
        self._load()

    def _load(self):
        try:
            if self._pattern_file.exists():
                data = json.loads(self._pattern_file.read_text())
                for ttype, pats in data.items():
                    self._patterns[ttype] = [CrossTargetPattern(**p) for p in pats]
            if self._profile_file.exists():
                self._target_profiles = json.loads(self._profile_file.read_text())
        except Exception as e:
            logger.debug(f"CrossTargetIntel load error: {e}")

    def _save(self):
        try:
            data = {k: [p.__dict__ for p in v] for k, v in self._patterns.items()}
            self._pattern_file.write_text(json.dumps(data, indent=2))
            self._profile_file.write_text(json.dumps(self._target_profiles, indent=2))
        except Exception as e:
            logger.debug(f"CrossTargetIntel save error: {e}")

    def record_finding(self, finding: Dict[str, Any], target_url: str, target_techs: List[str]):
        """Record a finding and learn from it."""
        now = datetime.now().isoformat()
        tech_key = "_".join(sorted(target_techs[:3])) or "unknown"

        pattern = CrossTargetPattern(
            technique=finding.get("agent_name", "unknown") or finding.get("category", "unknown"),
            target_tech=tech_key,
            endpoint_pattern=finding.get("evidence", "")[:200],
            vulnerability_type=finding.get("category", "unknown"),
            success_count=1,
            fail_count=0,
            payload_template=finding.get("proof_of_concept", ""),
            first_seen=now,
            last_seen=now,
            tags=[finding.get("severity", "info"), finding.get("category", ""), tech_key],
        )

        existing = self._find_match(pattern)
        if existing:
            existing.success_count += 1
            existing.last_seen = now
            if finding.get("proof_of_concept"):
                existing.payload_template = finding["proof_of_concept"]
        else:
            self._patterns[tech_key].append(pattern)

        # Update target profile
        if target_url not in self._target_profiles:
            self._target_profiles[target_url] = {
                "url": target_url,
                "first_scan": now,
                "technologies": [],
                "findings": [],
                "total_findings": 0,
            }
        profile = self._target_profiles[target_url]
        profile["technologies"] = list(set(profile["technologies"] + target_techs))
        profile["findings"].append({
            "title": finding.get("title", ""),
            "category": finding.get("category", ""),
            "severity": finding.get("severity", ""),
            "timestamp": now,
        })
        profile["total_findings"] = len(profile["findings"])
        profile["last_scan"] = now
        self._save()

    def record_failure(self, technique: str, target_techs: List[str]):
        """Record a technique that failed."""
        tech_key = "_".join(sorted(target_techs[:3])) or "unknown"
        for p in self._patterns.get(tech_key, []):
            if p.technique == technique:
                p.fail_count += 1
                p.last_seen = datetime.now().isoformat()
                break
        self._save()

    def _find_match(self, pattern: CrossTargetPattern) -> Optional[CrossTargetPattern]:
        for p in self._patterns.get(pattern.target_tech, []):
            if p.technique == pattern.technique and p.vulnerability_type == pattern.vulnerability_type:
                return p
        return None

    def get_recommendations(self, target_techs: List[str]) -> List[Dict[str, Any]]:
        """Get AI recommendations based on past targets."""
        tech_key = "_".join(sorted(target_techs[:3])) or "unknown"
        related = []
        for key, pats in self._patterns.items():
            # Match if tech shares keywords
            if any(t in key for t in target_techs) or any(t in target_techs for t in key.split("_")):
                related.extend(pats)
            elif key == tech_key:
                related.extend(pats)

        scored = [(p, p.confidence * (p.success_count + 1)) for p in related if p.is_reliable]
        scored.sort(key=lambda x: -x[1])

        results = []
        for p, score in scored[:10]:
            results.append({
                "technique": p.technique,
                "vulnerability_type": p.vulnerability_type,
                "confidence": p.confidence,
                "score": round(score, 2),
                "payload_template": p.payload_template or "",
                "waf_bypass": p.waf_bypass_method or "",
                "past_successes": p.success_count,
                "message": f"Past target with {p.target_tech} had {p.vulnerability_type} "
                           f"via {p.technique} (success={p.success_count}, confidence={p.confidence})",
            })
        return results

    def get_cross_target_suggestions(self, current_findings: List[Dict[str, Any]], target_techs: List[str]) -> List[str]:
        """Suggest techniques that worked on similar targets."""
        recommendations = self.get_recommendations(target_techs)
        found_categories = {f.get("category") for f in current_findings if f.get("category")}

        suggestions = []
        for rec in recommendations:
            if rec["vulnerability_type"] not in found_categories:
                suggestions.append(
                    f"{rec['technique']} for {rec['vulnerability_type']} "
                    f"(confidence={rec['confidence']}, past_successes={rec['past_successes']})"
                )
        return suggestions[:5]

    def get_stats(self) -> Dict[str, Any]:
        total_patterns = sum(len(v) for v in self._patterns.values())
        total_targets = len(self._target_profiles)
        reliable = sum(1 for pats in self._patterns.values() for p in pats if p.is_reliable)
        return {
            "total_patterns": total_patterns,
            "total_targets": total_targets,
            "reliable_patterns": reliable,
            "tech_groups": list(self._patterns.keys()),
            "targets": list(self._target_profiles.keys()),
        }


_instance: Optional[CrossTargetIntel] = None


def get_cross_target_intel() -> CrossTargetIntel:
    global _instance
    if _instance is None:
        _instance = CrossTargetIntel()
    return _instance
