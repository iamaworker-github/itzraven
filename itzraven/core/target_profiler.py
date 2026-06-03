"""
Adaptive Target Profiling — har target ka fingerprint banaye.
Pichle scans se seekh kar better attack strategy recommend kare.
"""

import json
import time
import hashlib
from pathlib import Path
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field

from itzraven.core.logger import get_logger

logger = get_logger()

PROFILE_STORE = Path.home() / ".itzraven" / "target_profiles.json"


@dataclass
class TargetTechProfile:
    technologies: Dict[str, str] = field(default_factory=dict)
    open_ports: List[int] = field(default_factory=list)
    frameworks: List[str] = field(default_factory=list)
    waf_detected: Optional[str] = None
    cms_type: Optional[str] = None
    server_type: Optional[str] = None


@dataclass
class ScanHistoryEntry:
    timestamp: float
    findings_count: int
    successful_techniques: List[str]
    failed_techniques: List[str]
    duration_seconds: float
    techniques_used: List[str] = field(default_factory=list)


@dataclass
class TargetProfile:
    domain: str
    ip_addresses: List[str] = field(default_factory=list)
    tech: TargetTechProfile = field(default_factory=TargetTechProfile)
    scans: List[ScanHistoryEntry] = field(default_factory=list)
    best_techniques: Dict[str, float] = field(default_factory=dict)
    worst_techniques: Dict[str, float] = field(default_factory=dict)
    tags: Set[str] = field(default_factory=set)
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    total_findings: int = 0

    def update_tech(self, tech_data: Dict):
        if "technologies" in tech_data:
            self.tech.technologies.update(tech_data["technologies"])
        if "ports" in tech_data:
            self.tech.open_ports = list(set(self.tech.open_ports + tech_data["ports"]))
        if "frameworks" in tech_data:
            for fw in tech_data["frameworks"]:
                if fw not in self.tech.frameworks:
                    self.tech.frameworks.append(fw)
        if "waf" in tech_data:
            self.tech.waf_detected = tech_data["waf"]
        if "cms" in tech_data:
            self.tech.cms_type = tech_data["cms"]

    def record_scan(self, findings_count: int, techniques: List[str],
                    successful: List[str], failed: List[str],
                    duration: float):
        entry = ScanHistoryEntry(
            timestamp=time.time(),
            findings_count=findings_count,
            successful_techniques=successful,
            failed_techniques=failed,
            duration_seconds=duration,
            techniques_used=techniques,
        )
        self.scans.append(entry)
        self.total_findings += findings_count
        self.last_seen = time.time()

        for t in successful:
            self.best_techniques[t] = self.best_techniques.get(t, 0) + 1
        for t in failed:
            self.worst_techniques[t] = self.worst_techniques.get(t, 0) + 1

    def get_recommended_techniques(self, top_k: int = 5) -> List[str]:
        scored = {}
        for t, count in self.best_techniques.items():
            fail_count = self.worst_techniques.get(t, 0)
            score = count / max(count + fail_count, 1)
            scored[t] = score
        sorted_techs = sorted(scored.items(), key=lambda x: -x[1])
        return [t for t, s in sorted_techs[:top_k]]

    def get_avoid_techniques(self, threshold: float = 0.3) -> List[str]:
        scored = {}
        for t, count in self.worst_techniques.items():
            success_count = self.best_techniques.get(t, 0)
            fail_rate = count / max(count + success_count, 1)
            if count >= 2 and fail_rate >= threshold:
                scored[t] = fail_rate
        sorted_techs = sorted(scored.items(), key=lambda x: -x[1])
        return [t for t, s in sorted_techs[:5]]

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "ip_addresses": self.ip_addresses,
            "technologies": self.tech.technologies,
            "open_ports": self.tech.open_ports,
            "waf": self.tech.waf_detected,
            "cms": self.tech.cms_type,
            "total_scans": len(self.scans),
            "total_findings": self.total_findings,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "tags": list(self.tags),
            "best_techniques": dict(sorted(self.best_techniques.items(), key=lambda x: -x[1])[:10]),
        }


class TargetProfiler:
    _instance = None

    def __init__(self):
        self.profiles: Dict[str, TargetProfile] = {}
        self._load()

    @classmethod
    def get_instance(cls) -> "TargetProfiler":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def get_or_create(self, domain: str) -> TargetProfile:
        key = domain.lower().replace("https://", "").replace("http://", "").split("/")[0]
        if key not in self.profiles:
            self.profiles[key] = TargetProfile(domain=key)
            logger.info(f"TargetProfiler: new profile for {key}")
        return self.profiles[key]

    def get_similar_targets(self, domain: str) -> List[TargetProfile]:
        current = self.get_or_create(domain)
        similar = []
        for other in self.profiles.values():
            if other.domain == current.domain:
                continue
            score = self._compute_similarity(current, other)
            if score > 0.3:
                similar.append((score, other))
        similar.sort(key=lambda x: -x[0])
        return [p for _, p in similar[:5]]

    def _compute_similarity(self, a: TargetProfile, b: TargetProfile) -> float:
        score = 0.0
        a_techs = set(a.tech.technologies.keys())
        b_techs = set(b.tech.technologies.keys())
        if a_techs and b_techs:
            overlap = len(a_techs & b_techs)
            score += overlap / max(len(a_techs | b_techs), 1) * 0.4

        a_ports = set(a.tech.open_ports)
        b_ports = set(b.tech.open_ports)
        if a_ports and b_ports:
            overlap = len(a_ports & b_ports)
            score += overlap / max(len(a_ports | b_ports), 1) * 0.3

        if a.tech.cms_type and b.tech.cms_type and a.tech.cms_type == b.tech.cms_type:
            score += 0.15
        if a.tech.waf_detected and b.tech.waf_detected and a.tech.waf_detected == b.tech.waf_detected:
            score += 0.15

        return score

    async def recommend_strategy(self, domain: str) -> Dict:
        profile = self.get_or_create(domain)
        similar = self.get_similar_targets(domain)

        recommendations = {
            "domain": domain,
            "recommended_techniques": profile.get_recommended_techniques(),
            "avoid_techniques": profile.get_avoid_techniques(),
            "similar_targets": [p.domain for p in similar],
            "tech_stack": profile.tech.technologies,
        }

        if similar:
            all_best = {}
            for p in similar:
                for t, c in p.best_techniques.items():
                    all_best[t] = all_best.get(t, 0) + c
            transferred = sorted(all_best.items(), key=lambda x: -x[1])[:5]
            recommendations["transferred_techniques"] = [t for t, _ in transferred]

        return recommendations

    def _save(self):
        PROFILE_STORE.parent.mkdir(parents=True, exist_ok=True)
        data = {k: v.to_dict() for k, v in self.profiles.items()}
        PROFILE_STORE.write_text(json.dumps(data, indent=2))

    def _load(self):
        try:
            if PROFILE_STORE.exists():
                data = json.loads(PROFILE_STORE.read_text())
                for domain, d in data.items():
                    profile = TargetProfile(domain=domain)
                    profile.ip_addresses = d.get("ip_addresses", [])
                    profile.tech.technologies = d.get("technologies", {})
                    profile.tech.open_ports = d.get("open_ports", [])
                    profile.tech.waf_detected = d.get("waf")
                    profile.tech.cms_type = d.get("cms")
                    profile.total_findings = d.get("total_findings", 0)
                    profile.first_seen = d.get("first_seen", time.time())
                    profile.last_seen = d.get("last_seen", time.time())
                    profile.tags = set(d.get("tags", []))
                    if "best_techniques" in d:
                        profile.best_techniques = {k: float(v) for k, v in d["best_techniques"].items()}
                    self.profiles[domain] = profile
                logger.info(f"TargetProfiler: loaded {len(self.profiles)} profiles")
        except Exception as e:
            logger.debug(f"Failed to load profiles: {e}")


get_target_profiler = TargetProfiler.get_instance
