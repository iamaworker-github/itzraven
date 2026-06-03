"""
Campaign Manager — multi-target correlation engine.

Finds cross-target patterns:
1. Same IP hosting multiple domains? → Cross-domain vulnerability
2. Same email across breach databases? → Credential reuse
3. Same tech stack across targets? → Bulk exploitation
4. Shared WHOIS registrant? → Related organizations
5. Shared analytics/tracking IDs? → Same owner
"""

import json
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Any
from urllib.parse import urlparse

from itzraven.core.logger import get_logger
from itzraven.core.graph_memory import (
    GraphMemory, EntityType, RelationType, get_graph_memory,
)

logger = get_logger()


@dataclass
class CampaignTarget:
    name: str
    added_at: float = field(default_factory=time.time)
    scan_count: int = 0
    findings_count: int = 0

    def to_dict(self) -> dict:
        return {"name": self.name, "scan_count": self.scan_count, "findings_count": self.findings_count}


@dataclass
class CrossCorrelation:
    type: str
    description: str
    targets: List[str]
    evidence: str
    confidence: float
    severity: str

    def to_dict(self) -> dict:
        return {
            "type": self.type,
            "description": self.description,
            "targets": self.targets,
            "evidence": self.evidence,
            "confidence": round(self.confidence, 3),
            "severity": self.severity,
        }


class CampaignManager:
    """Multi-target campaign management and correlation."""

    def __init__(self, name: str = "default", graph: Optional[GraphMemory] = None):
        self.name = name
        self._graph = graph or get_graph_memory()
        self._targets: Dict[str, CampaignTarget] = {}
        self._correlations: List[CrossCorrelation] = []
        self._campaign_dir = Path.home() / ".itzraven" / "campaigns" / name
        self._campaign_dir.mkdir(parents=True, exist_ok=True)

    def add_target(self, target: str):
        if target not in self._targets:
            self._targets[target] = CampaignTarget(name=target)
            logger.info(f"Campaign '{self.name}': added target {target}")

    def remove_target(self, target: str) -> bool:
        return self._targets.pop(target, None) is not None

    def list_targets(self) -> List[dict]:
        return [t.to_dict() for t in self._targets.values()]

    async def correlate_all(self) -> List[CrossCorrelation]:
        """Run all correlation analyses across campaign targets."""
        self._correlations.clear()
        await self._run_all_correlations()
        return self._correlations

    async def _run_all_correlations(self):
        await asyncio.gather(
            self._correlate_shared_ips(),
            self._correlate_tech_stacks(),
            self._correlate_whois(),
            self._correlate_tracking_ids(),
            self._correlate_breach_overlap(),
            return_exceptions=True,
        )

    async def _correlate_shared_ips(self):
        """Find domains that share the same IP."""
        ip_to_domains = defaultdict(set)
        for rel in self._graph._relationships.values():
            if rel.type == RelationType.RESOLVES_TO:
                ip_to_domains[rel.target_id].add(rel.source_id)
        for ip, domains in ip_to_domains.items():
            if len(domains) >= 2 and self._is_in_campaign(domains):
                self._correlations.append(CrossCorrelation(
                    type="shared_ip",
                    description=f"Shared IP ({ip}) across {len(domains)} domains",
                    targets=list(domains),
                    evidence=f"IP: {ip}",
                    confidence=0.9,
                    severity="medium",
                ))

    async def _correlate_tech_stacks(self):
        """Find targets with identical technology stacks."""
        domain_techs = defaultdict(set)
        for rel in self._graph._relationships.values():
            if rel.type == RelationType.RUNS_ON:
                # source is technology, target is domain/url
                src_entity = self._graph.get_entity(rel.source_id)
                if src_entity and src_entity.type == EntityType.TECHNOLOGY:
                    domain_techs[rel.target_id].add(src_entity.name)
        seen = set()
        domains = list(domain_techs.keys())
        for i in range(len(domains)):
            for j in range(i + 1, len(domains)):
                d1, d2 = domains[i], domains[j]
                key = tuple(sorted([d1, d2]))
                if key in seen:
                    continue
                seen.add(key)
                overlap = domain_techs[d1] & domain_techs[d2]
                if len(overlap) >= 3 and self._is_in_campaign({d1, d2}):
                    self._correlations.append(CrossCorrelation(
                        type="shared_tech",
                        description=f"Shared tech stack: {', '.join(list(overlap)[:5])}",
                        targets=[d1, d2],
                        evidence=f"Technologies: {list(overlap)}",
                        confidence=0.8,
                        severity="info",
                    ))

    async def _correlate_whois(self):
        """Find targets with same WHOIS registrant."""
        org_entities = self._graph.find_entity(EntityType.ORGANIZATION)
        for org in org_entities:
            related = set()
            for rel in self._graph.get_relations(org.id):
                related.add(rel.source_id if rel.target_id == org.id else rel.target_id)
            if len(related) >= 2 and self._is_in_campaign(related):
                self._correlations.append(CrossCorrelation(
                    type="shared_owner",
                    description=f"Same organization '{org.name}' across {len(related)} targets",
                    targets=list(related),
                    evidence=f"Organization: {org.name}",
                    confidence=0.85,
                    severity="medium",
                ))

    async def _correlate_tracking_ids(self):
        """Find shared analytics/tracking IDs (Google Analytics, Facebook Pixel, etc.)."""
        ga_patterns = ["UA-", "G-", "GTM-"]
        for entity in self._graph._entities.values():
            prop_vals = " ".join(str(v) for v in entity.properties.values())
            for pattern in ga_patterns:
                if pattern in prop_vals:
                    matched = set()
                    for e2 in self._graph._entities.values():
                        p2 = " ".join(str(v) for v in e2.properties.values())
                        if pattern in p2 and e2.id != entity.id:
                            matched.add(e2.name)
                    if len(matched) >= 1:
                        all_targets = {entity.name} | matched
                        if self._is_in_campaign(all_targets):
                            self._correlations.append(CrossCorrelation(
                                type="shared_tracking",
                                description=f"Shared tracking ID '{pattern}' across {len(all_targets)} targets",
                                targets=list(all_targets),
                                evidence=f"Tracking ID: {pattern}",
                                confidence=0.9,
                                severity="medium",
                            ))

    async def _correlate_breach_overlap(self):
        """Find emails appearing in same breach databases."""
        email_breaches = defaultdict(set)
        for entity in self._graph._entities.values():
            if entity.type == EntityType.EMAIL:
                for rel in self._graph.get_relations(entity.id):
                    if rel.type == RelationType.ATTRIBUTED_TO:
                        email_breaches[entity.name].add(rel.target_id)
        seen_pairs = set()
        emails = list(email_breaches.keys())
        for i in range(len(emails)):
            for j in range(i + 1, len(emails)):
                overlap = email_breaches[emails[i]] & email_breaches[emails[j]]
                if overlap:
                    pair = tuple(sorted([emails[i], emails[j]]))
                    if pair not in seen_pairs:
                        seen_pairs.add(pair)
                        self._correlations.append(CrossCorrelation(
                            type="breach_overlap",
                            description=f"Emails {emails[i]} and {emails[j]} in same breaches",
                            targets=[emails[i], emails[j]],
                            evidence=f"Breaches: {list(overlap)}",
                            confidence=0.95,
                            severity="high",
                        ))

    def _is_in_campaign(self, names: Set[str]) -> bool:
        """Check if at least 2 of the given names are campaign targets."""
        campaign_names = set(self._targets.keys())
        return len(names & campaign_names) >= 2

    def get_correlations(self, min_confidence: float = 0.0) -> List[CrossCorrelation]:
        return [c for c in self._correlations if c.confidence >= min_confidence]

    def get_summary(self) -> dict:
        return {
            "campaign": self.name,
            "targets": len(self._targets),
            "correlations": len(self._correlations),
            "high_value": len([c for c in self._correlations if c.severity in ("high", "critical")]),
        }

    def persist(self):
        data = {
            "campaign": self.name,
            "targets": {k: v.to_dict() for k, v in self._targets.items()},
            "correlations": [c.to_dict() for c in self._correlations],
        }
        (self._campaign_dir / "state.json").write_text(json.dumps(data, indent=2))

    def _load(self):
        state_file = self._campaign_dir / "state.json"
        if state_file.exists():
            try:
                data = json.loads(state_file.read_text())
                for name, tdata in data.get("targets", {}).items():
                    self._targets[name] = CampaignTarget(**tdata)
                for cdata in data.get("correlations", []):
                    self._correlations.append(CrossCorrelation(**cdata))
            except Exception:
                pass


import asyncio
