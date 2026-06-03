"""
Planner Agent — stateful planning engine that reads attack graph state and decides next actions.

Architecture:
  Observe (graph state)
  → Correlate (find patterns across entities)
  → Hypothesize (generate attack hypotheses)
  → Prioritize (rank by impact + probability)
  → Execute (dispatch tool/agent)
  → Verify (check success)
  → Learn (update graph + feedback)
  → Repeat

This implements the Observe→Correlate→Hypothesize→Prioritize→Execute→Verify→Learn→Repeat loop.
"""

import asyncio
import time
import uuid
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any, Callable
from enum import Enum

from itzraven.core.logger import get_logger
from itzraven.core.graph_memory import (
    GraphMemory, EntityType, RelationType, Entity, get_graph_memory,
)
from itzraven.core.chain_matrix import (
    find_matching_chains, get_next_suggestions, ExploitChain,
)
from itzraven.core.adaptive_enum import AdaptiveEnumEngine
from itzraven.core.context_compression import ContextCompressor

logger = get_logger()


class ActionType(Enum):
    SCAN = "scan"
    ENUMERATE = "enumerate"
    EXPLOIT = "exploit"
    VERIFY = "verify"
    RECON = "recon"
    RESEARCH = "research"
    PRIVESC = "privesc"
    PIVOT = "pivot"
    EXFIL = "exfil"
    REPORT = "report"


class HypothesisStatus(Enum):
    PROPOSED = "proposed"
    IN_PROGRESS = "in_progress"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"
    SUPERSEDED = "superseded"


@dataclass
class PlannedAction:
    id: str
    type: ActionType
    target: str
    description: str
    priority: int  # 1-10
    confidence: float
    tool: str = ""
    parameters: Dict[str, Any] = field(default_factory=dict)
    prerequisites: List[str] = field(default_factory=list)
    depends_on: List[str] = field(default_factory=list)  # action IDs this depends on
    status: str = "pending"  # pending, running, completed, failed, skipped
    result: Optional[Dict[str, Any]] = None
    created_at: float = field(default_factory=time.time)
    executed_at: Optional[float] = None
    max_retries: int = 2
    retry_count: int = 0

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "type": self.type.value,
            "target": self.target,
            "description": self.description,
            "priority": self.priority,
            "confidence": round(self.confidence, 3),
            "tool": self.tool,
            "status": self.status,
        }


@dataclass
class Hypothesis:
    id: str
    description: str
    attack_chain: str
    confidence: float
    supporting_evidence: List[str]
    contradicting_evidence: List[str]
    status: HypothesisStatus
    actions: List[str]  # action IDs
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "description": self.description,
            "attack_chain": self.attack_chain,
            "confidence": round(self.confidence, 3),
            "status": self.status.value,
            "evidence_for": len(self.supporting_evidence),
            "evidence_against": len(self.contradicting_evidence),
        }


class PlannerAgent:
    """
    Stateful planning engine.

    The planner:
    1. Reads current graph state
    2. Identifies patterns (open ports, detected tech, vulns, partial exploit chains)
    3. Generates hypotheses about attack paths
    4. Ranks and prioritizes actions
    5. Returns ordered action queue
    6. Learns from results (feedback loop)
    """

    def __init__(self, target: str, graph: Optional[GraphMemory] = None,
                 compressor: Optional[ContextCompressor] = None):
        self.target = target
        self._graph = graph or get_graph_memory()
        self._adaptive = AdaptiveEnumEngine(self._graph)
        self._compressor = compressor or ContextCompressor(graph=self._graph)
        self._actions: List[PlannedAction] = []
        self._hypotheses: List[Hypothesis] = []
        self._completed_actions: List[str] = []
        self._plan_version: int = 0

    async def observe_and_plan(self) -> List[PlannedAction]:
        """Main planning loop: observe state → plan next actions."""
        self._plan_version += 1

        # 1. Observe current graph state
        state = self._observe_graph_state()

        # 2. Correlate — find patterns
        state["patterns"] = self._correlate_patterns(state)

        # 3. Hypothesize — generate attack hypotheses
        hypotheses = self._generate_hypotheses(state)
        for h in hypotheses:
            existing = [x for x in self._hypotheses if x.description == h.description]
            if not existing:
                self._hypotheses.append(h)

        # 4. Prioritize — rank by impact + probability
        actions = self._generate_actions(state, hypotheses)

        # 5. Deduplicate and merge with existing
        existing_ids = {a.id for a in self._actions if a.status == "pending"}
        for action in actions:
            if action.id not in existing_ids:
                self._actions.append(action)

        # 6. Return sorted action queue
        pending = self._get_pending_actions()
        logger.info(f"Planner: plan v{self._plan_version} → {len(pending)} pending actions, "
                    f"{len(hypotheses)} hypotheses active")
        return pending

    def _observe_graph_state(self) -> dict:
        """Read all entities and relationships from graph memory."""
        state = {
            "entities": {"ports": [], "services": [], "vulns": [], "techs": [],
                         "domains": [], "urls": [], "credentials": []},
            "relations": [],
            "completed_actions": self._completed_actions,
        }

        for entity in self._graph._entities.values():
            etype = entity.type.value
            if etype == "port":
                state["entities"]["ports"].append(entity)
            elif etype == "service":
                state["entities"]["services"].append(entity)
            elif etype == "vulnerability":
                state["entities"]["vulns"].append(entity)
            elif etype == "technology":
                state["entities"]["techs"].append(entity)
            elif etype == "domain":
                state["entities"]["domains"].append(entity)
            elif etype == "url":
                state["entities"]["urls"].append(entity)

        # Count relations
        state["total_relations"] = len(self._graph._relationships)

        return state

    def _correlate_patterns(self, state: dict) -> List[dict]:
        """Find meaningful patterns in the current state."""
        patterns = []

        # Pattern: Open web ports without tech detection → need fingerprinting
        if state["entities"]["ports"] and not state["entities"]["techs"]:
            patterns.append({
                "type": "missing_tech_fingerprint",
                "priority": 7,
                "description": "Open ports found but no technology fingerprinting done",
            })

        # Pattern: Vulnerabilities found → check for exploit chains
        vuln_names = [v.properties.get("name", "") or v.name for v in state["entities"]["vulns"]]
        if vuln_names:
            matched = find_matching_chains(vuln_names)
            if matched:
                patterns.append({
                    "type": "exploit_chain_possible",
                    "priority": 9,
                    "description": f"Found {len(matched)} matching exploit chains",
                    "chains": matched,
                })

        # Pattern: Domains without HTTP probing → need to check HTTP
        unprobed_domains = [d for d in state["entities"]["domains"]
                          if not any("httpx" in (u.tags or []) for u in state["entities"]["urls"])]
        if unprobed_domains:
            patterns.append({
                "type": "unprobed_domains",
                "priority": 6,
                "description": f"{len(unprobed_domains)} domains not HTTP probed",
                "domains": [d.name for d in unprobed_domains[:5]],
            })

        return patterns

    def _generate_hypotheses(self, state: dict) -> List[Hypothesis]:
        """Generate attack hypotheses based on current state."""
        hypotheses = []
        now = time.time()

        # Check for partial exploit chains
        vuln_names = [v.properties.get("name", "") or v.name for v in state["entities"]["vulns"]]
        tech_names = [t.name for t in state["entities"]["techs"]]
        findings_text = vuln_names + tech_names

        suggestions = get_next_suggestions(findings_text)
        for suggestion in suggestions:
            evidence = [f"Chain: {suggestion['chain']}"]
            if suggestion.get("techniques"):
                evidence.extend(suggestion["techniques"])
            hypotheses.append(Hypothesis(
                id=f"hyp_{uuid.uuid4().hex[:8]}",
                description=suggestion["description"],
                attack_chain=suggestion["chain"],
                confidence=0.6 if suggestion.get("priority") == "medium" else 0.8,
                supporting_evidence=evidence,
                contradicting_evidence=[],
                status=HypothesisStatus.PROPOSED,
                actions=[],
            ))

        # Hypothesis: Open web ports → test for common web vulns
        web_ports = [p for p in state["entities"]["ports"]
                    if p.properties.get("port") in (80, 443, 8080, 8443, 3000, 5000, 9090)]
        if web_ports and not vuln_names:
            hypotheses.append(Hypothesis(
                id=f"hyp_{uuid.uuid4().hex[:8]}",
                description="Web ports open but no vulns found → run web vuln scan",
                attack_chain="Web Port → Nuclei Scan",
                confidence=0.7,
                supporting_evidence=[f"Ports: {[p.name for p in web_ports]}"],
                contradicting_evidence=[],
                status=HypothesisStatus.PROPOSED,
                actions=[],
            ))

        # Hypothesis: SSRF → cloud metadata
        if any("ssrf" in v.name.lower() for v in state["entities"]["vulns"]):
            hypotheses.append(Hypothesis(
                id=f"hyp_{uuid.uuid4().hex[:8]}",
                description="SSRF detected → attempt cloud metadata access",
                attack_chain="SSRF → IMDS → Cloud Credentials",
                confidence=0.75,
                supporting_evidence=["SSRF vulnerability confirmed"],
                contradicting_evidence=[],
                status=HypothesisStatus.PROPOSED,
                actions=[],
            ))

        return hypotheses

    def _generate_actions(self, state: dict, hypotheses: List[Hypothesis]) -> List[PlannedAction]:
        """Convert hypotheses + patterns into concrete actions."""
        actions = []

        # Action: Initial port scan if nothing discovered
        if not state["entities"]["ports"]:
            actions.append(PlannedAction(
                id=f"act_{uuid.uuid4().hex[:8]}",
                type=ActionType.SCAN,
                target=self.target,
                description="Initial port scan (top 1000 ports)",
                priority=10,
                confidence=1.0,
                tool="naabu",
                parameters={"ports": "top-1000", "exclude-cdn": True},
            ))

        # Action: HTTP probe for discovered web ports
        web_ports = [p for p in state["entities"]["ports"]
                    if p.properties.get("port") in (80, 443, 8080, 8443, 3000, 5000, 9090)]
        if web_ports and not state["entities"]["techs"]:
            actions.append(PlannedAction(
                id=f"act_{uuid.uuid4().hex[:8]}",
                type=ActionType.ENUMERATE,
                target=self.target,
                description="HTTP technology fingerprinting",
                priority=8,
                confidence=0.9,
                tool="httpx",
                parameters={"probe_all": True},
            ))

        # Actions from hypotheses
        for hyp in hypotheses:
            if hyp.status != HypothesisStatus.PROPOSED:
                continue

            if "Nuclei Scan" in hyp.attack_chain:
                actions.append(PlannedAction(
                    id=f"act_{uuid.uuid4().hex[:8]}",
                    type=ActionType.SCAN,
                    target=self.target,
                    description="Run nuclei vulnerability scan",
                    priority=7,
                    confidence=hyp.confidence,
                    tool="nuclei",
                    parameters={"severity": "critical,high,medium"},
                ))

            if "cloud metadata" in hyp.description.lower() or "IMDS" in hyp.attack_chain:
                actions.append(PlannedAction(
                    id=f"act_{uuid.uuid4().hex[:8]}",
                    type=ActionType.EXPLOIT,
                    target=self.target,
                    description="Attempt cloud metadata service access via SSRF",
                    priority=9,
                    confidence=0.7,
                    tool="curl",
                    parameters={
                        "urls": [
                            "http://169.254.169.254/latest/meta-data/",
                            "http://metadata.google.internal/",
                            "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
                        ]
                    },
                ))

        # Actions from chain matrix suggestions
        vuln_names = [v.properties.get("name", "") or v.name for v in state["entities"]["vulns"]]
        tech_names = [t.name for t in state["entities"]["techs"]]
        suggestions = get_next_suggestions(vuln_names + tech_names)
        for suggestion in suggestions:
            actions.append(PlannedAction(
                id=f"act_{uuid.uuid4().hex[:8]}",
                type=ActionType.EXPLOIT,
                target=self.target,
                description=f"[Chain: {suggestion['chain']}] {suggestion['description']}",
                priority=8 if suggestion.get("priority") == "high" else 5,
                confidence=0.7,
                tool=suggestion.get("tools", [""])[0] if suggestion.get("tools") else "",
                parameters={"techniques": suggestion.get("techniques", [])},
            ))

        # Deduplicate by description
        seen = set()
        unique_actions = []
        for a in actions:
            if a.description not in seen:
                seen.add(a.description)
                unique_actions.append(a)

        unique_actions.sort(key=lambda a: a.priority, reverse=True)
        return unique_actions

    def record_result(self, action_id: str, success: bool, output: str = "",
                      findings: Optional[List[dict]] = None):
        """Record action result and update graph + feedback loop."""
        for action in self._actions:
            if action.id == action_id:
                action.status = "completed" if success else "failed"
                action.executed_at = time.time()
                action.result = {"success": success, "output": output[:500], "findings": findings}
                break

        self._completed_actions.append(action_id)

        # Update hypotheses based on results
        for hyp in self._hypotheses:
            if action_id in hyp.actions:
                if success:
                    hyp.supporting_evidence.append(f"Action {action_id} succeeded: {output[:100]}")
                    hyp.confidence = min(1.0, hyp.confidence + 0.1)
                    if hyp.confidence > 0.85:
                        hyp.status = HypothesisStatus.CONFIRMED
                else:
                    hyp.contradicting_evidence.append(f"Action {action_id} failed: {output[:100]}")
                    hyp.confidence = max(0.0, hyp.confidence - 0.15)
                    if hyp.confidence < 0.2:
                        hyp.status = HypothesisStatus.REJECTED

        # Update context compressor
        if findings:
            for f in findings:
                self._compressor.add_finding(
                    finding_id=f.get("id", action_id),
                    title=f.get("title", "Planner action result"),
                    severity=f.get("severity", "info"),
                    confidence=f.get("confidence", 0.5),
                    category=f.get("category", "default"),
                )

    def _get_pending_actions(self) -> List[PlannedAction]:
        pending = [a for a in self._actions if a.status == "pending"]
        pending.sort(key=lambda a: a.priority, reverse=True)

        # Filter out actions whose dependencies aren't met
        completed_ids = set(self._completed_actions)
        available = []
        for action in pending:
            deps_met = all(dep in completed_ids for dep in action.depends_on)
            if deps_met:
                available.append(action)

        return available

    def get_failed_actions(self) -> List[PlannedAction]:
        return [a for a in self._actions if a.status == "failed"]

    def get_active_hypotheses(self) -> List[Hypothesis]:
        return [h for h in self._hypotheses if h.status in
                (HypothesisStatus.PROPOSED, HypothesisStatus.IN_PROGRESS)]

    def get_plan_summary(self) -> dict:
        pending = self._get_pending_actions()
        return {
            "plan_version": self._plan_version,
            "total_actions_planned": len(self._actions),
            "pending_actions": len(pending),
            "completed_actions": len(self._completed_actions),
            "failed_actions": len(self.get_failed_actions()),
            "active_hypotheses": len(self.get_active_hypotheses()),
            "next_steps": [a.to_dict() for a in pending[:5]],
            "context": self._compressor.get_active_context(),
        }
