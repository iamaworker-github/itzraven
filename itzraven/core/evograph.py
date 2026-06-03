"""
Dual Knowledge Graph — RedAmon-inspired architecture.

Separates static attack surface (what exists) from evolutionary attack chain
(what we tried, what worked, attack paths).

AttackSurfaceGraph: Target→Host→Port→Service→Finding→CVE→Technology
EvoGraph: Action→Result→Finding→Chain (temporal, directional)
"""

import json
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from itzraven.core.logger import get_logger

logger = get_logger()


# ─── Attack Surface Graph (static) ───

@dataclass
class ASNode:
    id: str
    type: str  # target, host, port, service, finding, cve, technology, endpoint
    label: str
    properties: Dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {"id": self.id, "type": self.type, "label": self.label, "properties": self.properties}


@dataclass
class ASEdge:
    source: str
    target: str
    type: str  # runs, exposes, has_finding, affects, uses, discovered_by
    properties: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {"source": self.source, "target": self.target, "type": self.type, "properties": self.properties}


class AttackSurfaceGraph:
    def __init__(self):
        self.nodes: Dict[str, ASNode] = {}
        self.edges: List[ASEdge] = []

    def add_node(self, node: ASNode) -> str:
        self.nodes[node.id] = node
        return node.id

    def get_or_create(self, nid: str, ntype: str, label: str, props: Optional[Dict[str, Any]] = None) -> ASNode:
        if nid in self.nodes:
            return self.nodes[nid]
        node = ASNode(id=nid, type=ntype, label=label, properties=props or {})
        self.nodes[nid] = node
        return node

    def add_edge(self, source: str, target: str, etype: str, props: Optional[Dict[str, Any]] = None):
        self.edges.append(ASEdge(source=source, target=target, type=etype, properties=props or {}))

    def get_neighbors(self, nid: str) -> List[ASNode]:
        neighbor_ids = set()
        for e in self.edges:
            if e.source == nid:
                neighbor_ids.add(e.target)
            if e.target == nid:
                neighbor_ids.add(e.source)
        return [self.nodes[n] for n in neighbor_ids if n in self.nodes]

    def find_path(self, from_type: str, to_type: str) -> List[List[ASNode]]:
        paths = []
        from_nodes = [n for n in self.nodes.values() if n.type == from_type]
        to_nodes = {n.id for n in self.nodes.values() if n.type == to_type}
        for fn in from_nodes:
            visited = {fn.id}
            queue = [[fn]]
            while queue:
                path = queue.pop(0)
                last = path[-1]
                if last.id in to_nodes:
                    paths.append(path)
                    continue
                for neighbor in self.get_neighbors(last.id):
                    if neighbor.id not in visited:
                        visited.add(neighbor.id)
                        queue.append(path + [neighbor])
        return paths

    def summary(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for n in self.nodes.values():
            counts[n.type] = counts.get(n.type, 0) + 1
        return counts


# ─── EvoGraph (evolutionary attack chain) ───

@dataclass
class EvoAction:
    id: str
    type: str
    tool: str
    target_id: str
    params: Dict[str, Any] = field(default_factory=dict)
    result: str = ""
    success: Optional[bool] = None
    parent_id: Optional[str] = None
    finding_ids: List[str] = field(default_factory=list)
    duration: float = 0.0
    technique: str = ""  # sqli, xss, ssrf, etc.
    technologies: List[str] = field(default_factory=list)  # target tech stack
    error: str = ""
    timestamp: float = field(default_factory=time.time)
    parent_id: Optional[str] = None
    finding_ids: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id, "type": self.type, "tool": self.tool,
            "target_id": self.target_id, "params": {k: str(v)[:100] for k, v in self.params.items()},
            "result": self.result[:200], "success": self.success,
            "duration": round(self.duration, 2), "parent_id": self.parent_id,
            "finding_ids": self.finding_ids,
        }


class EvoGraph:
    def __init__(self):
        self.actions: Dict[str, EvoAction] = {}
        self._chains: List[List[str]] = []

    def record_action(self, action: EvoAction):
        self.actions[action.id] = action

    def get_chain(self, from_id: str) -> List[EvoAction]:
        chain = []
        current = from_id
        while current and current in self.actions:
            chain.append(self.actions[current])
            current = self.actions[current].parent_id
        return chain

    def get_attack_paths(self) -> List[List[EvoAction]]:
        successful_leaves = [a for a in self.actions.values() if a.success and any(a.finding_ids)]
        paths = []
        for leaf in successful_leaves:
            paths.append(self.get_chain(leaf.id))
        return paths

    def summary(self) -> Dict[str, Any]:
        total = len(self.actions)
        success = sum(1 for a in self.actions.values() if a.success)
        with_findings = sum(1 for a in self.actions.values() if a.finding_ids)
        return {"total_actions": total, "successful": success, "with_findings": with_findings}

    def get_technique_stats(self) -> Dict[str, Dict[str, float]]:
        stats: Dict[str, Dict[str, Any]] = {}
        for a in self.actions.values():
            if not a.technique:
                continue
            if a.technique not in stats:
                stats[a.technique] = {"attempts": 0, "successes": 0, "failures": 0, "findings": 0}
            stats[a.technique]["attempts"] += 1
            if a.success:
                stats[a.technique]["successes"] += 1
            elif a.success is False:
                stats[a.technique]["failures"] += 1
            stats[a.technique]["findings"] += len(a.finding_ids)
        for t, s in stats.items():
            s["success_rate"] = round(s["successes"] / max(s["attempts"], 1), 3)
            s["findings_per_attempt"] = round(s["findings"] / max(s["attempts"], 1), 3)
        return stats

    def get_technique_stats_for_tech(self, tech_stack: List[str]) -> Dict[str, Dict[str, float]]:
        stats: Dict[str, Dict[str, Any]] = {}
        tech_lower = [t.lower() for t in tech_stack]
        for a in self.actions.values():
            if not a.technique or not a.technologies:
                continue
            action_tech_lower = [t.lower() for t in a.technologies]
            if not any(t in tech_lower for t in action_tech_lower):
                continue
            if a.technique not in stats:
                stats[a.technique] = {"attempts": 0, "successes": 0, "failures": 0, "findings": 0}
            stats[a.technique]["attempts"] += 1
            if a.success:
                stats[a.technique]["successes"] += 1
            elif a.success is False:
                stats[a.technique]["failures"] += 1
            stats[a.technique]["findings"] += len(a.finding_ids)
        for t, s in stats.items():
            s["success_rate"] = round(s["successes"] / max(s["attempts"], 1), 3)
        return stats

    def to_dict(self) -> Dict[str, Any]:
        return {"actions": [a.to_dict() for a in self.actions.values()]}


class DualKnowledgeGraph:
    def __init__(self, persist_path: Optional[str] = None):
        self.attack_surface = AttackSurfaceGraph()
        self.evo = EvoGraph()
        self._persist_path = persist_path or str(Path.home() / ".itzraven" / "dual_kg.json")

    def add_target(self, target: str) -> str:
        tid = f"target:{target}"
        self.attack_surface.get_or_create(tid, "target", target)
        return tid

    def add_host(self, target: str, host: str, ip: str = "") -> str:
        tid = f"target:{target}"
        hid = f"host:{host or ip}"
        self.attack_surface.get_or_create(hid, "host", host or ip, {"ip": ip})
        self.attack_surface.add_edge(tid, hid, "resolves_to")
        return hid

    def add_port(self, host_id: str, port: int, protocol: str = "tcp", service: str = "") -> str:
        pid = f"port:{host_id}:{port}"
        self.attack_surface.get_or_create(pid, "port", f"{port}/{protocol}", {"port": port, "protocol": protocol, "service": service})
        self.attack_surface.add_edge(host_id, pid, "exposes")
        return pid

    def add_finding(self, target: str, title: str, severity: str, agent: str) -> str:
        fid = f"finding:{target}:{hash(title) % 1000000}"
        self.attack_surface.get_or_create(fid, "finding", title, {"severity": severity, "agent": agent})
        tid = f"target:{target}"
        if tid in self.attack_surface.nodes:
            self.attack_surface.add_edge(tid, fid, "has_finding")
        return fid

    def add_technology(self, target: str, tech: str, version: str = "") -> str:
        teid = f"tech:{target}:{tech}"
        self.attack_surface.get_or_create(teid, "technology", tech, {"version": version})
        tid = f"target:{target}"
        if tid in self.attack_surface.nodes:
            self.attack_surface.add_edge(tid, teid, "uses")
        return teid

    def record_evo_action(self, aid: str, atype: str, tool: str, target_id: str, params: Dict[str, Any] = None, result: str = "", success: bool = None, parent_id: str = None) -> EvoAction:
        action = EvoAction(id=aid, type=atype, tool=tool, target_id=target_id, params=params or {}, result=result, success=success, parent_id=parent_id)
        self.evo.record_action(action)
        return action

    def get_attack_paths(self) -> List[List[Dict[str, Any]]]:
        return [[a.to_dict() for a in path] for path in self.evo.get_attack_paths()]

    def summary(self) -> Dict[str, Any]:
        return {"attack_surface": self.attack_surface.summary(), "evo": self.evo.summary()}

    def save(self, path: Optional[str] = None):
        p = path or self._persist_path
        data = {
            "attack_surface": {"nodes": {k: v.to_dict() for k, v in self.attack_surface.nodes.items()}, "edges": [e.to_dict() for e in self.attack_surface.edges]},
            "evo": self.evo.to_dict(),
        }
        Path(p).parent.mkdir(parents=True, exist_ok=True)
        with open(p, "w") as f:
            json.dump(data, f, indent=2)

    def load(self, path: Optional[str] = None):
        p = path or self._persist_path
        if not Path(p).exists():
            return
        try:
            with open(p) as f:
                data = json.load(f)
            for nid, ndata in data.get("attack_surface", {}).get("nodes", {}).items():
                self.attack_surface.nodes[nid] = ASNode(**ndata)
            for edata in data.get("attack_surface", {}).get("edges", []):
                self.attack_surface.edges.append(ASEdge(**edata))
            for adata in data.get("evo", {}).get("actions", []):
                self.evo.actions[adata["id"]] = EvoAction(**adata)
        except Exception as e:
            logger.debug(f"DualKG load failed: {e}")


_dual_kg: Optional[DualKnowledgeGraph] = None


def get_dual_kg() -> DualKnowledgeGraph:
    global _dual_kg
    if _dual_kg is None:
        _dual_kg = DualKnowledgeGraph()
        _dual_kg.load()
    return _dual_kg
