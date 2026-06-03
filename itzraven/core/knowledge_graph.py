"""
Knowledge Graph — tracks relationships between targets, hosts, services,
findings, exploits, and evidence across sessions.

Architecture:
  - Node types: Target, Host, Port, Service, Finding, CVE, Exploit, Credential
  - Edge types: RESOLVES_TO, RUNS_ON, HAS_PORT, HAS_SERVICE, HAS_FINDING,
                 RELATED_TO, EXPLOITS, MITIGATES, REFERENCES
  - In-memory with optional JSON persistence
"""

import json
import time
from pathlib import Path
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
from collections import defaultdict


NODE_TYPES = {
    "target", "host", "domain", "ip", "port", "service",
    "finding", "cve", "exploit", "credential", "technology",
}


EDGE_TYPES = {
    "resolves_to",        # domain -> ip
    "has_port",           # host -> port
    "runs_service",       # port -> service
    "has_finding",        # target -> finding
    "related_to",         # finding -> finding
    "exploits",           # exploit -> cve
    "uses_technology",    # target -> technology
    "references_cve",     # finding -> cve
    "has_credential",     # target -> credential
    "leads_to",           # finding -> finding (chained)
}


@dataclass
class GraphNode:
    id: str
    node_type: str
    label: str
    properties: Dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "type": self.node_type,
            "label": self.label,
            "properties": self.properties,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


@dataclass
class GraphEdge:
    source_id: str
    target_id: str
    edge_type: str
    properties: Dict[str, Any] = field(default_factory=dict)
    weight: float = 1.0
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "source": self.source_id,
            "target": self.target_id,
            "type": self.edge_type,
            "properties": self.properties,
            "weight": self.weight,
            "created_at": self.created_at,
        }


def _make_node_id(node_type: str, label: str) -> str:
    safe = label.lower().replace("://", "_").replace("/", "_").replace(".", "_").replace(":", "_")
    return f"{node_type}:{safe}"


class KnowledgeGraph:
    def __init__(self):
        self._nodes: Dict[str, GraphNode] = {}
        self._edges: List[GraphEdge] = []
        self._adjacency: Dict[str, Dict[str, List[GraphEdge]]] = defaultdict(lambda: defaultdict(list))

    def add_node(self, node_type: str, label: str, properties: Optional[Dict[str, Any]] = None) -> str:
        node_id = _make_node_id(node_type, label)
        if node_id in self._nodes:
            existing = self._nodes[node_id]
            existing.updated_at = time.time()
            if properties:
                existing.properties.update(properties)
            return node_id
        self._nodes[node_id] = GraphNode(
            id=node_id, node_type=node_type, label=label, properties=properties or {},
        )
        return node_id

    def add_edge(self, source_id: str, target_id: str, edge_type: str, properties: Optional[Dict[str, Any]] = None, weight: float = 1.0) -> str:
        if source_id not in self._nodes or target_id not in self._nodes:
            raise ValueError(f"Cannot add edge: node(s) not found ({source_id}, {target_id})")
        edge_id = f"{source_id}--{edge_type}--{target_id}"
        edge = GraphEdge(
            source_id=source_id, target_id=target_id,
            edge_type=edge_type, properties=properties or {},
            weight=weight,
        )
        self._edges.append(edge)
        self._adjacency[source_id][edge_type].append(edge)
        self._adjacency[target_id][edge_type].append(edge)
        return edge_id

    def add_target(self, url: str, tech: Optional[Dict[str, Any]] = None) -> str:
        return self.add_node("target", url, tech or {})

    def add_host(self, ip: str, hostname: str = "") -> str:
        props = {"hostname": hostname} if hostname else {}
        return self.add_node("host", ip, props)

    def add_port(self, host_id: str, port: int, protocol: str = "tcp") -> str:
        port_id = self.add_node("port", f"{host_id}:{port}/{protocol}", {"port": port, "protocol": protocol})
        self.add_edge(host_id, port_id, "has_port", {"port": port})
        return port_id

    def add_service(self, port_id: str, service_name: str, version: str = "") -> str:
        svc_id = self.add_node("service", f"{port_id}:{service_name}", {"name": service_name, "version": version})
        self.add_edge(port_id, svc_id, "runs_service")
        return svc_id

    def add_finding(self, target_id: str, title: str, severity: str, category: str) -> str:
        finding_id = self.add_node("finding", f"{target_id}:{title}", {
            "title": title, "severity": severity, "category": category,
        })
        self.add_edge(target_id, finding_id, "has_finding", {"severity": severity})
        return finding_id

    def add_technology(self, target_id: str, tech_name: str, version: str = "") -> str:
        tech_id = self.add_node("technology", f"{target_id}:{tech_name}", {
            "name": tech_name, "version": version,
        })
        self.add_edge(target_id, tech_id, "uses_technology")
        return tech_id

    def add_cve(self, finding_id: str, cve_id: str) -> str:
        cve_node_id = self.add_node("cve", cve_id)
        self.add_edge(finding_id, cve_node_id, "references_cve")
        return cve_node_id

    def relate_findings(self, finding_id_1: str, finding_id_2: str, relation: str = "related_to") -> str:
        return self.add_edge(finding_id_1, finding_id_2, relation)

    def get_node(self, node_id: str) -> Optional[GraphNode]:
        return self._nodes.get(node_id)

    def get_edges(self, node_id: str, edge_type: Optional[str] = None) -> List[GraphEdge]:
        if edge_type:
            return self._adjacency[node_id].get(edge_type, [])
        all_edges = []
        for edges in self._adjacency[node_id].values():
            all_edges.extend(edges)
        return all_edges

    def get_connected(self, node_id: str, edge_type: Optional[str] = None) -> List[GraphNode]:
        edges = self.get_edges(node_id, edge_type)
        connected = []
        for e in edges:
            other_id = e.target_id if e.source_id == node_id else e.source_id
            node = self._nodes.get(other_id)
            if node:
                connected.append(node)
        return connected

    def find_path(self, from_id: str, to_id: str, max_depth: int = 5) -> Optional[List[GraphEdge]]:
        visited: Set[str] = set()
        queue: List[tuple[str, List[GraphEdge]]] = [(from_id, [])]

        while queue:
            current, path = queue.pop(0)
            if current == to_id:
                return path
            if current in visited or len(path) >= max_depth:
                continue
            visited.add(current)
            for edges in self._adjacency[current].values():
                for e in edges:
                    next_id = e.target_id if e.source_id == current else e.source_id
                    if next_id not in visited:
                        queue.append((next_id, path + [e]))
        return None

    def get_findings_for_target(self, target_url: str) -> List[GraphNode]:
        target_id = _make_node_id("target", target_url)
        return self.get_connected(target_id, "has_finding")

    def get_all_findings(self) -> List[GraphNode]:
        return [n for n in self._nodes.values() if n.node_type == "finding"]

    def get_all_targets(self) -> List[GraphNode]:
        return [n for n in self._nodes.values() if n.node_type == "target"]

    def get_attack_surface(self, target_url: str) -> Dict[str, Any]:
        target_id = _make_node_id("target", target_url)
        target_node = self._nodes.get(target_id)
        if not target_node:
            return {"target": target_url, "error": "Target not found"}

        findings = self.get_connected(target_id, "has_finding")
        technologies = self.get_connected(target_id, "uses_technology")

        host_nodes = self.get_connected(target_id, "resolves_to")
        ports = []
        for h in host_nodes:
            port_connected = self.get_connected(h.id, "has_port")
            ports.extend(port_connected)

        return {
            "target": target_url,
            "findings": [{"title": n.label, "severity": n.properties.get("severity"),
                          "category": n.properties.get("category")} for n in findings],
            "technologies": [{"name": n.properties.get("name"),
                              "version": n.properties.get("version")} for n in technologies],
            "hosts": [{"ip": n.label} for n in host_nodes],
            "ports": [{"label": p.label, "port": p.properties.get("port")} for p in ports],
            "finding_count": len(findings),
        }

    @property
    def count(self) -> int:
        return len(self._nodes)

    @property
    def edge_count(self) -> int:
        return len(self._edges)

    def to_dict(self) -> dict:
        return {
            "nodes": {nid: n.to_dict() for nid, n in self._nodes.items()},
            "edges": [e.to_dict() for e in self._edges],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    def save(self, filepath: str):
        Path(filepath).parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, "w") as f:
            f.write(self.to_json())

    @classmethod
    def load(cls, filepath: str) -> "KnowledgeGraph":
        kg = cls()
        try:
            with open(filepath) as f:
                data = json.load(f)
            for nid, ndata in data.get("nodes", {}).items():
                node = GraphNode(
                    id=ndata["id"], node_type=ndata["type"],
                    label=ndata["label"], properties=ndata.get("properties", {}),
                    created_at=ndata.get("created_at", 0),
                    updated_at=ndata.get("updated_at", 0),
                )
                kg._nodes[nid] = node
            for edata in data.get("edges", []):
                edge = GraphEdge(
                    source_id=edata["source"], target_id=edata["target"],
                    edge_type=edata["type"], properties=edata.get("properties", {}),
                    weight=edata.get("weight", 1.0),
                    created_at=edata.get("created_at", 0),
                )
                kg._edges.append(edge)
                kg._adjacency[edge.source_id][edge.edge_type].append(edge)
                kg._adjacency[edge.target_id][edge.edge_type].append(edge)
        except (FileNotFoundError, json.JSONDecodeError):
            pass
        return kg


_knowledge_graph: Optional[KnowledgeGraph] = None


def get_knowledge_graph() -> KnowledgeGraph:
    global _knowledge_graph
    if _knowledge_graph is None:
        _knowledge_graph = KnowledgeGraph()
    return _knowledge_graph


def set_knowledge_graph(kg: KnowledgeGraph) -> None:
    global _knowledge_graph
    _knowledge_graph = kg
