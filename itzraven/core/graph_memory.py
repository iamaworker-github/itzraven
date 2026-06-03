"""
Graph Memory Engine — persistent knowledge graph for OSINT entities and relationships.

Without this, Itzraven is just a "glorified search wrapper". The graph memory provides:
1. Entity resolution (deduplication of findings across agents)
2. Relationship tracking (who-owns-what, domain-resolves-to-IP, etc.)
3. Path finding (find connections between seemingly unrelated entities)
4. Confidence decay (feedback loop — findings age and need reinforcement)
5. Clustering (group related entities into investigation subjects)
6. Time-aware queries (what did we know about X at time T)
"""

import json
import math
import time
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any, Callable
from enum import Enum

from itzraven.core.logger import get_logger

logger = get_logger()

GRAPH_DB_PATH = Path.home() / ".itzraven" / "graph_memory"


class EntityType(Enum):
    DOMAIN = "domain"
    IP_ADDRESS = "ip_address"
    URL = "url"
    EMAIL = "email"
    PHONE = "phone"
    PERSON = "person"
    ORGANIZATION = "organization"
    SOCIAL_ACCOUNT = "social_account"
    LOCATION = "location"
    BRAND = "brand"
    CERTIFICATE = "certificate"
    ASN = "asn"
    CIDR = "cidr"
    HASH = "hash"
    FILENAME = "filename"
    KEYWORD = "keyword"
    BREACH = "breach"
    VULNERABILITY = "vulnerability"
    CVE = "cve"
    TECHNOLOGY = "technology"
    JOB = "job"
    REPOSITORY = "repository"
    PHOTO = "photo"
    VIDEO = "video"
    DOCUMENT = "document"
    PORT = "port"
    SERVICE = "service"
    EXPLOIT = "exploit"
    ATTACK_PATH = "attack_path"
    SCAN_TASK = "scan_task"
    CHAIN_LINK = "chain_link"
    TOOL_RESULT = "tool_result"
    HYPOTHESIS = "hypothesis"
    DECISION = "decision"
    UNKNOWN = "unknown"


class RelationType(Enum):
    RESOLVES_TO = "resolves_to"           # Domain → IP
    OWNS = "owns"                          # Person/Org → Domain
    HOSTS = "hosts"                        # IP → Domain
    REGISTERS = "registers"               # Person → Domain (via WHOIS)
    BELONGS_TO = "belongs_to"             # Email → Person/Org
    EMPLOYEE_OF = "employee_of"           # Person → Organization
    MENTIONS = "mentions"                 # Any → Any (co-occurrence)
    LINKS_TO = "links_to"                 # URL → URL (hyperlinks)
    REDIRECTS_TO = "redirects_to"        # URL → URL (HTTP redirect)
    SUBDOMAIN_OF = "subdomain_of"        # sub.example.com → example.com
    CERTIFICATE_FOR = "certificate_for"  # Cert → Domain
    HAS_EMAIL = "has_email"              # Person/Org → Email
    HAS_PHONE = "has_phone"              # Person/Org → Phone
    HAS_SOCIAL = "has_social"            # Person/Org → SocialAccount
    LOCATED_AT = "located_at"           # Person/Org → Location
    FOUND_IN = "found_in"               # Secret → Repository
    PUBLISHED_ON = "published_on"       # Content → URL
    ATTRIBUTED_TO = "attributed_to"     # Finding → Person/Group
    EXPLOITS = "exploits"               # Exploit → CVE/Vulnerability
    MITIGATES = "mitigates"             # Fix → CVE/Vulnerability
    DEPENDS_ON = "depends_on"           # Technology → Technology
    RUNS_ON = "runs_on"                 # Technology → IP/Domain
    CONTAINS = "contains"               # Repo → File/Secret
    ARCHIVED_AT = "archived_at"         # URL → Archived URL (Wayback)
    RELATED_TO = "related_to"           # Generic relation
    REPORTS = "reports_to"              # Employee → Manager
    SIMILAR_TO = "similar_to"           # Visual similarity
    TRACKED_BY = "tracked_by"           # Analytics: GA/GTM IDs
    SERVES = "serves"                   # CDN → Content
    AUTHENTICATES = "authenticates"    # SSO/OAuth provider → App
    SCANNED_PORT = "scanned_port"      # Scanner → Port (tool discovered port)
    DETECTED_SERVICE = "detected_service" # Port → Service (service running on port)
    HAS_VULNERABILITY = "has_vulnerability" # Service → Vuln
    LEADS_TO = "leads_to"              # Attack Path: step_A → step_B
    PREREQUISITE_FOR = "prerequisite_for" # Finding A must exist before Finding B
    MITIGATED_BY = "mitigated_by"      # Vuln → Mitigation
    CHAIN_STEP = "chain_step"          # Attack Graph: step_N → step_N+1
    CONFIRMED_BY = "confirmed_by"      # Finding → Verification
    CONTRADICTS = "contradicts"        # Finding → Finding (mutually exclusive)
    INFERRED_FROM = "inferred_from"    # Finding → Evidence
    PRIORITIZED_BY = "prioritized_by"  # Target → Priority Score
    COMPRESSED_INTO = "compressed_into" # Finding → Summary


@dataclass
class Entity:
    id: str
    type: EntityType
    name: str
    properties: Dict[str, Any] = field(default_factory=dict)
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    confidence: float = 1.0           # 0.0 to 1.0
    source: str = ""                   # Which agent found this
    tags: List[str] = field(default_factory=list)
    aliases: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "type": self.type.value,
            "name": self.name,
            "properties": self.properties,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "confidence": round(self.confidence, 4),
            "source": self.source,
            "tags": self.tags,
            "aliases": self.aliases,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Entity":
        data["type"] = EntityType(data["type"])
        return cls(**data)


@dataclass
class Relationship:
    id: str
    source_id: str
    target_id: str
    type: RelationType
    properties: Dict[str, Any] = field(default_factory=dict)
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    confidence: float = 1.0
    source: str = ""
    weight: float = 1.0               # For graph traversal scoring

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "source_id": self.source_id,
            "target_id": self.target_id,
            "type": self.type.value,
            "properties": self.properties,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "confidence": round(self.confidence, 4),
            "source": self.source,
            "weight": round(self.weight, 4),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Relationship":
        data["type"] = RelationType(data["type"])
        return cls(**data)


class GraphMemory:
    """In-memory knowledge graph with persistence, path finding, and feedback decay."""

    DECAY_HALF_LIFE = 86400 * 7       # 7 days for entity confidence decay
    RELATION_DECAY_HALF_LIFE = 86400 * 3  # 3 days for relationship decay

    def __init__(self, namespace: str = "default"):
        self.namespace = namespace
        self._entities: Dict[str, Entity] = {}
        self._relationships: Dict[str, Relationship] = {}
        self._entity_index: Dict[str, Set[str]] = defaultdict(set)   # type -> {ids}
        self._relation_index: Dict[str, Set[str]] = defaultdict(set) # type -> {ids}
        self._out_edges: Dict[str, Set[str]] = defaultdict(set)      # entity -> outgoing rel ids
        self._in_edges: Dict[str, Set[str]] = defaultdict(set)       # entity -> incoming rel ids
        self._name_index: Dict[str, Set[str]] = defaultdict(set)     # name.lower() -> {ids}
        self._change_hooks: List[Callable] = []
        self._feedback_history: List[dict] = []
        self._load()

    # ─── Entity Operations ───────────────────────────────────────────────────

    def add_entity(self, etype: EntityType, name: str,
                   properties: Optional[Dict] = None,
                   source: str = "", confidence: float = 1.0,
                   tags: Optional[List[str]] = None,
                   aliases: Optional[List[str]] = None) -> Entity:
        key = self._entity_key(etype, name)
        now = time.time()

        if key in self._entities:
            existing = self._entities[key]
            existing.last_seen = now
            existing.properties.update(properties or {})
            existing.confidence = max(existing.confidence, confidence)
            if source and source not in existing.source:
                existing.source = existing.source or source
            if tags:
                existing.tags.extend(t for t in tags if t not in existing.tags)
            if aliases:
                existing.aliases.extend(a for a in aliases if a not in existing.aliases)
            self._notify("entity_updated", existing)
            return existing

        entity = Entity(
            id=key,
            type=etype,
            name=name,
            properties=properties or {},
            first_seen=now,
            last_seen=now,
            confidence=confidence,
            source=source,
            tags=tags or [],
            aliases=aliases or [],
        )
        self._entities[key] = entity
        self._entity_index[etype.value].add(key)
        self._name_index[name.lower()].add(key)
        self._notify("entity_added", entity)
        return entity

    def get_entity(self, eid: str) -> Optional[Entity]:
        return self._entities.get(eid)

    def find_entity(self, etype: Optional[EntityType] = None,
                    name: Optional[str] = None,
                    tag: Optional[str] = None,
                    min_confidence: float = 0.0) -> List[Entity]:
        results = []
        candidates = set(self._entities.keys())

        if etype:
            candidates &= self._entity_index.get(etype.value, set())
        if name:
            candidates &= self._name_index.get(name.lower(), set())
        if tag:
            candidates = {eid for eid in candidates if tag in self._entities[eid].tags}

        for eid in candidates:
            entity = self._entities[eid]
            if entity.confidence >= min_confidence:
                results.append(entity)

        results.sort(key=lambda e: e.confidence, reverse=True)
        return results

    def search_entities(self, query: str, limit: int = 20) -> List[Entity]:
        query = query.lower()
        results = []
        for entity in self._entities.values():
            if (query in entity.name.lower()
                or query in entity.id
                or any(query in a.lower() for a in entity.aliases)
                or any(query in str(v).lower() for v in entity.properties.values())):
                results.append(entity)
            if len(results) >= limit * 2:
                break
        results.sort(key=lambda e: e.confidence, reverse=True)
        return results[:limit]

    # ─── Relationship Operations ─────────────────────────────────────────────

    def add_relation(self, source_id: str, target_id: str,
                     rtype: RelationType,
                     properties: Optional[Dict] = None,
                     source: str = "", confidence: float = 1.0,
                     weight: float = 1.0) -> Optional[Relationship]:
        if source_id not in self._entities or target_id not in self._entities:
            logger.debug(f"Cannot create relation {rtype.value}: entity missing")
            return None

        key = f"{source_id}|{rtype.value}|{target_id}"
        now = time.time()

        if key in self._relationships:
            existing = self._relationships[key]
            existing.last_seen = now
            existing.properties.update(properties or {})
            existing.confidence = max(existing.confidence, confidence)
            existing.weight = max(existing.weight, weight)
            self._notify("relation_updated", existing)
            return existing

        rel = Relationship(
            id=key, source_id=source_id, target_id=target_id,
            type=rtype, properties=properties or {},
            first_seen=now, last_seen=now,
            confidence=confidence, source=source, weight=weight,
        )
        self._relationships[key] = rel
        self._relation_index[rtype.value].add(key)
        self._out_edges[source_id].add(key)
        self._in_edges[target_id].add(key)
        self._notify("relation_added", rel)
        return rel

    def get_relations(self, entity_id: str,
                      rtype: Optional[RelationType] = None,
                      direction: str = "both") -> List[Relationship]:
        results = []
        if direction in ("out", "both"):
            for rid in self._out_edges.get(entity_id, set()):
                rel = self._relationships.get(rid)
                if rel and (rtype is None or rel.type == rtype):
                    results.append(rel)
        if direction in ("in", "both"):
            for rid in self._in_edges.get(entity_id, set()):
                rel = self._relationships.get(rid)
                if rel and (rtype is None or rel.type == rtype):
                    results.append(rel)
        results.sort(key=lambda r: r.weight, reverse=True)
        return results

    def find_relations(self, source_type: Optional[RelationType] = None,
                       min_confidence: float = 0.0) -> List[Relationship]:
        results = []
        candidates = self._relation_index.get(source_type.value, set()) if source_type else self._relationships.keys()
        for rid in candidates:
            rel = self._relationships[rid]
            if rel.confidence >= min_confidence:
                results.append(rel)
        return results

    def get_connected_entities(self, entity_id: str, depth: int = 1,
                               rtype: Optional[RelationType] = None) -> Dict[str, List[Entity]]:
        """Get entities connected to this entity up to {depth} hops."""
        visited = {entity_id}
        queue = deque([(entity_id, 0)])
        connected: Dict[str, List[Entity]] = {}

        while queue:
            current_id, current_depth = queue.popleft()
            if current_depth >= depth:
                continue

            for rel in self.get_relations(current_id, rtype=rtype):
                other_id = rel.target_id if rel.source_id == current_id else rel.source_id
                if other_id not in visited:
                    visited.add(other_id)
                    entity = self._entities.get(other_id)
                    if entity:
                        rel_type_name = rel.type.value
                        if rel_type_name not in connected:
                            connected[rel_type_name] = []
                        connected[rel_type_name].append(entity)
                    queue.append((other_id, current_depth + 1))

        return connected

    # ─── Path Finding ────────────────────────────────────────────────────────

    def find_paths(self, source_id: str, target_id: str,
                   max_depth: int = 6,
                   min_confidence: float = 0.3) -> List[List[dict]]:
        """BFS-based path finding between two entities."""
        if source_id not in self._entities or target_id not in self._entities:
            return []

        paths = []
        queue = deque([(source_id, [source_id], [])])
        visited = {source_id: 0}

        while queue:
            current_id, path_ids, path_rels = queue.popleft()
            depth = len(path_ids) - 1

            if depth >= max_depth:
                continue

            for rel in self.get_relations(current_id):
                if rel.confidence < min_confidence:
                    continue
                next_id = rel.target_id if rel.source_id == current_id else rel.source_id
                if next_id in visited and visited[next_id] <= depth:
                    continue

                new_path_ids = path_ids + [next_id]
                new_path_rels = path_rels + [rel]

                if next_id == target_id:
                    path_data = []
                    for i, eid in enumerate(new_path_ids):
                        entity = self._entities.get(eid)
                        entry = {"entity": entity.to_dict() if entity else {"id": eid}}
                        if i < len(new_path_rels):
                            entry["relation"] = new_path_rels[i].to_dict()
                        path_data.append(entry)
                    paths.append(path_data)
                    if len(paths) >= 5:
                        return paths
                else:
                    visited[next_id] = depth + 1
                    queue.append((next_id, new_path_ids, new_path_rels))

        return paths

    # ─── Feedback Loop ───────────────────────────────────────────────────────

    def give_feedback(self, entity_id: str, positive: bool = True,
                      amount: float = 0.2, source: str = "") -> None:
        """Reinforce or decay an entity based on agent feedback."""
        entity = self._entities.get(entity_id)
        if not entity:
            return

        if positive:
            entity.confidence = min(1.0, entity.confidence + amount)
        else:
            entity.confidence = max(0.05, entity.confidence - amount)

        entity.last_seen = time.time()
        self._feedback_history.append({
            "entity_id": entity_id,
            "positive": positive,
            "amount": amount,
            "source": source,
            "timestamp": time.time(),
        })
        self._notify("feedback", entity)

    def give_relation_feedback(self, relation_id: str, positive: bool = True,
                                amount: float = 0.2) -> None:
        rel = self._relationships.get(relation_id)
        if not rel:
            return
        if positive:
            rel.confidence = min(1.0, rel.confidence + amount)
            rel.weight = min(2.0, rel.weight + amount * 0.5)
        else:
            rel.confidence = max(0.05, rel.confidence - amount)
            rel.weight = max(0.1, rel.weight - amount * 0.5)

    def decay_all(self, force: bool = False) -> int:
        """Decay entity and relationship confidences over time."""
        now = time.time()
        decayed = 0

        for entity in self._entities.values():
            age = now - entity.last_seen
            if age > self.DECAY_HALF_LIFE * 2 and not force:
                continue
            if age > 0:
                factor = math.pow(0.5, age / self.DECAY_HALF_LIFE)
                entity.confidence = max(0.05, entity.confidence * factor)
                decayed += 1

        for rel in self._relationships.values():
            age = now - rel.last_seen
            if age > self.RELATION_DECAY_HALF_LIFE * 2 and not force:
                continue
            if age > 0:
                factor = math.pow(0.5, age / self.RELATION_DECAY_HALF_LIFE)
                rel.confidence = max(0.05, rel.confidence * factor)
                rel.weight = max(0.1, rel.weight * factor)

        return decayed

    # ─── Clustering ──────────────────────────────────────────────────────────

    def get_cluster(self, seed_id: str, max_entities: int = 50,
                    min_confidence: float = 0.3) -> Dict[str, Any]:
        """Get all entities connected to seed_id via any relationship path."""
        visited: Set[str] = set()
        queue = deque([seed_id])
        cluster_entities = {}
        cluster_relations = []

        while queue and len(visited) < max_entities:
            current_id = queue.popleft()
            if current_id in visited:
                continue
            visited.add(current_id)

            entity = self._entities.get(current_id)
            if entity:
                cluster_entities[current_id] = entity.to_dict()

            for rel in self.get_relations(current_id):
                if rel.confidence < min_confidence:
                    continue
                cluster_relations.append(rel.to_dict())
                other_id = rel.target_id if rel.source_id == current_id else rel.source_id
                if other_id not in visited:
                    queue.append(other_id)

        return {
            "seed": seed_id,
            "entity_count": len(cluster_entities),
            "relation_count": len(cluster_relations),
            "entities": cluster_entities,
            "relations": cluster_relations,
            "depth": self._compute_cluster_depth(seed_id, visited),
        }

    def _compute_cluster_depth(self, seed: str, visited: Set[str]) -> int:
        max_depth = 0
        queue = deque([(seed, 0)])
        seen = {seed}
        while queue:
            current, depth = queue.popleft()
            max_depth = max(max_depth, depth)
            for rel in self.get_relations(current):
                other = rel.target_id if rel.source_id == current else rel.source_id
                if other in visited and other not in seen:
                    seen.add(other)
                    queue.append((other, depth + 1))
        return max_depth

    # ─── Statistics & Introspection ──────────────────────────────────────────

    def get_stats(self) -> dict:
        type_counts = defaultdict(int)
        for e in self._entities.values():
            type_counts[e.type.value] += 1
        rel_type_counts = defaultdict(int)
        for r in self._relationships.values():
            rel_type_counts[r.type.value] += 1
        return {
            "namespace": self.namespace,
            "total_entities": len(self._entities),
            "total_relations": len(self._relationships),
            "entity_types": dict(type_counts),
            "relation_types": dict(rel_type_counts),
            "feedback_events": len(self._feedback_history),
            "change_hooks": len(self._change_hooks),
        }

    def get_feedback_history(self, limit: int = 100) -> List[dict]:
        return self._feedback_history[-limit:]

    # ─── Hooks / Subscriptions ───────────────────────────────────────────────

    def on_change(self, handler: Callable) -> Callable:
        self._change_hooks.append(handler)
        return handler

    def _notify(self, event: str, data: Any):
        for hook in self._change_hooks:
            try:
                hook(event, data)
            except Exception as e:
                logger.debug(f"Graph memory hook error: {e}")

    # ─── Persistence ─────────────────────────────────────────────────────────

    def persist(self):
        GRAPH_DB_PATH.mkdir(parents=True, exist_ok=True)
        ns_dir = GRAPH_DB_PATH / self.namespace
        ns_dir.mkdir(exist_ok=True)

        entities_file = ns_dir / "entities.jsonl"
        with open(entities_file, "w") as f:
            for entity in self._entities.values():
                f.write(json.dumps(entity.to_dict()) + "\n")

        rels_file = ns_dir / "relationships.jsonl"
        with open(rels_file, "w") as f:
            for rel in self._relationships.values():
                f.write(json.dumps(rel.to_dict()) + "\n")

        meta_file = ns_dir / "meta.json"
        with open(meta_file, "w") as f:
            json.dump({
                "namespace": self.namespace,
                "entity_count": len(self._entities),
                "relation_count": len(self._relationships),
                "last_saved": time.time(),
            }, f)

    def _load(self):
        ns_dir = GRAPH_DB_PATH / self.namespace
        if not ns_dir.exists():
            return

        entities_file = ns_dir / "entities.jsonl"
        if entities_file.exists():
            with open(entities_file) as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            entity = Entity.from_dict(json.loads(line))
                            self._entities[entity.id] = entity
                            self._entity_index[entity.type.value].add(entity.id)
                            self._name_index[entity.name.lower()].add(entity.id)
                        except Exception:
                            pass

        rels_file = ns_dir / "relationships.jsonl"
        if rels_file.exists():
            with open(rels_file) as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            rel = Relationship.from_dict(json.loads(line))
                            self._relationships[rel.id] = rel
                            self._relation_index[rel.type.value].add(rel.id)
                            self._out_edges[rel.source_id].add(rel.id)
                            self._in_edges[rel.target_id].add(rel.id)
                        except Exception:
                            pass

        logger.info(f"GraphMemory loaded: {len(self._entities)} entities, "
                    f"{len(self._relationships)} relationships")

    @staticmethod
    def _entity_key(etype: EntityType, name: str) -> str:
        return f"{etype.value}:{name.lower().strip()}"

    def clear(self):
        self._entities.clear()
        self._relationships.clear()
        self._entity_index.clear()
        self._relation_index.clear()
        self._out_edges.clear()
        self._in_edges.clear()
        self._name_index.clear()
        self._feedback_history.clear()
        self._notify("cleared", None)


# ─── Global Singleton ──────────────────────────────────────────────────────

_graph_memory: Optional[GraphMemory] = None


def get_graph_memory(namespace: str = "default") -> GraphMemory:
    global _graph_memory
    if _graph_memory is None:
        _graph_memory = GraphMemory(namespace=namespace)
    return _graph_memory


def set_graph_memory(gm: GraphMemory):
    global _graph_memory
    _graph_memory = gm
