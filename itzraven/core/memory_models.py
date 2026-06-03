"""
Data models for Itzraven Memory System

Provides type-safe data structures for:
- Targets
- Vulnerabilities
- Exploits
- Attack paths
- Scan state

All models integrate with Neo4j, Qdrant, and Redis.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Any, Optional
from enum import Enum
import json


class VulnerabilitySeverity(Enum):
    """Vulnerability severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ExploitType(Enum):
    """Types of exploits"""
    MANUAL = "manual"
    AUTOMATED = "automated"
    TOOL = "tool"
    FRAMEWORK = "framework"


class AttackComplexity(Enum):
    """Attack complexity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass
class Target:
    """
    Target system representation

    Represents a target system being scanned, including
    its properties, technologies, and scan history.
    """
    id: str
    url: str
    hostname: str
    ip_address: Optional[str] = None
    ports: List[int] = field(default_factory=list)
    technologies: List[str] = field(default_factory=list)
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    scan_count: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_neo4j(self) -> Dict[str, Any]:
        """Convert to Neo4j node properties"""
        return {
            "id": self.id,
            "url": self.url,
            "hostname": self.hostname,
            "ip_address": self.ip_address,
            "ports": self.ports,
            "technologies": self.technologies,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "scan_count": self.scan_count,
            "metadata": json.dumps(self.metadata),
        }

    @classmethod
    def from_neo4j(cls, data: Dict[str, Any]) -> "Target":
        """Create from Neo4j node properties"""
        return cls(
            id=data["id"],
            url=data["url"],
            hostname=data["hostname"],
            ip_address=data.get("ip_address"),
            ports=data.get("ports", []),
            technologies=data.get("technologies", []),
            first_seen=datetime.fromisoformat(data["first_seen"]),
            last_seen=datetime.fromisoformat(data["last_seen"]),
            scan_count=data.get("scan_count", 0),
            metadata=json.loads(data.get("metadata", "{}")),
        )


@dataclass
class Vulnerability:
    """
    Vulnerability representation

    Represents a security vulnerability discovered during scanning,
    including evidence, confidence, and validation status.
    """
    id: str
    title: str
    description: str
    severity: VulnerabilitySeverity
    category: str
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    confidence: float = 1.0
    first_discovered: datetime = field(default_factory=datetime.now)
    last_validated: Optional[datetime] = None
    validation_count: int = 0
    false_positive: bool = False
    evidence: str = ""
    proof_of_concept: Optional[str] = None
    reproducibility_steps: Optional[List[str]] = None
    fix_hint: Optional[str] = None
    validation_status: str = "validated"
    poc_validated: bool = False
    reliability_score: float = 0.0
    attempts_count: int = 0
    remediation: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_neo4j(self) -> Dict[str, Any]:
        """Convert to Neo4j node properties"""
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "category": self.category,
            "cwe_id": self.cwe_id,
            "cvss_score": self.cvss_score,
            "confidence": self.confidence,
            "first_discovered": self.first_discovered.isoformat(),
            "last_validated": self.last_validated.isoformat() if self.last_validated else None,
            "validation_count": self.validation_count,
            "false_positive": self.false_positive,
            "validation_status": self.validation_status,
            "poc_validated": self.poc_validated,
            "reproducibility_steps": json.dumps(self.reproducibility_steps or []),
            "fix_hint": self.fix_hint,
            "metadata": json.dumps(self.metadata),
        }

    @classmethod
    def from_neo4j(cls, data: Dict[str, Any]) -> "Vulnerability":
        """Create from Neo4j node properties"""
        return cls(
            id=data["id"],
            title=data["title"],
            description=data["description"],
            severity=VulnerabilitySeverity(data["severity"]),
            category=data["category"],
            cwe_id=data.get("cwe_id"),
            cvss_score=data.get("cvss_score"),
            confidence=data["confidence"],
            first_discovered=datetime.fromisoformat(data["first_discovered"]),
            last_validated=datetime.fromisoformat(data["last_validated"]) if data.get("last_validated") else None,
            validation_count=data.get("validation_count", 0),
            false_positive=data.get("false_positive", False),
            evidence="",  # Not stored in Neo4j
            proof_of_concept=None,  # Not stored in Neo4j
            reproducibility_steps=json.loads(data.get("reproducibility_steps", "[]")),
            fix_hint=data.get("fix_hint"),
            validation_status=data.get("validation_status", "validated"),
            poc_validated=data.get("poc_validated", False),
            remediation=None,  # Not stored in Neo4j
            metadata=json.loads(data.get("metadata", "{}")),
        )

    def to_qdrant_payload(self) -> Dict[str, Any]:
        """Convert to Qdrant payload"""
        return {
            "finding_id": self.id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "category": self.category,
            "confidence": self.confidence,
            "validated": self.last_validated is not None,
            "validation_status": self.validation_status,
            "poc_validated": self.poc_validated,
            "reproducibility_steps": self.reproducibility_steps or [],
            "fix_hint": self.fix_hint,
            "timestamp": self.first_discovered.isoformat(),
            "cwe_id": self.cwe_id,
            "cvss_score": self.cvss_score,
        }

    def get_embedding_text(self) -> str:
        """Get text for embedding generation"""
        parts = [
            self.title,
            self.description,
            f"Category: {self.category}",
            f"Severity: {self.severity.value}",
        ]

        if self.evidence:
            parts.append(f"Evidence: {self.evidence}")

        if self.cwe_id:
            parts.append(f"CWE: {self.cwe_id}")

        return ". ".join(parts)


@dataclass
class Exploit:
    """
    Exploit representation

    Represents an exploit that can be used against a vulnerability,
    including success rate and prerequisites.
    """
    id: str
    name: str
    type: ExploitType
    payload: str
    success_rate: float = 0.0
    prerequisites: List[str] = field(default_factory=list)
    impact: str = ""
    created_at: datetime = field(default_factory=datetime.now)
    last_used: Optional[datetime] = None
    use_count: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_neo4j(self) -> Dict[str, Any]:
        """Convert to Neo4j node properties"""
        return {
            "id": self.id,
            "name": self.name,
            "type": self.type.value,
            "payload": self.payload,
            "success_rate": self.success_rate,
            "prerequisites": self.prerequisites,
            "impact": self.impact,
            "created_at": self.created_at.isoformat(),
            "last_used": self.last_used.isoformat() if self.last_used else None,
            "use_count": self.use_count,
            "metadata": json.dumps(self.metadata),
        }

    @classmethod
    def from_neo4j(cls, data: Dict[str, Any]) -> "Exploit":
        """Create from Neo4j node properties"""
        return cls(
            id=data["id"],
            name=data["name"],
            type=ExploitType(data["type"]),
            payload=data["payload"],
            success_rate=data.get("success_rate", 0.0),
            prerequisites=data.get("prerequisites", []),
            impact=data.get("impact", ""),
            created_at=datetime.fromisoformat(data["created_at"]),
            last_used=datetime.fromisoformat(data["last_used"]) if data.get("last_used") else None,
            use_count=data.get("use_count", 0),
            metadata=json.loads(data.get("metadata", "{}")),
        )


@dataclass
class AttackPath:
    """
    Attack path from initial access to goal

    Represents a sequence of vulnerabilities and exploits
    that lead to a specific impact (e.g., privilege escalation).
    """
    path_id: str
    vulnerabilities: List[Vulnerability]
    exploits: List[Exploit]
    success_probability: float
    complexity: AttackComplexity
    estimated_time: float  # minutes
    prerequisites: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def length(self) -> int:
        """Get path length (number of steps)"""
        return len(self.vulnerabilities)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "path_id": self.path_id,
            "vulnerabilities": [v.id for v in self.vulnerabilities],
            "exploits": [e.id for e in self.exploits],
            "success_probability": self.success_probability,
            "complexity": self.complexity.value,
            "estimated_time": self.estimated_time,
            "length": self.length,
            "prerequisites": self.prerequisites,
            "metadata": self.metadata,
        }


@dataclass
class ScanState:
    """
    Scan session state

    Represents the current state of a scan session,
    stored in Redis for distributed coordination.
    """
    scan_id: str
    target: str
    mode: str
    status: str  # pending, running, completed, failed
    start_time: datetime
    end_time: Optional[datetime] = None
    agents_total: int = 0
    agents_completed: int = 0
    findings_count: int = 0
    current_phase: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_redis(self) -> Dict[str, str]:
        """Convert to Redis hash (all values must be strings)"""
        return {
            "scan_id": self.scan_id,
            "target": self.target,
            "mode": self.mode,
            "status": self.status,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else "",
            "agents_total": str(self.agents_total),
            "agents_completed": str(self.agents_completed),
            "findings_count": str(self.findings_count),
            "current_phase": self.current_phase,
            "metadata": json.dumps(self.metadata),
        }

    @classmethod
    def from_redis(cls, data: Dict[str, str]) -> "ScanState":
        """Create from Redis hash"""
        return cls(
            scan_id=data["scan_id"],
            target=data["target"],
            mode=data["mode"],
            status=data["status"],
            start_time=datetime.fromisoformat(data["start_time"]),
            end_time=datetime.fromisoformat(data["end_time"]) if data.get("end_time") else None,
            agents_total=int(data.get("agents_total", 0)),
            agents_completed=int(data.get("agents_completed", 0)),
            findings_count=int(data.get("findings_count", 0)),
            current_phase=data.get("current_phase", ""),
            metadata=json.loads(data.get("metadata", "{}")),
        )

    @property
    def progress(self) -> float:
        """Calculate scan progress percentage"""
        if self.agents_total == 0:
            return 0.0
        return (self.agents_completed / self.agents_total) * 100.0

    @property
    def duration(self) -> Optional[float]:
        """Calculate scan duration in seconds"""
        if self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return (datetime.now() - self.start_time).total_seconds()
