"""
Goal Tree — recursive goal decomposition for autonomous pentesting.

The orchestrator decomposes "Compromise target" into sub-goals:
- Reconnaissance → Technology Detection → Port Scanning → Subdomain Discovery
- Vulnerability Discovery → SQLi Testing → XSS Testing → SSRF Testing
- Exploitation → Data Extraction → Lateral Movement

Each goal can have sub-goals, preconditions, and success criteria.
Goals are worked on by agents, and progress is tracked.
"""

import time
import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Callable
from enum import Enum

from itzraven.core.logger import get_logger

logger = get_logger()


class GoalStatus(Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    BLOCKED = "blocked"


@dataclass
class Goal:
    id: str = ""
    name: str = ""
    description: str = ""
    category: str = ""  # recon, vuln, exploit, post_exploit
    technique: str = ""  # sqli, xss, ssrf, etc.
    required_techs: List[str] = field(default_factory=list)
    required_findings: List[str] = field(default_factory=list)
    status: GoalStatus = GoalStatus.PENDING
    confidence: float = 0.0
    parent_id: Optional[str] = None
    sub_goals: List[str] = field(default_factory=list)
    result_summary: str = ""
    agent_assigned: str = ""
    created_at: float = 0.0
    completed_at: float = 0.0
    priority: int = 5  # 1-10

    def __post_init__(self):
        if not self.id:
            self.id = uuid.uuid4().hex[:8]
        if not self.created_at:
            self.created_at = time.time()

    def can_start(self, technologies: List[str], completed_goals: List[str]) -> bool:
        if self.required_techs:
            tech_lower = [t.lower() for t in technologies]
            if not any(r.lower() in tech_lower for r in self.required_techs):
                return False
        if self.required_findings:
            if not all(f in completed_goals for f in self.required_findings):
                return False
        return self.status == GoalStatus.PENDING or self.status == GoalStatus.BLOCKED

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "category": self.category,
            "status": self.status.value,
            "confidence": self.confidence,
            "parent_id": self.parent_id,
            "sub_goals": self.sub_goals,
            "agent_assigned": self.agent_assigned,
            "priority": self.priority,
        }


GOAL_TEMPLATES: Dict[str, List[dict]] = {
    "recon": [
        {"name": "Technology Fingerprinting", "category": "recon", "technique": "fingerprint", "priority": 10,
         "description": "Identify target technologies (httpx -td)"},
        {"name": "Port Scanning", "category": "recon", "technique": "port_scan", "priority": 9,
         "description": "Discover open ports and services", "required_findings": ["Technology Fingerprinting"]},
        {"name": "Subdomain Discovery", "category": "recon", "technique": "dns_enum", "priority": 7,
         "description": "Find subdomains via DNS enumeration"},
        {"name": "Endpoint Discovery", "category": "recon", "technique": "endpoint_discovery", "priority": 8,
         "description": "Discover hidden endpoints and paths", "required_findings": ["Technology Fingerprinting"]},
        {"name": "WAF Fingerprinting", "category": "recon", "technique": "waf_detect", "priority": 6,
         "description": "Detect WAF/firewall and identify bypass techniques"},
    ],
    "vuln": [
        {"name": "SQL Injection Testing", "category": "vuln", "technique": "sql_injection", "priority": 9,
         "required_techs": ["mysql", "postgresql", "oracle", "mssql", "sqlite"],
         "description": "Test for SQL injection vulnerabilities"},
        {"name": "XSS Testing", "category": "vuln", "technique": "xss", "priority": 8,
         "description": "Test for cross-site scripting vulnerabilities"},
        {"name": "SSRF Testing", "category": "vuln", "technique": "ssrf", "priority": 9,
         "required_techs": ["java", "tomcat", "node", "python", "php"],
         "description": "Test for server-side request forgery"},
        {"name": "Authentication Testing", "category": "vuln", "technique": "authentication", "priority": 7,
         "description": "Test authentication mechanisms for bypass"},
        {"name": "IDOR Testing", "category": "vuln", "technique": "idor", "priority": 7,
         "description": "Test for insecure direct object references"},
        {"name": "Command Injection Testing", "category": "vuln", "technique": "command_injection", "priority": 6,
         "description": "Test for OS command injection"},
        {"name": "XXE Testing", "category": "vuln", "technique": "xxe", "priority": 5,
         "required_techs": ["xml", "soap", "dtd"],
         "description": "Test for XML external entity injection"},
    ],
    "exploit": [
        {"name": "Data Extraction", "category": "exploit", "technique": "data_extraction", "priority": 8,
         "required_findings": ["SQL Injection Testing"],
         "description": "Extract data from database via SQLi"},
        {"name": "Internal Network Pivot", "category": "exploit", "technique": "internal_pivot", "priority": 7,
         "required_findings": ["SSRF Testing"],
         "description": "Use SSRF to scan and access internal services"},
        {"name": "Session Hijacking", "category": "exploit", "technique": "session_hijack", "priority": 6,
         "required_findings": ["XSS Testing"],
         "description": "Steal session tokens via XSS"},
    ],
}


class GoalTreePlanner:
    _instance = None

    def __init__(self):
        self.goals: Dict[str, Goal] = {}
        self.target_technologies: List[str] = []
        self.completed_goal_names: List[str] = []
        self._goal_order: List[str] = []

    @classmethod
    def get_instance(cls) -> "GoalTreePlanner":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def plan_for_target(self, technologies: List[str], depth: str = "quick") -> List[Goal]:
        self.target_technologies = technologies
        self.goals.clear()
        self.completed_goal_names.clear()

        tech_lower = [t.lower() for t in technologies]
        categories = ["recon"] if depth == "quick" else ["recon", "vuln", "exploit"]
        if depth == "deep":
            categories.append("post_exploit")

        created = []
        for cat in categories:
            templates = GOAL_TEMPLATES.get(cat, [])
            for tmpl in templates:
                goal = Goal(
                    name=tmpl["name"],
                    description=tmpl.get("description", ""),
                    category=tmpl["category"],
                    technique=tmpl.get("technique", ""),
                    priority=tmpl.get("priority", 5),
                    required_techs=tmpl.get("required_techs", []),
                    required_findings=tmpl.get("required_findings", []),
                )
                goal.id = f"goal_{cat}_{goal.name.lower().replace(' ', '_')}_{uuid.uuid4().hex[:4]}"
                self.goals[goal.id] = goal
                created.append(goal)

        self._goal_order = [g.id for g in sorted(created, key=lambda g: -g.priority)]
        logger.info(f"🎯 GoalTree: {len(created)} goals planned for {technologies}")
        return created

    def get_next_goals(self) -> List[Goal]:
        """Get goals that are ready to start (preconditions met)."""
        ready = []
        for gid in self._goal_order:
            goal = self.goals.get(gid)
            if goal and goal.can_start(self.target_technologies, self.completed_goal_names):
                ready.append(goal)
        return ready

    def mark_completed(self, goal_id: str, summary: str = ""):
        goal = self.goals.get(goal_id)
        if goal:
            goal.status = GoalStatus.COMPLETED
            goal.completed_at = time.time()
            goal.result_summary = summary
            self.completed_goal_names.append(goal.name)
            logger.info(f"✅ Goal completed: {goal.name}")

    def mark_failed(self, goal_id: str, reason: str = ""):
        goal = self.goals.get(goal_id)
        if goal:
            goal.status = GoalStatus.FAILED
            goal.result_summary = reason
            logger.info(f"❌ Goal failed: {goal.name} — {reason}")

    def get_progress(self) -> dict:
        total = len(self.goals)
        completed = sum(1 for g in self.goals.values() if g.status == GoalStatus.COMPLETED)
        failed = sum(1 for g in self.goals.values() if g.status == GoalStatus.FAILED)
        in_progress = sum(1 for g in self.goals.values() if g.status == GoalStatus.IN_PROGRESS)
        return {
            "total_goals": total,
            "completed": completed,
            "failed": failed,
            "in_progress": in_progress,
            "progress_pct": round(completed / max(total, 1) * 100, 1),
        }

    def assign_agent(self, goal_id: str, agent_name: str):
        goal = self.goals.get(goal_id)
        if goal:
            goal.agent_assigned = agent_name
            goal.status = GoalStatus.IN_PROGRESS


get_goal_tree = GoalTreePlanner.get_instance
