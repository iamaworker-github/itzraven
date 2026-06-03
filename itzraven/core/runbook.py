"""
Task Tree / Runbook System — deterministic security workflows.

Each runbook defines a structured sequence of capability-checked steps
for a specific vulnerability class. Agents follow runbooks instead of
free-form ReAct, preventing drift and ensuring coverage.

Inspired by: PentestGPT (task tree), Numasec (runbooks), Escape (specialists).
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple
import time
from itzraven.core.logger import get_logger

logger = get_logger()


class StepStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class RunbookStep:
    name: str
    description: str
    required_tools: List[str] = field(default_factory=list)
    depends_on: List[str] = field(default_factory=list)
    timeout: int = 60
    status: StepStatus = StepStatus.PENDING
    result: str = ""
    error: str = ""
    duration: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "required_tools": self.required_tools,
            "depends_on": self.depends_on,
            "timeout": self.timeout,
            "status": self.status.value,
            "result": self.result[:200],
            "error": self.error[:200],
            "duration": round(self.duration, 2),
        }


@dataclass
class Runbook:
    name: str
    description: str
    category: str  # sqli, xss, ssrf, recon, enum, auth, etc.
    steps: List[RunbookStep] = field(default_factory=list)
    required_technologies: List[str] = field(default_factory=list)
    max_retries: int = 2

    def get_next_pending(self) -> Optional[RunbookStep]:
        completed = {s.name for s in self.steps if s.status in (StepStatus.PASSED, StepStatus.SKIPPED)}
        for s in self.steps:
            if s.status != StepStatus.PENDING:
                continue
            if all(dep in completed for dep in s.depends_on):
                return s
        return None

    def all_done(self) -> bool:
        return all(s.status in (StepStatus.PASSED, StepStatus.FAILED, StepStatus.SKIPPED) for s in self.steps)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "category": self.category,
            "steps": [s.to_dict() for s in self.steps],
            "required_technologies": self.required_technologies,
            "max_retries": self.max_retries,
        }


# Built-in runbooks for common vulnerability classes

SQLI_RUNBOOK = Runbook(
    name="SQL Injection Assessment",
    description="Systematic SQL injection testing across all input vectors",
    category="sqli",
    steps=[
        RunbookStep("param_discovery", "Discover injectable parameters", required_tools=["httpx", "grep"]),
        RunbookStep("time_based_test", "Test time-based SQLi payloads", depends_on=["param_discovery"]),
        RunbookStep("error_based_test", "Test error-based SQLi payloads", depends_on=["param_discovery"]),
        RunbookStep("union_test", "Test UNION-based data extraction", depends_on=["error_based_test"]),
        RunbookStep("blind_test", "Test blind SQLi with conditional responses", depends_on=["param_discovery"]),
        RunbookStep("db_fingerprint", "Identify database type from responses", depends_on=["error_based_test", "time_based_test"]),
        RunbookStep("data_extraction", "Extract database metadata if injectable", depends_on=["union_test"]),
        RunbookStep("confirmation", "Confirm with multi-payload verification", depends_on=["time_based_test", "error_based_test"]),
    ],
)

XSS_RUNBOOK = Runbook(
    name="Cross-Site Scripting Assessment",
    description="Comprehensive XSS testing across all input points",
    category="xss",
    steps=[
        RunbookStep("input_discovery", "Discover user-controlled input points", required_tools=["httpx", "grep"]),
        RunbookStep("reflected_test", "Test reflected XSS with immediate feedback", depends_on=["input_discovery"]),
        RunbookStep("stored_test", "Test stored XSS via persistent payloads", depends_on=["input_discovery"]),
        RunbookStep("dom_test", "Test DOM-based XSS via JavaScript evaluation", depends_on=["input_discovery"]),
        RunbookStep("context_analysis", "Analyze output encoding context", depends_on=["reflected_test", "stored_test"]),
        RunbookStep("bypass_test", "Test WAF/bypass payloads if filters detected", depends_on=["context_analysis"]),
        RunbookStep("confirmation", "Confirm XSS with alert() in headless browser", depends_on=["reflected_test", "stored_test"]),
    ],
)

RECON_RUNBOOK = Runbook(
    name="Reconnaissance",
    description="Systematic target discovery and fingerprinting",
    category="recon",
    steps=[
        RunbookStep("dns_lookup", "DNS resolution and subdomain discovery", required_tools=["nmap", "dig"]),
        RunbookStep("port_scan", "Port scanning with service detection", depends_on=["dns_lookup"], timeout=300),
        RunbookStep("tech_detect", "Technology stack fingerprinting", depends_on=["port_scan"], required_tools=["httpx"]),
        RunbookStep("endpoint_discovery", "Endpoint/URL discovery via wordlist", depends_on=["tech_detect"]),
        RunbookStep("waf_detect", "WAF/firewall detection", depends_on=["tech_detect"]),
        RunbookStep("ssl_check", "SSL/TLS certificate analysis", depends_on=["port_scan"]),
    ],
)

AUTH_RUNBOOK = Runbook(
    name="Authentication Assessment",
    description="Authentication mechanism testing",
    category="auth",
    steps=[
        RunbookStep("login_discovery", "Discover login/registration endpoints", required_tools=["httpx"]),
        RunbookStep("credential_test", "Test default/weak credentials", depends_on=["login_discovery"]),
        RunbookStep("session_analysis", "Analyze session token strength", depends_on=["login_discovery"]),
        RunbookStep("bypass_test", "Test auth bypass techniques", depends_on=["login_discovery"]),
        RunbookStep("rate_limit_test", "Test rate limiting on auth endpoints", depends_on=["login_discovery"]),
        RunbookStep("password_policy", "Enumerate password policy", depends_on=["login_discovery"]),
    ],
)

API_RUNBOOK = Runbook(
    name="API Security Assessment",
    description="REST/GraphQL API security testing",
    category="api",
    steps=[
        RunbookStep("endpoint_enum", "Enumerate API endpoints from docs/traffic", required_tools=["httpx"]),
        RunbookStep("auth_test", "Test API authentication", depends_on=["endpoint_enum"]),
        RunbookStep("bola_test", "Test broken object-level authorization", depends_on=["endpoint_enum"]),
        RunbookStep("rate_limit", "Test API rate limiting", depends_on=["endpoint_enum"]),
        RunbookStep("injection_test", "Test API injection points", depends_on=["endpoint_enum"]),
        RunbookStep("graphql_test", "Test GraphQL introspection and batching", depends_on=["endpoint_enum"]),
    ],
)

ALL_RUNBOOKS: Dict[str, Runbook] = {
    "sqli": SQLI_RUNBOOK,
    "xss": XSS_RUNBOOK,
    "recon": RECON_RUNBOOK,
    "auth": AUTH_RUNBOOK,
    "api": API_RUNBOOK,
}


class RunbookEngine:
    _instance: Optional["RunbookEngine"] = None

    def __init__(self):
        self._runbooks: Dict[str, Runbook] = dict(ALL_RUNBOOKS)
        self._active: Dict[str, Tuple[Runbook, int]] = {}  # session_id -> (runbook, step_index)

    def get_runbook(self, category: str) -> Optional[Runbook]:
        return self._runbooks.get(category)

    def list_categories(self) -> List[str]:
        return list(self._runbooks.keys())

    def start_runbook(self, session_id: str, category: str) -> Optional[Runbook]:
        rb = self.get_runbook(category)
        if not rb:
            return None
        for s in rb.steps:
            s.status = StepStatus.PENDING
        self._active[session_id] = (rb, 0)
        return rb

    def get_next_step(self, session_id: str) -> Optional[RunbookStep]:
        entry = self._active.get(session_id)
        if not entry:
            return None
        rb, _ = entry
        return rb.get_next_pending()

    def mark_step(self, session_id: str, step_name: str, status: StepStatus, result: str = "", error: str = ""):
        entry = self._active.get(session_id)
        if not entry:
            return
        rb, _ = entry
        for s in rb.steps:
            if s.name == step_name:
                s.status = status
                s.result = result
                s.error = error
                break

    def is_complete(self, session_id: str) -> bool:
        entry = self._active.get(session_id)
        if not entry:
            return True
        return entry[0].all_done()

    def get_runbook_status(self, session_id: str) -> Optional[Dict[str, Any]]:
        entry = self._active.get(session_id)
        if not entry:
            return None
        return entry[0].to_dict()

    def select_runbook(self, technologies: List[str], category_hint: str = "") -> Optional[Runbook]:
        if category_hint and category_hint in self._runbooks:
            return self._runbooks[category_hint]
        tech_lower = [t.lower() for t in technologies]
        for rb in self._runbooks.values():
            if any(t in tech_lower for t in rb.required_technologies):
                return rb
        return self._runbooks.get("recon")

    @classmethod
    def get_instance(cls) -> "RunbookEngine":
        if cls._instance is None:
            cls._instance = RunbookEngine()
        return cls._instance


_runbook_engine: Optional[RunbookEngine] = None


def get_runbook_engine() -> RunbookEngine:
    global _runbook_engine
    if _runbook_engine is None:
        _runbook_engine = RunbookEngine()
    return _runbook_engine
