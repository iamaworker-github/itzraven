"""
ACI (Agent-Computer Interface) — Tool contract system.

Each tool exposed to agents has a formal contract specifying:
- Input schema (typed params with defaults)
- Output schema (max_len, structure)
- Linter gates (pre-validation before execution)
- Empty feedback (explicit no-op response)
- Resource limits (timeout, max_output)
"""

import time
from dataclasses import dataclass, field, asdict
from typing import Any, Callable, Dict, List, Optional, Tuple
from enum import Enum
from itzraven.core.logger import get_logger

logger = get_logger()


class ParamType(Enum):
    STRING = "string"
    INTEGER = "integer"
    BOOLEAN = "boolean"
    LIST = "list"
    DICT = "dict"


@dataclass
class ParamSpec:
    name: str
    type: ParamType = ParamType.STRING
    description: str = ""
    required: bool = True
    default: Any = None
    max_length: int = 2000
    allowed_values: Optional[List[str]] = None

    def validate(self, value: Any) -> Optional[str]:
        if value is None and not self.required:
            return None
        if value is None and self.required:
            return f"{self.name}: required"
        if self.type == ParamType.INTEGER:
            if not isinstance(value, int):
                return f"{self.name}: expected int, got {type(value).__name__}"
        elif self.type == ParamType.LIST:
            if not isinstance(value, list):
                return f"{self.name}: expected list, got {type(value).__name__}"
        elif self.type == ParamType.STRING:
            if not isinstance(value, str):
                return f"{self.name}: expected string, got {type(value).__name__}"
            if len(value) > self.max_length:
                return f"{self.name}: exceeds max length {self.max_length}"
        if self.allowed_values and value not in self.allowed_values:
            return f"{self.name}: must be one of {self.allowed_values}"
        return None


@dataclass
class ToolContract:
    name: str
    description: str
    params: List[ParamSpec] = field(default_factory=list)
    max_output_length: int = 2000
    timeout_seconds: int = 60
    linter_gate: Optional[Callable[[Dict[str, Any]], Optional[str]]] = None
    empty_feedback: str = "Tool executed successfully with no output."

    def validate_input(self, params: Dict[str, Any]) -> Optional[str]:
        for p in self.params:
            err = p.validate(params.get(p.name))
            if err:
                return err
        if self.linter_gate:
            return self.linter_gate(params)
        return None

    def format_output(self, raw: Any) -> str:
        if raw is None or (isinstance(raw, (list, dict)) and len(raw) == 0):
            return self.empty_feedback
        text = str(raw)
        if len(text) > self.max_output_length:
            text = text[:self.max_output_length] + f"\n... (truncated {len(text) - self.max_output_length} chars)"
        return text


class ACIRegistry:
    _instance: Optional["ACIRegistry"] = None

    def __init__(self):
        self._contracts: Dict[str, ToolContract] = {}

    def register(self, contract: ToolContract):
        self._contracts[contract.name] = contract
        logger.debug(f"ACI: registered tool '{contract.name}'")

    def get(self, name: str) -> Optional[ToolContract]:
        return self._contracts.get(name)

    def list_tools(self) -> List[Dict[str, Any]]:
        return [{"name": c.name, "description": c.description, "params": [asdict(p) for p in c.params]} for c in self._contracts.values()]

    def validate(self, name: str, params: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        contract = self._contracts.get(name)
        if not contract:
            return False, f"Unknown tool: {name}"
        err = contract.validate_input(params)
        if err:
            return False, err
        return True, None

    def format(self, name: str, raw: Any) -> str:
        contract = self._contracts.get(name)
        if not contract:
            return str(raw)
        return contract.format_output(raw)

    @classmethod
    def get_instance(cls) -> "ACIRegistry":
        if cls._instance is None:
            cls._instance = ACIRegistry()
        return cls._instance


_aci_registry: Optional[ACIRegistry] = None


def get_aci_registry() -> ACIRegistry:
    global _aci_registry
    if _aci_registry is None:
        _aci_registry = ACIRegistry()
    return _aci_registry


# Default contracts for common security tools
DEFAULT_CONTRACTS = [
    ToolContract(
        name="http_request",
        description="Send HTTP request to target",
        params=[
            ParamSpec("method", ParamType.STRING, "HTTP method", default="GET", allowed_values=["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"]),
            ParamSpec("path", ParamType.STRING, "URL path", default="/", max_length=500),
            ParamSpec("headers", ParamType.DICT, "HTTP headers", required=False, default={}),
            ParamSpec("body", ParamType.STRING, "Request body", required=False, max_length=10000),
        ],
        max_output_length=2000,
        timeout_seconds=30,
        empty_feedback="HTTP request completed with empty response.",
    ),
    ToolContract(
        name="scan_endpoints",
        description="Discover endpoints on target using wordlist",
        params=[
            ParamSpec("wordlist_size", ParamType.INTEGER, "Number of paths to try", default=20),
        ],
        max_output_length=1500,
        timeout_seconds=60,
        empty_feedback="No new endpoints discovered.",
    ),
    ToolContract(
        name="test_sqli",
        description="Test for SQL injection on a parameter",
        params=[
            ParamSpec("url", ParamType.STRING, "Target URL", max_length=1000),
            ParamSpec("param", ParamType.STRING, "Parameter to test", default="id", max_length=100),
            ParamSpec("method", ParamType.STRING, "HTTP method", default="GET", allowed_values=["GET", "POST"]),
        ],
        max_output_length=3000,
        timeout_seconds=60,
    ),
    ToolContract(
        name="test_xss",
        description="Test for XSS on a parameter",
        params=[
            ParamSpec("url", ParamType.STRING, "Target URL", max_length=1000),
            ParamSpec("param", ParamType.STRING, "Parameter to test", default="q", max_length=100),
            ParamSpec("method", ParamType.STRING, "HTTP method", default="GET", allowed_values=["GET", "POST"]),
        ],
        max_output_length=3000,
        timeout_seconds=60,
    ),
    ToolContract(
        name="nuclei_scan",
        description="Run nuclei template against target",
        params=[
            ParamSpec("template_tags", ParamType.LIST, "Nuclei template tags", default=["cve"]),
            ParamSpec("url", ParamType.STRING, "Target URL", required=False, max_length=1000),
        ],
        max_output_length=3000,
        timeout_seconds=120,
        empty_feedback="Nuclei scan completed with no findings.",
    ),
    ToolContract(
        name="emit_finding",
        description="Record a confirmed security finding",
        params=[
            ParamSpec("title", ParamType.STRING, "Finding title", max_length=200),
            ParamSpec("severity", ParamType.STRING, "Severity level", allowed_values=["critical", "high", "medium", "low", "info"]),
            ParamSpec("description", ParamType.STRING, "Finding description", max_length=2000),
            ParamSpec("evidence", ParamType.STRING, "Evidence string", max_length=5000),
        ],
        max_output_length=500,
        timeout_seconds=5,
        empty_feedback="Finding recorded.",
    ),
    ToolContract(
        name="done",
        description="Mark current phase as complete",
        params=[
            ParamSpec("summary", ParamType.STRING, "Phase summary", max_length=1000),
        ],
        max_output_length=200,
        timeout_seconds=2,
    ),
]


def register_default_contracts():
    registry = get_aci_registry()
    for c in DEFAULT_CONTRACTS:
        registry.register(c)
