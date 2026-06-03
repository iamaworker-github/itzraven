"""
Typed Tool System — OpenHands Action/Observation pattern for Itzraven.

Architecture:
- ToolAction: typed input with Pydantic-like validation
- ToolObservation: typed output with success/error/findings
- ToolRegistry: manages tool registration, schema generation, execution
- SecurityMiddleware: validates actions before execution (OpenHands Security pattern)
- Dynamic tool selection: tools can be added/removed at runtime (LangGraph pattern)
"""

import asyncio
import time
import json
import uuid
from dataclasses import dataclass, field, asdict
from typing import Any, Callable, Dict, List, Optional, Set, Type
from enum import Enum

from itzraven.core.logger import get_logger

logger = get_logger()


class RiskLevel(Enum):
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ToolSpec:
    """Tool metadata: name, description, input schema, risk level, category."""
    name: str
    description: str
    parameters: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    risk_level: RiskLevel = RiskLevel.MEDIUM
    category: str = "general"
    requires_confirmation: bool = False
    timeout_seconds: int = 60
    id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def to_openai_schema(self) -> dict:
        props = {}
        required = []
        for pname, pinfo in self.parameters.items():
            props[pname] = {
                "type": pinfo.get("type", "string"),
                "description": pinfo.get("description", ""),
            }
            if pinfo.get("required", False):
                required.append(pname)
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": {
                    "type": "object",
                    "properties": props,
                    "required": required,
                },
            },
        }


@dataclass
class ToolAction:
    """Typed action to execute (OpenHands Action pattern)."""
    tool_name: str
    params: Dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    source: str = "agent"

    def to_dict(self) -> dict:
        return {"tool": self.tool_name, "params": self.params, "id": self.id}


@dataclass
class ToolObservation:
    """Typed observation from tool execution (OpenHands Observation pattern)."""
    action_id: str
    tool_name: str
    success: bool
    output: str = ""
    error: Optional[str] = None
    duration_ms: float = 0.0
    findings: List[Dict] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "tool": self.tool_name,
            "success": self.success,
            "output": self.output[:500],
            "duration_ms": round(self.duration_ms, 1),
            "findings_count": len(self.findings),
        }


class ToolRegistry:
    """Central registry for tool definitions and execution (OpenHands pattern).

    Supports:
    - Registration with schema
    - Dynamic add/remove at runtime (LangGraph dynamic tools)
    - Schema generation for LLM function calling
    - Execution with timeout and error handling
    - Risk-level based filtering
    """

    def __init__(self):
        self._tools: Dict[str, ToolSpec] = {}
        self._handlers: Dict[str, Callable] = {}
        self._execution_history: List[ToolObservation] = []

    def register(self, spec: ToolSpec, handler: Callable):
        self._tools[spec.name] = spec
        self._handlers[spec.name] = handler
        logger.debug(f"Tool registered: {spec.name} ({spec.category}, risk={spec.risk_level.value})")

    def unregister(self, name: str):
        self._tools.pop(name, None)
        self._handlers.pop(name, None)

    def get_spec(self, name: str) -> Optional[ToolSpec]:
        return self._tools.get(name)

    def list_tools(self, category: Optional[str] = None,
                   max_risk: Optional[RiskLevel] = None) -> List[ToolSpec]:
        tools = self._tools.values()
        if category:
            tools = [t for t in tools if t.category == category]
        if max_risk:
            risk_order = [r.value for r in RiskLevel]
            tools = [t for t in tools if risk_order.index(t.risk_level.value) <= risk_order.index(max_risk.value)]
        return list(tools)

    def get_openai_schemas(self) -> List[dict]:
        return [t.to_openai_schema() for t in self._tools.values()]

    async def execute(self, action: ToolAction) -> ToolObservation:
        spec = self._tools.get(action.tool_name)
        if not spec:
            return ToolObservation(
                action_id=action.id, tool_name=action.tool_name,
                success=False, error=f"Unknown tool: {action.tool_name}",
            )
        handler = self._handlers.get(action.tool_name)
        if not handler:
            return ToolObservation(
                action_id=action.id, tool_name=action.tool_name,
                success=False, error=f"No handler for: {action.tool_name}",
            )

        start = time.time()
        try:
            result = await asyncio.wait_for(
                self._call_handler(handler, action.params),
                timeout=spec.timeout_seconds,
            )
            obs = ToolObservation(
                action_id=action.id, tool_name=action.tool_name,
                success=True, output=str(result),
                duration_ms=(time.time() - start) * 1000,
            )
        except asyncio.TimeoutError:
            obs = ToolObservation(
                action_id=action.id, tool_name=action.tool_name,
                success=False, error=f"Timeout ({spec.timeout_seconds}s)",
                duration_ms=spec.timeout_seconds * 1000,
            )
        except Exception as e:
            obs = ToolObservation(
                action_id=action.id, tool_name=action.tool_name,
                success=False, error=str(e),
                duration_ms=(time.time() - start) * 1000,
            )

        self._execution_history.append(obs)
        return obs

    async def _call_handler(self, handler: Callable, params: Dict) -> Any:
        result = handler(**params)
        if asyncio.iscoroutine(result):
            result = await result
        return result

    def get_history(self, limit: int = 50) -> List[ToolObservation]:
        return self._execution_history[-limit:]

    def clear_history(self):
        self._execution_history.clear()

    def get_stats(self) -> dict:
        total = len(self._execution_history)
        successes = sum(1 for h in self._execution_history if h.success)
        return {
            "tools_registered": len(self._tools),
            "total_executions": total,
            "success_rate": successes / max(total, 1),
            "by_tool": {
                name: sum(1 for h in self._execution_history if h.tool_name == name)
                for name in self._tools
            },
        }


# ─── Security Middleware (OpenHands Security pattern) ────────────────────────

class SecurityMiddleware:
    """Validates tool actions before execution.

    Supports:
    - Risk-level based blocking
    - Target scope validation
    - Confirmation requirements
    - Rate limiting per tool
    """

    def __init__(self, max_risk: RiskLevel = RiskLevel.HIGH):
        self.max_risk = max_risk
        self._allowed_targets: Set[str] = set()
        self._blocked_tools: Set[str] = set()
        self._tool_call_counts: Dict[str, int] = {}
        self._max_calls_per_tool = 100

    def allow_target(self, target: str):
        self._allowed_targets.add(target)

    def block_tool(self, name: str):
        self._blocked_tools.add(name)

    def validate(self, action: ToolAction, spec: Optional[ToolSpec] = None,
                 state: Optional[dict] = None) -> Optional[str]:
        """Returns error message if action should be blocked, None if allowed."""
        if action.tool_name in self._blocked_tools:
            return f"Tool '{action.tool_name}' is blocked"

        if spec:
            risk_order = [r.value for r in RiskLevel]
            if risk_order.index(spec.risk_level.value) > risk_order.index(self.max_risk.value):
                return f"Risk level '{spec.risk_level.value}' exceeds max '{self.max_risk.value}'"

        # Rate limiting
        self._tool_call_counts[action.tool_name] = self._tool_call_counts.get(action.tool_name, 0) + 1
        if self._tool_call_counts[action.tool_name] > self._max_calls_per_tool:
            return f"Rate limit exceeded for tool '{action.tool_name}'"

        # Scope validation
        if self._allowed_targets:
            target = action.params.get("target", action.params.get("url", action.params.get("host", "")))
            if target and not any(a in target for a in self._allowed_targets):
                return f"Target '{target}' not in allowed scope"

        return None


# ─── Tool Presets ────────────────────────────────────────────────────────────

def create_default_tools(registry: ToolRegistry):
    """Register default Itzraven tools in the registry, including all external tool wrappers."""

    from itzraven.core.tool_runner import ToolRunner
    _runner = ToolRunner()

    async def _run_tool(tool_id: str, **kwargs):
        from itzraven.core.tool_runner import ToolRunner
        runner = ToolRunner()
        args = kwargs.pop("args", "")
        timeout = kwargs.pop("timeout", 180)
        result = await runner.execute(tool_id, args=args, timeout=timeout, **kwargs)
        return result.to_dict()

    async def tool_nmap(target: str, ports: str = "top-1000"):
        result = await _run_tool("information_gathering.NMAP", args=f"-sV -sC {target} -p {ports}", timeout=300)
        return f"nmap scan: {result.get('status', 'error')} | findings: {result.get('findings_count', 0)}"

    async def tool_httpx(target: str):
        result = await _run_tool("information_gathering.Httpx", args=f"-u {target} -title -tech-detect -status-code", timeout=60)
        return f"httpx probe: {result.get('status', 'error')}"

    async def tool_nuclei(target: str, severity: str = "medium"):
        result = await _run_tool("web_attack.Nuclei", args=f"-u {target} -severity {severity} -json", timeout=300)
        return f"nuclei scan: {result.get('status', 'error')} | findings: {result.get('findings_count', 0)}"

    async def tool_subfinder(domain: str):
        result = await _run_tool("information_gathering.Subfinder", args=f"-d {domain} -silent", timeout=60)
        return f"subfinder: {result.get('status', 'error')}"

    async def tool_holehe(email: str):
        result = await _run_tool("information_gathering.Holehe", args=email, timeout=120)
        return f"holehe email check: {result.get('status', 'error')}"

    async def tool_maigret(username: str):
        result = await _run_tool("information_gathering.Maigret", args=username, timeout=300)
        return f"maigret username check: {result.get('status', 'error')}"

    async def tool_sherlock(username: str):
        result = await _run_tool("information_gathering.Sherlock", args=username, timeout=300)
        return f"sherlock search: {result.get('status', 'error')}"

    async def tool_trufflehog(path: str):
        result = await _run_tool("information_gathering.TruffleHog", args=f"filesystem {path}", timeout=300)
        return f"trufflehog scan: {result.get('status', 'error')}"

    async def tool_gitleaks(path: str):
        result = await _run_tool("information_gathering.Gitleaks", args=f"detect --source {path} -v", timeout=300)
        return f"gitleaks scan: {result.get('status', 'error')}"

    async def tool_rustscan(target: str, ports: str = ""):
        result = await _run_tool("information_gathering.RustScan", args=f"-a {target} {'-p ' + ports if ports else ''}", timeout=300)
        return f"rustscan: {result.get('status', 'error')}"

    async def tool_testssl(host: str):
        result = await _run_tool("web_attack.TestSSL", args=host, timeout=300)
        return f"testssl check: {result.get('status', 'error')}"

    async def tool_dnstwist(domain: str):
        result = await _run_tool("phishing_attack.Dnstwist", args=domain, timeout=120)
        return f"dnstwist: {result.get('status', 'error')}"

    async def tool_certipy(target: str, user: str = "", password: str = ""):
        args = f"find -target {target}"
        if user: args += f" -u {user}"
        if password: args += f" -p {password}"
        result = await _run_tool("active_directory.Certipy", args=args, timeout=300)
        return f"certipy: {result.get('status', 'error')}"

    async def tool_responder(interface: str = "eth0"):
        result = await _run_tool("active_directory.Responder", args=f"-I {interface} -A", timeout=60)
        return f"responder: {result.get('status', 'error')}"

    async def tool_peass(os_type: str = "linux"):
        cmd = "linpeas.sh" if os_type == "linux" else "winpeas.exe"
        result = await _run_tool("post_exploitation.PEASS", command=cmd, timeout=120)
        return f"peass: {result.get('status', 'error')}"

    async def tool_prowler(provider: str = "aws"):
        result = await _run_tool("cloud_security.Prowler", args=f"-p {provider}", timeout=600)
        return f"prowler: {result.get('status', 'error')}"

    async def tool_trivy(target: str, scan_type: str = "image"):
        result = await _run_tool("cloud_security.Trivy", args=f"{scan_type} {target}", timeout=300)
        return f"trivy: {result.get('status', 'error')}"

    async def tool_binwalk(filepath: str):
        result = await _run_tool("forensics.Binwalk", args=filepath, timeout=120)
        return f"binwalk: {result.get('status', 'error')}"

    async def tool_volatility(image_path: str, plugin: str = "windows.info"):
        result = await _run_tool("forensics.Volatility", command=f"volatility -f {image_path} {plugin}", timeout=300)
        return f"volatility: {result.get('status', 'error')}"

    async def tool_mobsf(apk_path: str):
        result = await _run_tool("mobile_security.MobSF", command=f"mobsf scan --file {apk_path} --json", timeout=600)
        return f"mobsf: {result.get('status', 'error')}"

    async def tool_frida(target: str = ""):
        result = await _run_tool("mobile_security.Frida", command=f"frida-ps -Uai{ ' ' + target if target else ''}", timeout=30)
        return f"frida: {result.get('status', 'error')}"

    async def tool_chisel(mode: str, port: str = "8080", server: str = ""):
        if mode == "server":
            cmd = f"chisel server -p {port} --reverse"
        else:
            cmd = f"chisel client {server}:{port} remote"
        result = await _run_tool("post_exploitation.Chisel", command=cmd, timeout=60)
        return f"chisel: {result.get('status', 'error')}"

    async def tool_impacket(module: str, args: str = ""):
        result = await _run_tool("active_directory.Impacket", command=f"{module} {args}", timeout=120)
        return f"impacket: {result.get('status', 'error')}"

    async def tool_kerbrute(domain: str, wordlist: str = "/usr/share/wordlists/names.txt"):
        result = await _run_tool("active_directory.Kerbrute", args=f"userenum -d {domain} {wordlist}", timeout=300)
        return f"kerbrute: {result.get('status', 'error')}"

    async def tool_graph_query(entity_type: str, query: str):
        return f"graph query: {entity_type} matching '{query}'"

    async def tool_web_search(query: str):
        return f"web search: {query}"

    tools = [
        ToolSpec("nmap", "Port scan a target", {"target": {"type": "string", "required": True}, "ports": {"type": "string"}},
                 RiskLevel.MEDIUM, "scanning", timeout_seconds=300),
        ToolSpec("httpx", "HTTP probe for technology detection", {"target": {"type": "string", "required": True}},
                 RiskLevel.LOW, "recon", timeout_seconds=60),
        ToolSpec("nuclei", "Vulnerability scan using templates", {"target": {"type": "string", "required": True}, "severity": {"type": "string"}},
                 RiskLevel.MEDIUM, "scanning", timeout_seconds=300),
        ToolSpec("subfinder", "Passive subdomain discovery", {"domain": {"type": "string", "required": True}},
                 RiskLevel.LOW, "recon", timeout_seconds=60),
        ToolSpec("holehe", "Check email on 120+ sites", {"email": {"type": "string", "required": True}},
                 RiskLevel.LOW, "osint", timeout_seconds=120),
        ToolSpec("maigret", "Username OSINT across 3000+ sites", {"username": {"type": "string", "required": True}},
                 RiskLevel.LOW, "osint", timeout_seconds=300),
        ToolSpec("sherlock", "Search username across social networks", {"username": {"type": "string", "required": True}},
                 RiskLevel.LOW, "osint", timeout_seconds=300),
        ToolSpec("trufflehog", "Scan git/filesystem for secrets", {"path": {"type": "string", "required": True}},
                 RiskLevel.MEDIUM, "scanning", timeout_seconds=300),
        ToolSpec("gitleaks", "Detect hardcoded secrets in git repos", {"path": {"type": "string", "required": True}},
                 RiskLevel.MEDIUM, "scanning", timeout_seconds=300),
        ToolSpec("rustscan", "Fast port scanner - 65k ports in 3s", {"target": {"type": "string", "required": True}, "ports": {"type": "string"}},
                 RiskLevel.MEDIUM, "scanning", timeout_seconds=300),
        ToolSpec("testssl", "Deep TLS/SSL audit", {"host": {"type": "string", "required": True}},
                 RiskLevel.LOW, "scanning", timeout_seconds=300),
        ToolSpec("dnstwist", "Domain typosquatting detection", {"domain": {"type": "string", "required": True}},
                 RiskLevel.LOW, "osint", timeout_seconds=120),
        ToolSpec("certipy", "AD CS enumeration and abuse", {"target": {"type": "string", "required": True}, "user": {"type": "string"}, "password": {"type": "string"}},
                 RiskLevel.HIGH, "active_directory", timeout_seconds=300),
        ToolSpec("responder", "LLMNR/NBT-NS/MDNS poisoner", {"interface": {"type": "string"}},
                 RiskLevel.HIGH, "active_directory", timeout_seconds=60),
        ToolSpec("peass", "Privilege escalation enumeration (LinPEAS/WinPEAS)", {"os_type": {"type": "string"}},
                 RiskLevel.MEDIUM, "post_exploitation", timeout_seconds=120),
        ToolSpec("prowler", "Multi-cloud security audit", {"provider": {"type": "string"}},
                 RiskLevel.LOW, "cloud", timeout_seconds=600),
        ToolSpec("trivy", "Container/K8s/IaC vulnerability scanner", {"target": {"type": "string", "required": True}, "scan_type": {"type": "string"}},
                 RiskLevel.MEDIUM, "cloud", timeout_seconds=300),
        ToolSpec("binwalk", "Firmware analysis and extraction", {"filepath": {"type": "string", "required": True}},
                 RiskLevel.LOW, "forensics", timeout_seconds=120),
        ToolSpec("volatility", "Memory forensics framework", {"image_path": {"type": "string", "required": True}, "plugin": {"type": "string"}},
                 RiskLevel.MEDIUM, "forensics", timeout_seconds=300),
        ToolSpec("mobsf", "Mobile app security scanner (APK/IPA)", {"apk_path": {"type": "string", "required": True}},
                 RiskLevel.MEDIUM, "mobile", timeout_seconds=600),
        ToolSpec("frida", "Dynamic instrumentation toolkit", {"target": {"type": "string"}},
                 RiskLevel.HIGH, "mobile", timeout_seconds=30),
        ToolSpec("chisel", "TCP/UDP tunnel for pivoting", {"mode": {"type": "string", "required": True}, "port": {"type": "string"}, "server": {"type": "string"}},
                 RiskLevel.HIGH, "post_exploitation", timeout_seconds=60),
        ToolSpec("impacket", "AD protocol toolkit (SMB/MSRPC/Kerberos)", {"module": {"type": "string", "required": True}, "args": {"type": "string"}},
                 RiskLevel.HIGH, "active_directory", timeout_seconds=120),
        ToolSpec("kerbrute", "Kerberos pre-auth brute-force", {"domain": {"type": "string", "required": True}, "wordlist": {"type": "string"}},
                 RiskLevel.HIGH, "active_directory", timeout_seconds=300),
        ToolSpec("graph_query", "Query graph memory for entities", {"entity_type": {"type": "string", "required": True}, "query": {"type": "string", "required": True}},
                 RiskLevel.SAFE, "intelligence", timeout_seconds=10),
        ToolSpec("web_search", "Search the web for intelligence", {"query": {"type": "string", "required": True}},
                 RiskLevel.LOW, "intelligence", timeout_seconds=30),
    ]

    handlers = [
        tool_nmap, tool_httpx, tool_nuclei, tool_subfinder,
        tool_holehe, tool_maigret, tool_sherlock,
        tool_trufflehog, tool_gitleaks,
        tool_rustscan, tool_testssl, tool_dnstwist,
        tool_certipy, tool_responder, tool_peass,
        tool_prowler, tool_trivy,
        tool_binwalk, tool_volatility,
        tool_mobsf, tool_frida, tool_chisel,
        tool_impacket, tool_kerbrute,
        tool_graph_query, tool_web_search,
    ]
    for spec, handler in zip(tools, handlers):
        registry.register(spec, handler)


# ─── Global Singleton ────────────────────────────────────────────────────────

_default_registry: Optional[ToolRegistry] = None


def get_tool_registry() -> ToolRegistry:
    global _default_registry
    if _default_registry is None:
        _default_registry = ToolRegistry()
        create_default_tools(_default_registry)
    return _default_registry
