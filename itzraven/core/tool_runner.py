"""
Unified tool execution engine — inspired by hackingtool-plugin's ht_run.py.

Features:
- Docker image override map (25+ purpose-built images)
- Auto-backend selection (native/docker)
- Error classification & smart retry (sudo retry on permission denied)
- Capability flags (sudo, interactive, hw, long, gui)
- Structured JSON output with diagnostics
"""

import asyncio
import json
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from itzraven.core.logger import get_logger

logger = get_logger()

DEFAULT_TIMEOUT = 180
TOOLS_JSON = Path(__file__).resolve().parent.parent / "data" / "tools.json"

DOCKER_IMAGE_OVERRIDES: Dict[str, str] = {
    "osint_google_dork.GDorkEngine": "iamaworker135/gdork-engine",
    "information_gathering.NMAP": "instrumentisto/nmap",
    "information_gathering.Subfinder": "projectdiscovery/subfinder",
    "information_gathering.Httpx": "projectdiscovery/httpx",
    "information_gathering.Amass": "caffix/amass",
    "information_gathering.TheHarvester": "secsi/theharvester",
    "information_gathering.Holehe": "megadose/holehe",
    "information_gathering.Maigret": "soxoj/maigret",
    "information_gathering.Sherlock": "sherlock/sherlock",
    "information_gathering.SpiderFoot": "spiderfoot/spiderfoot",
    "information_gathering.TruffleHog": "trufflesecurity/trufflehog",
    "information_gathering.Gitleaks": "zricethezav/gitleaks",
    "information_gathering.Masscan": "ilyaglow/masscan",
    "information_gathering.RustScan": "rustscan/rustscan",
    "web_attack.Nuclei": "projectdiscovery/nuclei",
    "web_attack.Katana": "projectdiscovery/katana",
    "web_attack.Ffuf": "secsi/ffuf",
    "web_attack.Gobuster": "devopsworks/gobuster",
    "web_attack.Dirsearch": "loqutus/dirsearch",
    "web_attack.TestSSL": "drwetter/testssl.sh",
    "web_attack.Wafw00f": "0xsauby/wafw00f",
    "web_attack.Nikto": "frapsoft/nikto",
    "sql_injection.Sqlmap": "paoloo/sqlmap",
    "phishing_attack.Dnstwist": "elceef/dnstwist",
    "active_directory.Impacket": "rflathers/impacket",
    "active_directory.NetExec": "byt3bl33d3r/netexec",
    "active_directory.Certipy": "ly4k/certipy",
    "active_directory.BloodHound": "bloodhoundad/bloodhound",
    "active_directory.Kerbrute": "ropnop/kerbrute",
    "active_directory.Responder": "lgandx/responder",
    "post_exploitation.Chisel": "jpillora/chisel",
    "post_exploitation.EvilWinRM": "oscarakxv/evil-winrm",
    "post_exploitation.Havoc": "havocframework/havoc",
    "post_exploitation.PEASS": "peassng/peass",
    "cloud_security.Pacu": "rhinosecuritylabs/pacu",
    "cloud_security.Prowler": "prowlercloud/prowler",
    "cloud_security.ScoutSuite": "nccgroup/scoutsuite",
    "cloud_security.Trivy": "aquasecurity/trivy",
    "mobile_security.MobSF": "opensecurity/mobile-security-framework-mobsf",
    "mobile_security.Frida": "fridalabs/frida",
    "forensics.Binwalk": "cincan/binwalk",
    "forensics.Volatility": "volatilityfoundation/volatility",
    "reverse_engineering.Radare2": "radare/radare2",
    "wireless_attack.Bettercap": "bettercap/bettercap",
}

DEFAULT_DOCKER_IMAGE = "kalilinux/kali-rolling"

PERMISSION_PATTERNS = [
    re.compile(r"permission denied", re.I),
    re.compile(r"operation not permitted", re.I),
    re.compile(r"you need to be root", re.I),
    re.compile(r"requires root", re.I),
    re.compile(r"must be run as root", re.I),
    re.compile(r"EPERM"),
]
NOT_FOUND_PATTERNS = [
    re.compile(r"command not found", re.I),
    re.compile(r"not found.*PATH", re.I),
    re.compile(r"No such file or directory.*bin", re.I),
]
NO_DEVICE_PATTERNS = [
    re.compile(r"no such device", re.I),
    re.compile(r"no wireless", re.I),
    re.compile(r"no interfaces.*monitor mode", re.I),
]
STDIN_NEEDED_PATTERNS = [
    re.compile(r"input.*required", re.I),
    re.compile(r"EOFError"),
]


@dataclass
class ToolOutput:
    status: str
    tool_id: str = ""
    title: str = ""
    command: str = ""
    stdout: str = ""
    stderr: str = ""
    returncode: int = 0
    backend: str = "native"
    duration_ms: float = 0.0
    error_class: Optional[str] = None
    findings: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "tool_id": self.tool_id,
            "title": self.title,
            "command": self.command,
            "stdout": self.stdout[:1000] if self.stdout else "",
            "stderr": self.stderr[:500] if self.stderr else "",
            "returncode": self.returncode,
            "backend": self.backend,
            "duration_ms": round(self.duration_ms, 1),
            "findings_count": len(self.findings),
        }

    def is_success(self) -> bool:
        return self.status == "ok"


class ToolRunner:
    def __init__(self, timeout: int = DEFAULT_TIMEOUT, use_docker: bool = False):
        self.timeout = timeout
        self.use_docker = use_docker
        self._tools: Dict[str, dict] = {}

    def _load_tools(self) -> Dict[str, dict]:
        if self._tools:
            return self._tools
        if TOOLS_JSON.exists():
            try:
                with open(TOOLS_JSON) as f:
                    data = json.load(f)
                    self._tools = {t["id"]: t for t in data.get("tools", [])}
            except Exception as e:
                logger.warning(f"Failed to load tools.json: {e}")
        return self._tools

    def get_tool(self, tool_id: str) -> Optional[dict]:
        return self._load_tools().get(tool_id)

    def search_tools(self, query: str = "", category: str = "", tag: str = "") -> List[dict]:
        tools = list(self._load_tools().values())
        if query:
            q = query.lower()
            tools = [t for t in tools if q in t["title"].lower() or q in t.get("id", "").lower()]
        if category:
            tools = [t for t in tools if t.get("category") == category]
        if tag:
            tools = [t for t in tools if tag in t.get("tags", [])]
        return tools

    def list_categories(self) -> List[str]:
        return list({t.get("category", "other") for t in self._load_tools().values()})

    def get_workflows(self) -> Dict[str, List[str]]:
        if TOOLS_JSON.exists():
            try:
                with open(TOOLS_JSON) as f:
                    return json.load(f).get("workflows", {})
            except Exception:
                pass
        return {}

    async def execute(self, tool_id: str, args: str = "",
                      command: Optional[str] = None,
                      backend: str = "auto",
                      timeout: Optional[int] = None,
                      network_host: bool = False,
                      privileged: bool = False,
                      force: bool = False,
                      env: Optional[Dict[str, str]] = None) -> ToolOutput:
        tool = self.get_tool(tool_id)
        if not tool:
            return ToolOutput(status="error", tool_id=tool_id, stderr=f"Unknown tool: {tool_id}")

        caps = tool.get("capabilities", {})
        if caps.get("interactive") and not force:
            return ToolOutput(
                status="fallback", tool_id=tool_id, title=tool["title"],
                error_class="interactive",
                stderr="Tool is interactive (reads stdin). Use force=True or run manually.",
            )

        if command is None:
            run_cmds = tool.get("run_commands", [])
            if not run_cmds:
                return ToolOutput(
                    status="error", tool_id=tool_id, title=tool["title"],
                    stderr="No run commands defined for this tool",
                )
            command = run_cmds[0]
            if args:
                command = f"{command} {args}"

        resolved_backend = await self._pick_backend(backend, tool_id)
        timeout = timeout or self.timeout

        start = time.time()
        result = await self._execute_on_backend(command, tool_id, resolved_backend, timeout,
                                                 network_host, privileged, env)
        result.tool_id = tool_id
        result.title = tool["title"]
        result.command = command
        result.duration_ms = (time.time() - start) * 1000

        if result.status == "error":
            err_class = classify_error(result.stdout, result.stderr, result.returncode)
            result.error_class = err_class
            if err_class == "permission_denied" and resolved_backend in ("native",):
                sudo_result = await self._retry_sudo(command, tool_id, timeout, env)
                if sudo_result.status == "ok":
                    sudo_result.tool_id = tool_id
                    sudo_result.title = tool["title"]
                    sudo_result.command = command
                    sudo_result.duration_ms = (time.time() - start) * 1000
                    return sudo_result

        result.findings = self._parse_findings(result, tool)
        return result

    async def _pick_backend(self, preferred: str, tool_id: str) -> str:
        if preferred != "auto":
            return preferred
        if self.use_docker or tool_id in DOCKER_IMAGE_OVERRIDES:
            if await self._docker_ready():
                return "docker"
        return "native"

    async def _docker_ready(self) -> bool:
        try:
            r = await asyncio.create_subprocess_exec(
                "docker", "info", "--format", "{{.ServerVersion}}",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(r.communicate(), timeout=5)
            return r.returncode == 0
        except Exception:
            return False

    async def _execute_on_backend(self, command: str, tool_id: str, backend: str,
                                   timeout: int, network_host: bool, privileged: bool,
                                   env: Optional[Dict[str, str]]) -> ToolOutput:
        if backend == "docker":
            return await self._run_docker(command, tool_id, timeout, network_host, privileged, env)
        return await self._run_native(command, timeout, env)

    async def _run_native(self, command: str, timeout: int,
                          env: Optional[Dict[str, str]]) -> ToolOutput:
        try:
            proc = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env={**os.environ, **(env or {})},
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            out = stdout.decode("utf-8", errors="replace")
            err = stderr.decode("utf-8", errors="replace")
            status = "ok" if proc.returncode == 0 else "error"
            return ToolOutput(status=status, stdout=out, stderr=err,
                              returncode=proc.returncode or 0, backend="native")
        except asyncio.TimeoutError:
            return ToolOutput(status="timeout", backend="native",
                              stderr=f"Timed out after {timeout}s")
        except FileNotFoundError as e:
            return ToolOutput(status="error", backend="native",
                              stderr=f"Command not found: {e}")

    async def _run_docker(self, command: str, tool_id: str, timeout: int,
                          network_host: bool, privileged: bool,
                          env: Optional[Dict[str, str]]) -> ToolOutput:
        image = DOCKER_IMAGE_OVERRIDES.get(tool_id, DEFAULT_DOCKER_IMAGE)
        cwd = os.getcwd()
        argv = ["docker", "run", "--rm"]
        if network_host:
            argv += ["--network", "host"]
        if privileged:
            argv += ["--privileged"]
        argv += ["-v", f"{cwd}:/work", "-w", "/work"]

        if env:
            for k, v in env.items():
                argv += ["-e", f"{k}={v}"]

        needs_entrypoint = tool_id in DOCKER_IMAGE_OVERRIDES
        if needs_entrypoint:
            image_binary = image.split("/")[-1].split(":")[0]
            tokens = command.split()
            if tokens and tokens[0] == image_binary:
                tokens = tokens[1:]
            argv += [image] + tokens
        else:
            argv += [image, "bash", "-lc", command]

        try:
            proc = await asyncio.create_subprocess_exec(
                *argv,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            out = stdout.decode("utf-8", errors="replace")
            err = stderr.decode("utf-8", errors="replace")
            status = "ok" if proc.returncode == 0 else "error"
            return ToolOutput(status=status, stdout=out, stderr=err,
                              returncode=proc.returncode or 0, backend="docker")
        except asyncio.TimeoutError:
            return ToolOutput(status="timeout", backend="docker",
                              stderr=f"Timed out after {timeout}s")

    async def _retry_sudo(self, command: str, tool_id: str, timeout: int,
                          env: Optional[Dict[str, str]]) -> ToolOutput:
        sudo_cmd = f"sudo -n {command}"
        proc = await asyncio.create_subprocess_shell(
            sudo_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env={**os.environ, **(env or {})},
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            out = stdout.decode("utf-8", errors="replace")
            err = stderr.decode("utf-8", errors="replace")
            if proc.returncode == 0:
                return ToolOutput(status="ok", stdout=out, stderr=err,
                                  returncode=0, backend="native")
            return ToolOutput(status="error", stdout=out, stderr=err,
                              returncode=proc.returncode or 0, backend="native")
        except asyncio.TimeoutError:
            return ToolOutput(status="timeout", backend="native",
                              stderr=f"Sudo retry timed out after {timeout}s")

    def _parse_findings(self, result: ToolOutput, tool: dict) -> List[Dict[str, Any]]:
        if result.status != "ok":
            return []
        findings = []
        tid = tool.get("id", "")
        category = tool.get("category", "general")
        if "nmap" in tid.lower() and result.stdout:
            findings = self._parse_nmap_output(result.stdout, category)
        elif "nuclei" in tid.lower() and result.stdout:
            findings = self._parse_nuclei_output(result.stdout, category)
        elif "subfinder" in tid.lower() and result.stdout:
            findings = self._parse_subfinder_output(result.stdout, category)
        elif "httpx" in tid.lower() and result.stdout:
            findings = self._parse_httpx_output(result.stdout, category)
        return findings

    def _parse_nmap_output(self, stdout: str, category: str) -> List[Dict]:
        findings = []
        for line in stdout.splitlines():
            m = re.search(r'(\d+)/tcp\s+(open|filtered)\s+(\S+)', line)
            if m:
                findings.append({
                    "type": "open_port", "port": int(m.group(1)),
                    "state": m.group(2), "service": m.group(3),
                    "category": category,
                })
        return findings

    def _parse_nuclei_output(self, stdout: str, category: str) -> List[Dict]:
        findings = []
        for line in stdout.splitlines():
            try:
                item = json.loads(line)
                findings.append({
                    "type": "vulnerability",
                    "template": item.get("template-id", ""),
                    "name": item.get("info", {}).get("name", ""),
                    "severity": item.get("info", {}).get("severity", ""),
                    "matched": item.get("matched-at", ""),
                    "category": category,
                })
            except (json.JSONDecodeError, AttributeError):
                pass
        return findings

    def _parse_subfinder_output(self, stdout: str, category: str) -> List[Dict]:
        return [{"type": "subdomain", "host": line.strip(), "category": category}
                for line in stdout.splitlines() if line.strip()]

    def _parse_httpx_output(self, stdout: str, category: str) -> List[Dict]:
        findings = []
        for line in stdout.splitlines():
            parts = line.strip().split()
            if parts:
                findings.append({
                    "type": "http_endpoint", "url": parts[0],
                    "status_code": parts[1] if len(parts) > 1 else "",
                    "category": category,
                })
        return findings


def classify_error(stdout: str, stderr: str, returncode: int) -> Optional[str]:
    blob = f"{stdout}\n{stderr}"
    if any(p.search(blob) for p in NOT_FOUND_PATTERNS):
        return "not_installed"
    if any(p.search(blob) for p in NO_DEVICE_PATTERNS):
        return "no_device"
    if any(p.search(blob) for p in PERMISSION_PATTERNS):
        return "permission_denied"
    if any(p.search(blob) for p in STDIN_NEEDED_PATTERNS):
        return "stdin_needed"
    return None


def get_tool_runner() -> ToolRunner:
    return ToolRunner()
