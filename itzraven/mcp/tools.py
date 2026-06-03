"""
MCP Tool implementations for Itzraven.
"""

import asyncio
import json
import uuid
from typing import Any, Dict, List, Optional
from datetime import datetime

from itzraven.core.logger import get_logger

logger = get_logger()

# In-memory scan registry
_active_scans: Dict[str, dict] = {}


async def run_scan(target: str, mode: str = "auto", depth: str = "deep") -> dict:
    scan_id = str(uuid.uuid4())[:8]
    _active_scans[scan_id] = {
        "scan_id": scan_id,
        "target": target,
        "mode": mode,
        "depth": depth,
        "status": "running",
        "started_at": datetime.now().isoformat(),
    }
    logger.info(f"MCP: Scan started {scan_id} -> {target} ({mode}, {depth})")
    return {"scan_id": scan_id, "status": "started", "target": target, "mode": mode, "depth": depth}


async def get_status(scan_id: str) -> dict:
    scan = _active_scans.get(scan_id)
    if not scan:
        return {"error": f"Scan {scan_id} not found"}
    return {"scan_id": scan_id, "status": scan.get("status", "unknown"), "progress": scan.get("progress", 0)}


async def list_findings(scan_id: str) -> dict:
    scan = _active_scans.get(scan_id, {})
    findings = scan.get("findings", [])
    return {"scan_id": scan_id, "findings_count": len(findings), "findings": findings}


async def list_tools() -> dict:
    return {
        "tools": [
            {"name": "nmap", "category": "port_scanner", "description": "Network discovery and port scanning"},
            {"name": "naabu", "category": "port_scanner", "description": "Fast port scanner"},
            {"name": "nuclei", "category": "vuln_scanner", "description": "Fast vulnerability scanner"},
            {"name": "httpx", "category": "http", "description": "HTTP probe and tech detection"},
            {"name": "sqlmap", "category": "vuln_scanner", "description": "SQL injection automation"},
            {"name": "ffuf", "category": "fuzzer", "description": "Web fuzzer"},
            {"name": "subfinder", "category": "recon", "description": "Subdomain discovery"},
            {"name": "gau", "category": "recon", "description": "URL gathering"},
            {"name": "katana", "category": "crawler", "description": "Web crawler"},
            {"name": "kubescape", "category": "kubernetes", "description": "K8s security scanner"},
            {"name": "wpscan", "category": "cms", "description": "WordPress scanner"},
            {"name": "impacket", "category": "ad", "description": "AD toolkit"},
            {"name": "bloodhound", "category": "ad", "description": "AD enumeration"},
            {"name": "hydra", "category": "auth", "description": "Login brute-forcer"},
        ]
    }


async def get_attack_surface(scan_id: str) -> dict:
    scan = _active_scans.get(scan_id, {})
    return {
        "scan_id": scan_id,
        "target": scan.get("target", "unknown"),
        "open_ports": scan.get("open_ports", []),
        "technologies": scan.get("technologies", []),
        "endpoints": scan.get("endpoints", []),
    }


async def medusa_scan(target: str, git_mode: bool = False) -> dict:
    try:
        from itzraven.toolkit.medusa_integration import MedusaIntegration
        if git_mode:
            result = MedusaIntegration.scan_git_repo(target)
        else:
            result = MedusaIntegration.scan_path(target)
        return {
            "status": "completed",
            "total_issues": result.total_issues,
            "files_scanned": result.files_scanned,
            "security_score": result.security_score,
            "risk_level": result.risk_level,
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


async def bounty_search_programs(platform: str, query: str = "") -> dict:
    return {"platform": platform, "results": [], "message": f"Search on {platform} for '{query}'"}


async def bounty_get_program(platform: str, name: str) -> dict:
    return {"platform": platform, "name": name, "details": {}}


async def bounty_triage_finding(finding_dict: dict) -> dict:
    severity = finding_dict.get("severity", "medium")
    has_poc = bool(finding_dict.get("proof_of_concept"))
    score = 9.0 if severity == "critical" else 7.0 if severity == "high" else 4.0 if severity == "medium" else 1.0
    return {"bounty_ready": has_poc and severity in ("critical", "high"), "priority_score": score}


async def bounty_find_programs(target: str) -> dict:
    return {"target": target, "programs": []}


async def bounty_submit_report(platform: str, report_data: dict) -> dict:
    return {"platform": platform, "status": "drafted", "report_id": str(uuid.uuid4())[:8]}


# ========================================================================
# NEW: Health & Diagnostics Tools
# ========================================================================


async def health_check() -> dict:
    """Full system health check — Docker, tools, memory, disk."""
    checks = {
        "docker": await _check_docker(),
        "tools": await _check_tools_available(),
        "memory": _check_memory(),
    }
    all_ok = all(c.get("ok", False) for c in checks.values())
    return {"status": "healthy" if all_ok else "degraded", "checks": checks}


async def check_tool(tool_name: str) -> dict:
    """Check if a specific tool is installed and available."""
    available = await _is_tool_available(tool_name)
    return {"tool": tool_name, "available": available, "status": "ok" if available else "missing"}


async def diagnose() -> dict:
    """Comprehensive diagnostics — system info, tool versions, resource usage."""
    import os
    diag = {
        "system": {
            "hostname": os.uname().nodename,
            "platform": os.uname().sysname,
            "release": os.uname().release,
        },
        "tools": {},
        "resources": {
            "cpu_count": os.cpu_count(),
        },
    }
    key_tools = ["nuclei", "nmap", "naabu", "httpx", "sqlmap", "ffuf", "kubescape", "subfinder", "gau"]
    for tool in key_tools:
        diag["tools"][tool] = await _is_tool_available(tool)
    return diag


async def list_allowed_tools() -> dict:
    """List all tools available in the toolbox, organized by category."""
    categories = {
        "port_scanners": ["nmap", "naabu", "masscan", "rustscan"],
        "web": ["nuclei", "httpx", "ffuf", "gobuster", "dirsearch", "nikto", "wafw00f", "sqlmap"],
        "recon": ["subfinder", "amass", "gau", "katana", "waybackurls", "theHarvester"],
        "dns": ["dig", "nslookup", "dnsrecon", "dnsenum"],
        "cms": ["wpscan", "cmseek", "whatweb", "droopescan"],
        "network": ["hydra", "nc", "curl", "wget", "socat"],
        "ad": ["impacket", "bloodhound", "kerbrute", "netexec", "responder", "certipy"],
        "cloud": ["prowler", "scoutsuite", "trivy", "kubescape"],
        "mobile": ["mobsf", "apktool", "jadx"],
    }
    available = {}
    for cat, tools in categories.items():
        available[cat] = []
        for t in tools:
            available[cat].append({"name": t, "available": await _is_tool_available(t)})
    return {"categories": available}


async def _check_docker() -> dict:
    try:
        proc = await asyncio.create_subprocess_exec(
            "docker", "info", "--format", "{{.ServerVersion}}",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
        version = stdout.decode().strip()
        return {"ok": proc.returncode == 0, "version": version}
    except Exception as e:
        return {"ok": False, "error": str(e)}


async def _check_tools_available() -> dict:
    tools = ["nuclei", "nmap", "naabu", "httpx", "ffuf", "sqlmap"]
    results = {}
    for tool in tools:
        results[tool] = await _is_tool_available(tool)
    return {"ok": any(results.values()), "tools": results}


def _check_memory() -> dict:
    try:
        import psutil
        mem = psutil.virtual_memory()
        return {"ok": mem.available > 500 * 1024 * 1024, "available_gb": round(mem.available / (1024**3), 2)}
    except Exception:
        return {"ok": True, "available_gb": "unknown (psutil not installed)"}


async def _is_tool_available(tool: str) -> bool:
    try:
        proc = await asyncio.create_subprocess_exec(
            "which", tool,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        await asyncio.wait_for(proc.communicate(), timeout=5)
        return proc.returncode == 0
    except Exception:
        return False


# ========================================================================
# Writeup Search Tools
# ========================================================================


async def writeup_search(query: str, technique: str = "", k: int = 5) -> dict:
    try:
        from itzraven.mcp.writeup_search import get_writeup_server
        server = get_writeup_server()
        return await server.search_writeups(query, technique, k)
    except Exception as e:
        return {"error": str(e), "results": [], "fallback": True}


async def writeup_get(writeup_id: str) -> dict:
    try:
        from itzraven.mcp.writeup_search import get_writeup_server
        server = get_writeup_server()
        return await server.get_writeup(writeup_id)
    except Exception as e:
        return {"error": str(e)}


async def writeup_techniques(vuln_class: str) -> dict:
    try:
        from itzraven.mcp.writeup_search import get_writeup_server
        server = get_writeup_server()
        return await server.search_techniques(vuln_class)
    except Exception as e:
        return {"error": str(e)}


async def writeup_payloads(vuln_class: str) -> dict:
    try:
        from itzraven.mcp.writeup_search import get_writeup_server
        server = get_writeup_server()
        return await server.search_payloads(vuln_class)
    except Exception as e:
        return {"error": str(e)}


async def writeup_ingest(source: str, title: str, description: str, technique: str, severity: str, content: str) -> dict:
    try:
        from itzraven.mcp.writeup_search import get_writeup_server
        server = get_writeup_server()
        return await server.ingest_writeup(source, title, description, technique, severity, content)
    except Exception as e:
        return {"error": str(e)}
