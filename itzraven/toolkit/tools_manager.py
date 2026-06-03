"""
Automated tool management — install/check security testing tools.

Usage:
  itzraven tools install     Auto-detect OS, install missing tools
  itzraven tools list        Show all tools and their install status
  itzraven tools check       Quick check of what's available
"""

import os
import sys
import shutil
import subprocess
import platform
from pathlib import Path
from typing import Dict, List, Tuple

# (name, binary_check, install_url_or_apt_pkg, category)
TOOLS: List[Tuple[str, str, str, str, str]] = [
    ("nmap",    "nmap",     "apt: nmap",                    "recon"),
    ("nuclei",  "nuclei",   "brew: nuclei;apt: nuclei",     "vuln"),
    ("httpx",   "httpx",    "brew: httpx;apt: httpx",       "recon"),
    ("naabu",   "naabu",    "brew: naabu;apt: naabu",       "recon"),
    ("sqlmap",  "sqlmap",   "pip: sqlmap",                   "exploit"),
    ("nikto",   "nikto",    "apt: nikto",                    "vuln"),
    ("gobuster","gobuster", "apt: gobuster",                 "recon"),
    ("jq",      "jq",       "apt: jq",                       "util"),
    ("xsltproc","xsltproc", "apt: xsltproc",                 "util"),
    ("whatweb", "whatweb",  "apt: whatweb",                  "recon"),
    ("wpscan",  "wpscan",   "gem: wpscan",                   "cms"),
    ("hydra",   "hydra",    "apt: hydra",                    "brute"),
    ("subfinder","subfinder","brew: subfinder;apt: subfinder","recon"),
]

INSTALL_SCRIPTS: Dict[str, str] = {
    "go": 'command -v go 2>/dev/null || {{ echo "Go required"; return 1; }}',
    "rust": 'command -v cargo 2>/dev/null || {{ echo "Rust required"; return 1; }}',
}


def _run(cmd: str, check: bool = False) -> Tuple[int, str]:
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=120)
        return r.returncode, r.stdout.strip()
    except subprocess.TimeoutExpired:
        return -1, "timeout"
    except Exception as e:
        return -1, str(e)


def _check_tool(name: str, binary: str) -> bool:
    return shutil.which(binary) is not None


def check_all() -> Dict[str, bool]:
    results = {}
    for name, binary, _, _ in TOOLS:
        results[name] = _check_tool(name, binary)
    return results


def _get_os() -> str:
    sys_platform = platform.system().lower()
    if sys_platform == "linux":
        if os.path.exists("/etc/debian_version"):
            return "debian"
        if os.path.exists("/etc/redhat-release"):
            return "rhel"
        if os.path.exists("/etc/arch-release"):
            return "arch"
        return "linux"
    if sys_platform == "darwin":
        return "macos"
    if sys_platform == "windows":
        return "windows"
    return sys_platform


def _install_apt(pkg: str) -> bool:
    code, out = _run(f"apt-get install -y {pkg} 2>/dev/null")
    return code == 0


def _install_brew(pkg: str) -> bool:
    code, out = _run(f"brew install {pkg} 2>/dev/null")
    return code == 0


def _install_pip(pkg: str) -> bool:
    code, out = _run(f"pip3 install {pkg} 2>/dev/null || pip install {pkg} 2>/dev/null")
    return code == 0


def _install_go(pkg_url: str) -> bool:
    code, out = _run(f"go install {pkg_url}@latest 2>/dev/null")
    return code == 0


def install_tool(name: str, binary: str, pkg_spec: str, yes: bool = False) -> bool:
    if _check_tool(name, binary):
        return True

    os_type = _get_os()
    methods = pkg_spec.split(";")

    if not yes:
        print(f"  {name}: not found → installing...", end="")

    for method in methods:
        method = method.strip()
        if method.startswith("apt:") and os_type in ("debian", "linux", "rhel"):
            pkg = method.split(":", 1)[1].strip()
            ok = _install_apt(pkg)
        elif method.startswith("brew:") and os_type == "macos":
            pkg = method.split(":", 1)[1].strip()
            ok = _install_brew(pkg)
        elif method.startswith("pip:"):
            pkg = method.split(":", 1)[1].strip()
            ok = _install_pip(pkg)
        elif method.startswith("go:"):
            pkg_url = method.split(":", 1)[1].strip()
            ok = _install_go(pkg_url)
        elif method.startswith("gem:"):
            pkg = method.split(":", 1)[1].strip()
            code, _ = _run(f"gem install {pkg} 2>/dev/null")
            ok = code == 0
        else:
            ok = False
        if ok:
            if not yes:
                print(" done")
            return True

    if not yes:
        print(" FAILED")
        print(f"    Try manual install: {pkg_spec}")
    return False


def install_all(yes: bool = False) -> Dict[str, bool]:
    print(f"Itzraven Tool Installer — OS: {_get_os()}")
    print("=" * 50)
    results = {}
    for name, binary, pkg_spec, category in TOOLS:
        results[name] = install_tool(name, binary, pkg_spec, yes)
    print("=" * 50)
    installed = sum(1 for v in results.values() if v)
    print(f"Tools: {installed}/{len(results)} installed")
    return results


def print_status():
    results = check_all()
    print(f"{'Tool':<15} {'Status':<10} {'Category':<12} {'Binary':<15}")
    print("-" * 52)
    for name, binary, _, category in TOOLS:
        status = "✅" if results.get(name) else "❌"
        print(f"{name:<15} {status:<10} {category:<12} {binary:<15}")


def handle_tools_cli(args) -> int:
    cmd = getattr(args, "tools_command", None)
    if cmd == "install":
        tool = getattr(args, "tool", None)
        yes = getattr(args, "yes", False)
        if tool:
            for name, binary, pkg_spec, _ in TOOLS:
                if name == tool:
                    ok = install_tool(name, binary, pkg_spec, yes)
                    return 0 if ok else 1
            print(f"Unknown tool: {tool}")
            print(f"Known tools: {', '.join(t[0] for t in TOOLS)}")
            return 1
        install_all(yes)
        return 0
    elif cmd == "list":
        print_status()
        return 0
    elif cmd == "check":
        results = check_all()
        missing = [name for name, ok in results.items() if not ok]
        if missing:
            print(f"Missing tools ({len(missing)}): {', '.join(missing)}")
            print("Run 'itzraven tools install' to install them.")
        else:
            print("All tools available!")
        return 1 if missing else 0
    else:
        print("Usage: itzraven tools install|list|check")
        print("  install\tAuto-detect OS and install missing tools")
        print("  list\t\tShow installed tool status")
        print("  check\t\tCheck which tools are available")
        return 1
