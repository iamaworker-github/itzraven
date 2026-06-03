"""
Main CLI entry point for Itzraven - Strix-compatible interface
"""
from __future__ import annotations
import argparse
import asyncio
import subprocess
import sys
from pathlib import Path
from typing import List, Optional

import click

from itzraven import __version__
from itzraven.core.config import set_config, check_docker, ensure_docker_image
from itzraven.core.logger import setup_logging, get_logger
from itzraven.core.di_container import get_container, ServiceLifecycle

logger = get_logger()


def _init_di_container():
    """Register core services in DI container at startup."""
    container = get_container()
    from itzraven.core.event_bus import EventBus, get_event_bus
    from itzraven.core.blackboard import Blackboard, get_blackboard
    from itzraven.core.bloom_filter import FindingDeduplicator, get_finding_dedup
    from itzraven.core.http_client import SharedHttpClient
    container.register_instance("event_bus", get_event_bus(), alias="EventBus")
    container.register_instance("blackboard", get_blackboard(), alias="Blackboard")
    container.register_instance("finding_dedup", get_finding_dedup(), alias="FindingDeduplicator")
    container.register(
        "http_client",
        lambda c: SharedHttpClient(name="default", max_connections=100),
        lifecycle=ServiceLifecycle.SINGLETON,
        alias="HttpClient",
    )


def print_banner():
    """Print Itzraven banner"""
    banner = f"""
     █████╗ ██████╗  ██████╗ ██╗   ██╗███████╗
    ██╔══██╗██╔══██╗██╔════╝ ██║   ██║██╔════╝
    ███████║██████╔╝██║  ███╗██║   ██║███████║
    ██╔══██║██╔══██╗██║   ██║██║   ██║╚════██║
    ██║  ██║██║  ██║╚██████╔╝╚██████╔╝███████║
    ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚══════╝

    See Everything. Miss Nothing • v{__version__}
    AI-Powered Security Testing Platform
    """
    click.secho(banner, fg="cyan", bold=True)


def build_parser() -> argparse.ArgumentParser:
    """Construct the Itzraven CLI parser - Strix-compatible interface."""
    parser = argparse.ArgumentParser(
        prog="itzraven",
        description="Itzraven - AI-Powered Security Testing Platform (Strix-compatible)",
        add_help=False,
    )
    parser.add_argument("-v", "--version", action="store_true", help="Show version and exit")
    parser.add_argument("-h", "--help", action="store_true", help="Show this help message and exit")

    parser.add_argument("--target", "-t", type=str, default=None,
                        help="Target to scan (URL, domain, IP, directory, or git repo)")
    parser.add_argument("--output", "-o", type=str, default=None, help="Output directory")
    parser.add_argument("--verbose", "-V", action="store_true", help="Verbose logging")
    parser.add_argument("--non-interactive", "-n", action="store_true", help="Non-interactive / headless mode")
    parser.add_argument("--parallel", action="store_true", help="Run agents in parallel")
    parser.add_argument("--quick", action="store_true", help="Quick scan mode")

    subparsers = parser.add_subparsers(dest="command")

    # ====================================================================
    # Swarm mode: itzraven swarm --target <target>
    # ====================================================================
    swarm_parser = subparsers.add_parser("swarm", help="Swarm mode — stigmergic blackboard agents")
    swarm_parser.add_argument("--target", "-t", type=str, required=True,
                              help="Target to scan (URL, domain, IP)")
    swarm_parser.add_argument("--playbook", "-p", type=str, default="bug-bounty",
                              choices=["bug-bounty", "external-asm", "ci-cd", "ctf-solver"],
                              help="Playbook to use for the scan")
    swarm_parser.add_argument("--bias", type=str, default="med",
                              choices=["low", "med", "high"],
                              help="Exploration bias: conservative, balanced, aggressive")
    swarm_parser.add_argument("--max-decisions", type=int, default=20,
                              help="Maximum swarm iterations")
    swarm_parser.add_argument("--budget", type=int, default=30,
                              help="Budget in minutes")

    # ====================================================================
    # MCP server: itzraven mcp serve
    # ====================================================================
    mcp_parser = subparsers.add_parser("mcp", help="MCP server for Claude Desktop / Cursor")
    mcp_sub = mcp_parser.add_subparsers(dest="mcp_command")
    mcp_serve = mcp_sub.add_parser("serve", help="Start MCP server over stdio")

    # ====================================================================
    # Playbook commands: itzraven playbook
    # ====================================================================
    pb_parser = subparsers.add_parser("playbook", help="List/run playbooks")
    pb_sub = pb_parser.add_subparsers(dest="pb_command")
    pb_list = pb_sub.add_parser("list", help="List available playbooks")
    pb_run = pb_sub.add_parser("run", help="Run a playbook")
    pb_run.add_argument("name", type=str, help="Playbook name (bug-bounty, external-asm, ci-cd, ctf-solver)")
    pb_run.add_argument("--target", "-t", type=str, required=True, help="Target to scan")

    # ====================================================================
    # Strix-compatible top-level flags (itzraven --target <target>)
    # ====================================================================
    strix_parser = subparsers.add_parser("strix", help="Strix-compatible scanning interface")
    strix_parser.add_argument("--target", "-t", type=str, required=True,
                              help="Target to test (URL, domain, IP, directory, or GitHub repo). Can be specified multiple times.")
    strix_parser.add_argument("--scan-mode", "-m", type=str, choices=["quick", "standard", "deep"],
                              default="deep", help="Scan depth: quick (minutes), standard (30min-1hr), deep (1-4hrs)")
    strix_parser.add_argument("--mode", type=str, choices=["osint", "bugbounty", "ctf", "pentest", "api-pentest"],
                              default="pentest", help="Scan mode: osint (passive), bugbounty (methodology gates), ctf (challenge solving), pentest (full), api-pentest (API security testing with Akto-inspired tests)")
    strix_parser.add_argument("--sub-mode", type=str, choices=["whitebox", "blackbox"],
                              default=None, help="Pentest sub-mode: whitebox (source code), blackbox (network)")
    strix_parser.add_argument("--scope", type=str, default=None,
                              help="Comma-separated allowed targets/patterns (e.g., example.com,*.example.com)")
    strix_parser.add_argument("--exclude", type=str, default=None,
                              help="Comma-separated excluded targets/patterns")
    strix_parser.add_argument("--scope-file", type=str, default=None,
                              help="YAML file with scope rules")
    strix_parser.add_argument("--scope-mode", type=str, choices=["auto", "diff", "full"],
                              default="auto", help="Code scope mode: auto (enable PR diff-scope in CI), diff (force), full (disable)")
    strix_parser.add_argument("--diff-base", type=str, default="origin/main",
                              help="Target branch or commit to compare against")
    strix_parser.add_argument("--instruction", type=str, default=None,
                              help="Custom instructions for the scan (credentials, focus areas)")
    strix_parser.add_argument("--instruction-file", type=str, default=None,
                              help="Path to a file containing detailed instructions")
    strix_parser.add_argument("--non-interactive", "-n", action="store_true",
                              help="Run in headless mode without TUI. Ideal for CI/CD.")
    strix_parser.add_argument("--output", "-o", type=str, help="Output directory")
    strix_parser.add_argument("--verbose", "-V", action="store_true", help="Verbose logging output")
    strix_parser.add_argument("--parallel", action="store_true", help="Run agents in parallel")
    strix_parser.add_argument("--remediation", action="store_true",
                              help="Generate autofix-style remediation suggestions from validated findings")
    strix_parser.add_argument("--gating-mode", choices=["off", "shadow", "enforced"], default="shadow",
                              help="Agent gating mode: off (disable), shadow (report only), enforced (block)")
    strix_parser.add_argument("--docker", action="store_true", help="Execute shell commands inside Docker sandbox")
    strix_parser.add_argument("--docker-image", type=str, default=None,
                              help="Docker image to use with --docker")
    strix_parser.add_argument("--headless/--no-headless", dest="headless", default=True,
                              action="store_true", help="Run browser in headless mode (default)")
    strix_parser.add_argument("--no-headless", dest="headless", action="store_false",
                              help="Run browser with UI")
    strix_parser.add_argument("--akto-dashboard-url", type=str, default=None,
                              help="Akto dashboard URL for Docker-based API security tests")
    strix_parser.add_argument("--akto-api-key", type=str, default=None,
                              help="Akto API key for authenticated testing")
    strix_parser.add_argument("--strict-poc", choices=["off", "shadow", "strict"], default="shadow",
                              help="No Exploit No Report policy: strict (remove unvalidated), shadow (annotate), off (default behavior)")
    strix_parser.add_argument("--profile", type=str, default=None,
                              help="Auth profile name for authenticated scanning (from ~/.itzraven/auth-profiles/)")
    strix_parser.add_argument("--checkpoint", action="store_true",
                               help="Enable workspace resume with checkpointing")
    strix_parser.add_argument("--temporal", action="store_true",
                                help="Enable distributed temporal orchestration (requires Redis)")
    strix_parser.add_argument("--graph", action="store_true",
                                help="Use LangGraph-powered orchestration (durable execution + conditional routing)")

    # ====================================================================
    # Bug Bounty Flags (Dark-Moon style — rich scope definition)
    # ====================================================================
    strix_parser.add_argument("--program", type=str, default=None,
                               help="Bug bounty program name (e.g., \"Juice Shop\")")
    strix_parser.add_argument("--focus", type=str, default=None,
                               help="Comma-separated focus vulnerabilities (e.g., sqli,xss,idor)")
    strix_parser.add_argument("--exclude-flags", type=str, default=None,
                               help="Free-form exclusion rules interpreted by LLM (e.g., H1, OOS)")
    strix_parser.add_argument("--noise", type=str, choices=["stealth", "low", "moderate", "high"],
                               default="moderate", help="Noise level: stealth (minimal), low, moderate, high (aggressive)")
    strix_parser.add_argument("--severity-cap", type=str, choices=["critical", "high", "medium", "low", "info"],
                               default=None, help="Cap findings at this severity level")
    strix_parser.add_argument("--report-format", type=str, choices=["standard", "h1", "bugcrowd", "custom"],
                               default="standard", help="Report format for bug bounty submissions")
    strix_parser.add_argument("--safe-harbor", action="store_true",
                               help="Enable safe harbor mode (no active exploitation, detection only)")
    strix_parser.add_argument("--engagement-rules", type=str, default=None,
                               help="Path to YAML file with engagement rules / RoE")
    strix_parser.add_argument("--asset-type", type=str,
                               choices=["domain", "url", "api", "cidr", "ip", "ios", "android", "source", "exec", "hw"],
                               default=None, help="Type of target asset (bug bounty scope)")

    # ====================================================================
    # Legacy subcommands
    # ====================================================================
    scan_parser = subparsers.add_parser("scan", help="[Legacy] Scan a target for security vulnerabilities")
    scan_parser.add_argument("target", help="Target to scan (IP, URL, domain, etc.)")
    scan_parser.add_argument("--parallel", action="store_true", help="Run agents in parallel")
    scan_parser.add_argument("--output", "-o", type=str, help="Output directory")
    scan_parser.add_argument("--verbose", "-V", action="store_true", help="Verbose logging output")
    scan_parser.add_argument("-n", "--non-interactive", action="store_true",
                             help="Run scan without interactive prompts")
    scan_parser.add_argument("--diff", action="store_true", help="Scan only changed paths from git diff")
    scan_parser.add_argument("--diff-base", type=str, default="origin/main",
                             help="Git base ref for --diff (default: origin/main)")
    scan_parser.add_argument("--instruction", type=str, default=None,
                             help="Focused instruction for scan planning")
    scan_parser.add_argument("--instruction-file", type=str, default=None,
                             help="Path to a file containing detailed instructions")
    scan_parser.add_argument("--remediation", action="store_true",
                             help="Generate autofix-style remediation suggestions")
    scan_parser.add_argument("--gating-mode", choices=["off", "shadow", "enforced"], default="shadow",
                             help="Agent gating mode")
    scan_parser.add_argument("--docker", action="store_true", help="Execute shell commands inside Docker sandbox")
    scan_parser.add_argument("--docker-image", type=str, default=None,
                             help="Docker image to use with --docker")
    scan_parser.add_argument("--headless/--no-headless", dest="headless", default=True,
                             action="store_true", help="Run browser in headless mode")
    scan_parser.add_argument("--no-headless", dest="headless", action="store_false",
                             help="Run browser with UI")

    tui_parser = subparsers.add_parser("tui", help="Launch interactive TUI for scanning")
    tui_parser.add_argument("target", nargs="?", default=None, help="Optional target for the TUI")

    # ====================================================================
    # Medusa scan subcommand
    # ====================================================================
    medusa_parser = subparsers.add_parser("medusa", help="Run Medusa AI security scanner (9600+ detection patterns)")
    medusa_parser.add_argument("target", help="Target directory or git repo URL to scan")
    medusa_parser.add_argument("--git", action="store_true", help="Scan a GitHub repo (user/repo or full URL)")
    medusa_parser.add_argument("--workers", "-w", type=int, default=None, help="Number of parallel workers")
    medusa_parser.add_argument("--output", "-o", type=str, default=None, help="Output directory for reports")

    # ====================================================================
    # Skills subcommand
    # ====================================================================
    skills_parser = subparsers.add_parser("skills", help="List and search loaded skills")
    skills_sub = skills_parser.add_subparsers(dest="skills_command")
    skills_list = skills_sub.add_parser("list", help="List all skills")
    skills_list.add_argument("--category", "-c", type=str, default=None, help="Filter by category")
    skills_search = skills_sub.add_parser("search", help="Search skills by keyword")
    skills_search.add_argument("query", help="Search query")

    # ====================================================================
    # Monitor
    # ====================================================================
    monitor_parser = subparsers.add_parser("monitor", help="Continuous monitoring mode")
    monitor_sub = monitor_parser.add_subparsers(dest="monitor_command")
    mon_add = monitor_sub.add_parser("add", help="Add target to monitor")
    mon_add.add_argument("target", help="Target to monitor")
    mon_add.add_argument("--interval", type=float, default=24.0, help="Scan interval in hours")
    mon_add.add_argument("--mode", choices=["osint", "pentest", "ctf"], default="osint")
    mon_list = monitor_sub.add_parser("list", help="List monitored targets")
    mon_rm = monitor_sub.add_parser("remove", help="Remove monitored target")
    mon_rm.add_argument("target", help="Target to remove")

    # ====================================================================
    # Campaign
    # ====================================================================
    campaign_parser = subparsers.add_parser("campaign", help="Campaign management")
    campaign_sub = campaign_parser.add_subparsers(dest="campaign_command")
    camp_create = campaign_sub.add_parser("create", help="Create campaign")
    camp_create.add_argument("name", help="Campaign name")
    camp_add = campaign_sub.add_parser("add", help="Add target to campaign")
    camp_add.add_argument("name", help="Campaign name")
    camp_add.add_argument("target", help="Target to add")
    camp_corr = campaign_sub.add_parser("correlate", help="Run correlations")
    camp_corr.add_argument("name", help="Campaign name")
    camp_list = campaign_sub.add_parser("list", help="List campaigns")

    # ====================================================================
    # Bug bounty commands
    # ====================================================================
    bounty_parser = subparsers.add_parser("bounty", help="Bug bounty platform integration")
    bounty_sub = bounty_parser.add_subparsers(dest="bounty_command")
    bp_search = bounty_sub.add_parser("search", help="Search programs")
    bp_search.add_argument("platform", choices=["hackerone", "bugcrowd", "intigriti"], help="Platform")
    bp_search.add_argument("--query", "-q", type=str, default="", help="Search query")
    bp_triage = bounty_sub.add_parser("triage", help="Triage a finding for bounty")
    bp_triage.add_argument("--finding-file", type=str, required=True, help="Finding JSON file")
    bp_submit = bounty_sub.add_parser("submit", help="Submit report (saves locally)")
    bp_submit.add_argument("platform", choices=["hackerone", "bugcrowd", "intigriti"])
    bp_submit.add_argument("--program", type=str, required=True, help="Program name")
    bp_submit.add_argument("--title", type=str, required=True, help="Report title")
    bp_submit.add_argument("--severity", choices=["critical", "high", "medium", "low", "info"], default="medium")
    bp_submit.add_argument("--description", type=str, required=True, help="Vulnerability description")
    bp_match = bounty_sub.add_parser("match", help="Find programs matching a target")
    bp_match.add_argument("target", help="Target domain/URL")

    # ====================================================================
    # Autopilot autonomous hunt loop
    # ====================================================================
    autopilot_parser = subparsers.add_parser("autopilot", help="Autonomous hunt loop (continuous)")
    autopilot_parser.add_argument("target", help="Target to hunt")
    autopilot_parser.add_argument("--waves", type=int, default=5, help="Number of waves (max 10)")
    autopilot_parser.add_argument("--output", "-o", type=str, default=None, help="Output directory")
    autopilot_parser.add_argument("--status", action="store_true", help="Show current hunt status")
    autopilot_parser.add_argument("--resume", action="store_true", help="Resume previous hunt session")

    # ====================================================================
    # Corpus management (RAG index population)
    # ====================================================================
    corpus_parser = subparsers.add_parser("corpus", help="Manage RAG prior-art corpus")
    corpus_sub = corpus_parser.add_subparsers(dest="corpus_command")
    corp_populate = corpus_sub.add_parser("populate", help="Build/rebuild RAG index from data sources")
    corp_populate.add_argument("--max-reports", type=int, default=0, help="Max reports to load (0=all)")
    corp_populate.add_argument("--force", action="store_true", help="Force rebuild even if index exists")
    corp_populate.add_argument("--source", choices=["huggingface", "json", "all"], default="all",
                               help="Data source (default: all)")
    corp_populate.add_argument("--json-dir", type=str, default=None, help="Path to JSON report directory")
    corp_refresh = corpus_sub.add_parser("refresh", help="Incremental update from GitHub repos (zzzteph/bugbounty-monitor)")
    corp_status = corpus_sub.add_parser("status", help="Show corpus statistics")
    corp_info = corpus_sub.add_parser("info", help="Detailed corpus info")

    # ====================================================================
    # Web Dashboard — same flags as strix for scan-on-start
    # ====================================================================
    web_parser = subparsers.add_parser("web", help="Start web dashboard")
    web_parser.add_argument("--host", type=str, default="0.0.0.0", help="Bind address")
    web_parser.add_argument("--port", type=int, default=8484, help="Bind port")
    web_parser.add_argument("--target", "-t", type=str, default=None,
                            help="Target to scan (URL, domain, IP, directory)")
    web_parser.add_argument("--scan-mode", "-m", type=str, choices=["quick", "standard", "deep"],
                            default="deep", help="Scan depth")
    web_parser.add_argument("--mode", type=str, choices=["osint", "bugbounty", "ctf", "pentest", "api-pentest"],
                            default="pentest", help="Scan mode")
    web_parser.add_argument("--parallel", action="store_true", help="Run agents in parallel")

    # ====================================================================
    # Tools management — install/check security testing tools
    # ====================================================================
    tools_parser = subparsers.add_parser("tools", help="Manage security testing tools")
    tools_sub = tools_parser.add_subparsers(dest="tools_command")
    tools_install = tools_sub.add_parser("install", help="Auto-detect OS and install missing tools")
    tools_install.add_argument("--tool", type=str, default=None, help="Install specific tool only (nmap, nuclei, naabu, httpx, sqlmap, jq, nikto, gobuster)")
    tools_install.add_argument("--yes", "-y", action="store_true", help="Skip confirmation prompts")
    tools_list = tools_sub.add_parser("list", help="Show installed tool status")
    tools_check = tools_sub.add_parser("check", help="Check which tools are available")

    return parser


def _print_help():
    help_text = """
Usage: itzraven --target <target> [OPTIONS]

  Itzraven - AI-Powered Security Testing Platform
  Just give it a target — Itzraven auto-detects, auto-decides, autonomous.

Examples:
  itzraven -t target.com           Auto-detect, run full suite
  itzraven -t ./my-project         Code analysis + Medusa SAST
  itzraven -t https://app.com -n   Non-interactive / headless
  itzraven -t target.com --quick   Quick scan mode
  itzraven -t target.com --parallel Run all agents in parallel
  itzraven -t target.com -o ./out  Custom output directory

Commands:
  strix                    Strix-compatible scanning (advanced options)
  scan TARGET              Legacy scan
  medusa TARGET            Run Medusa AI security scanner (9600+ patterns)
  skills list|search       List/search all 92+ loaded security skills
  tui [TARGET]             Launch interactive TUI

Options:
  -v, --version                  Show version
  -h, --help                     Show this help
  -t, --target TEXT              Target to scan [auto-detects type]
  -o, --output PATH              Output directory
  -n, --non-interactive          Headless mode (no TUI)
  --parallel                     Run agents in parallel
  --quick                        Quick scan mode
  -V, --verbose                  Verbose logging

API Pentest Mode:
  --mode api-pentest             Run API-specific security testing
  --akto-dashboard-url TEXT      Akto dashboard URL (optional, for Akto CLI)
  --akto-api-key TEXT            Akto API key (optional, for Akto CLI)
"""
    click.echo(help_text)


def resolve_diff_scope(scope_mode: str, diff_base: str) -> Optional[List[str]]:
    """Resolve changed files based on scope mode.

    Strix-style scope modes:
    - auto: Enable diff-scope in CI/headless runs
    - diff: Force changed-files scope
    - full: Disable diff-scope (scan everything)
    """
    if scope_mode == "full":
        return None
    if scope_mode == "auto":
        import os
        is_ci = os.environ.get("CI", "").lower() in ("true", "1")
        if not is_ci:
            return None

    try:
        cmd = ["git", "diff", "--name-only", f"{diff_base}...HEAD"]
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)

        if result.returncode != 0:
            logger.warning(f"Diff scope failed (git returned {result.returncode}); falling back to full scan")
            return None

        changed_files = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        if not changed_files:
            logger.warning("Diff scope requested but no changed files found; falling back to full scan")
            return None

        scoped_paths = [f"/{p}" for p in changed_files]
        logger.info(f"Scope mode '{scope_mode}': scoped to {len(scoped_paths)} changed paths")
        return scoped_paths
    except Exception as exc:
        logger.warning(f"Diff scope unavailable ({exc}); falling back to full scan")
        return None


def _load_instruction_file(path: str) -> str:
    """Load instruction from file."""
    try:
        return Path(path).read_text(encoding="utf-8").strip()
    except Exception as e:
        logger.warning(f"Failed to load instruction file {path}: {e}")
        return ""


def _build_markdown_report(result) -> str:
    """Build a Strix-style markdown summary report."""
    lines = [
        "# Itzraven Security Scan Report",
        "",
        f"- **Target:** {result.target}",
        f"- **Duration:** {result.duration:.2f}s",
        f"- **Total Findings:** {result.total_findings}",
        "",
    ]

    scan_metadata = result.metadata or {}
    scan_depth = scan_metadata.get("scan_depth", "deep")
    lines.append(f"- **Scan Depth:** {scan_depth}")
    lines.append("")

    poc_validation = scan_metadata.get("poc_validation", {})
    if poc_validation:
        lines.extend([
            "## PoC Validation",
            "",
            f"- Processed: {poc_validation.get('processed', 0)}",
            f"- Validated: {poc_validation.get('validated', 0)}",
            f"- Failed: {poc_validation.get('failed', 0)}",
            f"- Skipped: {poc_validation.get('skipped', 0)}",
            "",
        ])

    remediation = scan_metadata.get("remediation", {})
    if remediation:
        lines.extend([
            "## Remediation Suggestions",
            "",
            f"- Processed: {remediation.get('processed', 0)}",
            f"- Suggested: {remediation.get('suggested', 0)}",
            f"- Skipped: {remediation.get('skipped', 0)}",
            "",
        ])
        suggestions = remediation.get("suggestions", [])
        if suggestions:
            total_suggestions = len(suggestions)
            displayed_suggestions = min(5, total_suggestions)
            lines.extend([
                "### Top Suggestions",
                "",
                f"_Showing {displayed_suggestions} of {total_suggestions} remediation suggestions._",
                "",
            ])
            for suggestion in suggestions[:5]:
                lines.extend([
                    f"- **{suggestion.get('title', 'Unknown finding')}** ({suggestion.get('severity', 'unknown')})",
                    f"  - Suggested fix: {suggestion.get('suggested_fix', 'N/A')}",
                ])
                patch_suggestion = suggestion.get("patch_suggestion")
                if patch_suggestion:
                    lines.append(f"  - Patch suggestion: {patch_suggestion}")
                lines.append("")

    gating_shadow = scan_metadata.get("gating_shadow_decisions", [])
    if gating_shadow:
        lines.extend([
            "## Agent Gating Decisions (Shadow Mode)",
            "",
        ])
        for decision in gating_shadow:
            lines.extend([
                f"- **{decision.get('agent_name', 'Unknown Agent')}**: {str(decision.get('decision', 'skip')).upper()}",
                f"  - Confidence: {decision.get('confidence', 0)}",
                f"  - Reason: {decision.get('reason', 'N/A')}",
            ])
            blockers = decision.get("blockers", [])
            if blockers:
                lines.append(f"  - Blockers: {', '.join(str(b) for b in blockers)}")
            lines.append("")

    gating_enforced = scan_metadata.get("gating_enforced_decisions", [])
    if gating_enforced:
        lines.extend([
            "## Agent Gating Decisions (Enforced Mode)",
            "",
        ])
        for decision in gating_enforced:
            lines.extend([
                f"- **{decision.get('agent_name', 'Unknown Agent')}**: {str(decision.get('decision', 'skip')).upper()}",
                f"  - Confidence: {decision.get('confidence', 0)}",
                f"  - Reason: {decision.get('reason', 'N/A')}",
            ])
            blockers = decision.get("blockers", [])
            if blockers:
                lines.append(f"  - Blockers: {', '.join(str(b) for b in blockers)}")
            lines.append("")

    gating_enforced_skips = scan_metadata.get("gating_enforced_skips", [])
    if gating_enforced_skips:
        lines.extend([
            "### Enforced Gating Blocked Agents",
            "",
        ])
        for skipped in gating_enforced_skips:
            lines.extend([
                f"- **{skipped.get('agent_name', 'Unknown Agent')}**",
                f"  - Reason: {skipped.get('reason', 'N/A')}",
            ])
        lines.append("")

    if result.total_findings > 0:
        lines.extend(["## Findings by Severity", ""])
        for severity, count in result.findings_by_severity.items():
            if count > 0:
                lines.append(f"- **{severity.upper()}**: {count}")
        lines.append("")

    critical_high = [f for f in result.all_findings if f.severity.lower() in ["critical", "high"]]
    if critical_high:
        lines.extend(["## Vulnerabilities Found", ""])
        from itzraven.core.cvss_scorer import score_finding, generate_code_location_xml, generate_finding_xml
        for finding in critical_high[:10]:
            cvss = score_finding(finding.category, finding.severity, bool(finding.proof_of_concept))
            lines.extend([
                f"### [{finding.severity.upper()}] {finding.title}",
                f"- **Category:** {finding.category}",
                f"- **CVSS Score:** {cvss.score} ({cvss.vector})",
                f"- **CWE:** {finding.cwe_id or 'N/A'}",
                f"- **Confidence:** {finding.confidence}",
                f"- **Evidence:** {finding.evidence}",
            ])
            if finding.file_path or finding.line_number:
                loc_parts = []
                if finding.file_path: loc_parts.append(f"`{finding.file_path}`")
                if finding.line_number: loc_parts.append(f"line {finding.line_number}")
                lines.append(f"- **Location:** {', '.join(loc_parts)}")
            if finding.proof_of_concept:
                lines.append(f"- **PoC:** `{finding.proof_of_concept}`")
            if finding.remediation:
                lines.append(f"- **Remediation:** {finding.remediation}")
            lines.append("")

    lines.extend([
        "---",
        "_Generated by Itzraven - See Everything. Miss Nothing._",
        "",
    ])

    return "\n".join(lines).rstrip() + "\n"


def _create_mode_orchestrator(
    target: str,
    mode: str,
    scan_depth: str = "deep",
    scope: Optional[List[str]] = None,
    gating_mode: str = "shadow",
    instruction: Optional[str] = None,
    sub_mode: Optional[str] = None,
    scope_validator: Optional['ScopeValidator'] = None,
    event_bus=None,
    memory_manager=None,
    akto_dashboard_url: Optional[str] = None,
    akto_api_key: Optional[str] = None,
) -> ModeOrchestrator:
    """Create the appropriate mode-specific orchestrator (lazy imports)."""
    import_map = {
        "osint": ("itzraven.agents.modes.osint", "OSINTOrchestrator"),
        "bugbounty": ("itzraven.agents.modes.bugbounty", "BugBountyOrchestrator"),
        "ctf": ("itzraven.agents.modes.ctf", "CTFOrchestrator"),
        "pentest": ("itzraven.agents.modes.pentest", "PentestOrchestrator"),
        "api-pentest": ("itzraven.agents.modes.api_pentest", "ApiPentestOrchestrator"),
    }
    entry = import_map.get(mode, import_map["pentest"])
    import importlib
    mod = importlib.import_module(entry[0])
    cls = getattr(mod, entry[1])
    base = {"target": target, "scan_depth": scan_depth, "event_bus": event_bus, "memory_manager": memory_manager}
    if mode == "ctf":
        kwargs = {**base}
    elif mode == "osint":
        kwargs = {**base, "scope": scope}
    else:
        kwargs = {**base, "scope": scope, "instruction": instruction}
    if mode == "pentest":
        kwargs["sub_mode"] = sub_mode
    if mode == "api-pentest":
        kwargs["akto_dashboard_url"] = akto_dashboard_url
        kwargs["akto_api_key"] = akto_api_key
    return cls(**kwargs)


async def run_scan(
    target: str,
    parallel: bool,
    scan_depth: str = "deep",
    scope_mode: str = "auto",
    diff: bool = False,
    diff_base: str = "origin/main",
    non_interactive: bool = False,
    instruction: Optional[str] = None,
    remediation: bool = False,
    gating_mode: str = "shadow",
    mode: str = "pentest",
    sub_mode: Optional[str] = None,
    scope_list: Optional[List[str]] = None,
    exclude_list: Optional[List[str]] = None,
    akto_dashboard_url: Optional[str] = None,
    akto_api_key: Optional[str] = None,
    strict_poc: str = "shadow",
    profile: Optional[str] = None,
    checkpoint: bool = False,
    graph: bool = False,
    event_bus=None,
    _from_web: bool = False,
    _orchestrator_hook=None,
):
    """Run security scan - Strix-compatible with telemetry."""
    from itzraven.core.telemetry import get_tracer, trace
    tracer = get_tracer()
    scan_trace = tracer.start_span(f"scan:{target}", attributes={"target": target, "mode": mode, "depth": scan_depth})
    try:
        # Resolve scope (Strix-style scope-mode logic)
        if diff:
            scope_mode = "diff"
        scan_scope = resolve_diff_scope(scope_mode, diff_base)

        # Build scope validator if scope rules provided
        scope_validator = None
        if scope_list or exclude_list:
            from itzraven.core.scope import ScopeValidator
            scope_validator = ScopeValidator()
            for s in (scope_list or []):
                scope_validator.add_scope(s)
            for e in (exclude_list or []):
                scope_validator.add_exclude_scope(e)
            logger.info(f"Scope enforcement active: {len(scope_list or [])} allow, {len(exclude_list or [])} exclude rules")

        # Create mode-specific orchestrator
        orchestrator = _create_mode_orchestrator(
            target=target,
            mode=mode,
            scan_depth=scan_depth,
            scope=scan_scope,
            gating_mode=gating_mode,
            instruction=instruction,
            sub_mode=sub_mode,
            scope_validator=scope_validator,
            event_bus=event_bus,
            akto_dashboard_url=akto_dashboard_url,
            akto_api_key=akto_api_key,
        )
        orchestrator.load_agents()

        # Pass orchestrator reference to web server for pause/kill
        if _orchestrator_hook:
            _orchestrator_hook(orchestrator)

        # Run scan
        if graph and hasattr(orchestrator, 'run_graph'):
            logger.info("🧠 Running LangGraph-powered orchestration...")
            result = await orchestrator.run_graph()
        elif parallel:
            logger.info("Running agents in parallel...")
            result = await orchestrator.run_parallel()
        else:
            logger.info("Running agents sequentially...")
            result = await orchestrator.run_sequential()

        # Save results
        import json
        from itzraven.core.config import get_config
        config = get_config()
        output_dir = Path(config.get("output_dir"))

        target_slug = target.replace(".", "_").replace(":", "_").replace("/", "_")
        output_file = output_dir / f"{target_slug}_scan.json"
        output_file.parent.mkdir(parents=True, exist_ok=True)

        with open(output_file, "w") as f:
            json.dump(result.to_dict(), f, indent=2)

        logger.success(f"Results saved to: {output_file}")

        # Save XML report with CVSS + code locations (Strix v0.8.0 style)
        try:
            from itzraven.core.cvss_scorer import generate_report_xml
            xml_file = output_dir / f"{target_slug}_scan.xml"
            xml_content = generate_report_xml(
                [f.to_dict() for f in result.all_findings],
                result.target,
            )
            xml_file.write_text(xml_content, encoding="utf-8")
            logger.success(f"XML report saved to: {xml_file}")
        except Exception as e:
            logger.debug(f"XML report generation skipped: {e}")

        if non_interactive:
            try:
                from itzraven.core.professional_report import generate_professional_report
                paths = generate_professional_report(
                    result.all_findings, result.target,
                    output_dir=output_dir,
                    scan_metadata=result.metadata,
                    formats=("md", "html") if scan_depth == "deep" else ("md",),
                )
                for p in paths:
                    logger.success(f"Report saved: {p}")
            except Exception as e:
                logger.debug(f"Professional report failed, falling back: {e}")
                markdown_file = output_dir / f"{target_slug}_scan.md"
                markdown_file.write_text(_build_markdown_report(result), encoding="utf-8")
                logger.success(f"Markdown report saved to: {markdown_file}")

        print_summary(result)

        # Strix exit code: 2 when vulnerabilities found in non-interactive mode
        if non_interactive and result.total_findings > 0 and not _from_web:
            sys.exit(2)

        tracer.end_span(scan_trace, status="ok")
    except KeyboardInterrupt:
        if not _from_web:
            tracer.end_span(scan_trace, status="cancelled", error="User interrupt")
            logger.warning("Scan interrupted by user")
            sys.exit(1)
    except Exception as e:
        tracer.end_span(scan_trace, status="error", error=str(e))
        logger.error(f"Scan failed: {e}")
        try:
            from itzraven.core.config import get_config
            config = get_config()
            if config.debug:
                import traceback
                traceback.print_exc()
        except Exception:
            pass
        sys.exit(1)


def print_summary(result):
    """Print scan summary using click for coloured output"""
    click.echo("\n" + "=" * 60)
    click.secho("SCAN SUMMARY", fg="cyan", bold=True)
    click.echo("=" * 60)

    click.echo(f"Target: {result.target}")
    click.echo(f"Duration: {result.duration:.2f}s")
    click.echo(f"Total Findings: {result.total_findings}")

    scan_metadata = result.metadata or {}
    if "scan_depth" in scan_metadata:
        click.echo(f"Scan Depth: {scan_metadata['scan_depth']}")

    poc_validation = scan_metadata.get("poc_validation", {})
    if poc_validation:
        click.echo("\nPoC Validation:")
        click.echo(f"  Processed: {poc_validation.get('processed', 0)}")
        click.echo(f"  Validated: {poc_validation.get('validated', 0)}")
        click.echo(f"  Failed: {poc_validation.get('failed', 0)}")
        click.echo(f"  Skipped: {poc_validation.get('skipped', 0)}")

    if result.total_findings > 0:
        click.echo("\nFindings by Severity:")
        for severity, count in result.findings_by_severity.items():
            if count > 0:
                color = {
                    "critical": "red", "high": "red",
                    "medium": "yellow", "low": "blue",
                    "info": "white",
                }.get(severity, "white")
                click.secho(f"  {severity.upper()}: {count}", fg=color)

        critical_high = [f for f in result.all_findings if f.severity.lower() in ["critical", "high"]]
        if critical_high:
            click.echo("\n" + "=" * 60)
            click.secho("CRITICAL & HIGH SEVERITY FINDINGS", fg="red", bold=True)
            click.echo("=" * 60)
            from itzraven.core.cvss_scorer import score_finding
            for finding in critical_high[:5]:
                cvss = score_finding(finding.category, finding.severity, bool(finding.proof_of_concept))
                click.secho(f"\n[{finding.severity.upper()}] {finding.title}", fg="red", bold=True)
                click.echo(f"Category: {finding.category}")
                click.echo(f"CVSS: {cvss.score} | Vector: {cvss.vector}")
                if finding.file_path:
                    click.echo(f"File: {finding.file_path}:{finding.line_number or '?'}")
                click.echo(f"Evidence: {finding.evidence}")
                if finding.proof_of_concept:
                    click.echo(f"PoC: {finding.proof_of_concept}")

    click.echo("\n" + "=" * 60)


def launch_tui(target: str | None):
    """Launch the StrixUI TUI."""
    from itzraven.ui.strix_app import run_strix_ui
    run_strix_ui(target)


def _init_docker():
    """Initialize Docker sandbox — mandatory for consistent execution."""
    from itzraven.core.config import get_config
    config = get_config()
    if not config.get("use_docker"):
        logger.info("Docker sandbox disabled via config")
        return
    if not config.get("docker_mandatory"):
        logger.info("Docker sandbox not mandatory")
        return
    logger.info("Checking Docker daemon...")
    if not check_docker():
        logger.error(
            "Docker is required but not running.\n"
            "  Install Docker: https://docs.docker.com/get-docker/\n"
            "  Or disable: export USE_DOCKER=false\n"
            "  Or skip check: export DOCKER_MANDATORY=false"
        )
        import sys
        sys.exit(1)
    logger.info("Docker daemon: OK")
    image = config.get("docker_image") or "itzraven-security/sandbox:latest"
    logger.info(f"Ensuring sandbox image: {image}")
    if not ensure_docker_image(image):
        logger.warning(f"Could not pull {image}, continuing with local execution")
    else:
        logger.info(f"Sandbox image ready: {image}")


def main(argv: list[str] | None = None):
    """Entry point for the Itzraven CLI.

    ``argv`` can be injected for testing; defaults to ``sys.argv[1:]``.
    """
    _init_di_container()
    _init_docker()
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.version:
        click.echo(f"Itzraven v{__version__}")
        return

    if args.help and args.command is None:
        _print_help()
        return

    # ====================================================================
    # DEFAULT: itzraven --target <target> — fully autonomous mode
    # Just give it a target, Itzraven decides everything
    # ====================================================================
    if args.command is None:
        target = args.target
        if target:
            from itzraven.agents.modes import AutonomousOrchestrator, detect_target_type
            target_type = detect_target_type(target)
            print_banner()
            if not args.non_interactive and target_type != "directory":
                launch_tui(target)
                return
            output_dir = Path(args.output) if args.output else Path("./itzraven_results")
            set_config(verbose=args.verbose, output_dir=output_dir)
            setup_logging(output_dir, args.verbose)
            click.secho(f"🎯 {target} → {target_type}", fg="cyan", bold=True)
            logger.info(f"🚀 Autonomous mode — target: {target} (type: {target_type})")
            logger.info(f"🎯 Auto-selecting agents, running Medusa + 92 skills")
            orchestrator = AutonomousOrchestrator(
                target=target,
                scan_depth="quick" if args.quick else "deep",
                instruction=None,
            )
            orchestrator.load_agents()
            result = asyncio.run(
                orchestrator.run_parallel() if args.parallel else orchestrator.run_sequential()
            )
            t = getattr(result, 'total_findings', 0)
            click.secho(f"\n✅ Scan complete. {t} findings.", fg="green", bold=True)
            return
        _print_help()
        return

    # ====================================================================
    # Strix-compatible command: itzraven strix --target <target>
    # ====================================================================
    if args.command == "strix":
        print_banner()

        # Process instruction file
        instruction = args.instruction
        if args.instruction_file:
            file_instruction = _load_instruction_file(args.instruction_file)
            if file_instruction:
                instruction = (instruction + "\n" + file_instruction).strip() if instruction else file_instruction

        output_dir = Path(args.output) if args.output else Path("./itzraven_results")
        runtime_config = {
            "verbose": args.verbose,
            "headless_browser": args.headless,
            "output_dir": output_dir,
            "use_docker": args.docker,
        }
        if args.docker_image:
            runtime_config["docker_image"] = args.docker_image
        set_config(**runtime_config)
        setup_logging(output_dir, args.verbose)

        logger.info(f"Target: {args.target}")
        logger.info(f"Scan Depth: {args.scan_mode}")
        logger.info(f"Output: {output_dir}")

        # Set up scope enforcement
        scope_list = None
        if args.scope:
            scope_list = [s.strip() for s in args.scope.split(",")]
        if args.scope_file:
            from itzraven.core.scope import ScopeValidator
            sv = ScopeValidator()
            sv.load_from_file(args.scope_file)
            if args.exclude:
                for ex in args.exclude.split(","):
                    sv.add_exclude_scope(ex.strip())
            scope_list = scope_list or []
            scope_list.extend(sv._allow_patterns)

        # Load auth profile if specified
        if args.profile:
            try:
                from itzraven.core.auth_handler import get_auth_profile_manager, AuthFlowExecutor
                mgr = get_auth_profile_manager()
                profile = mgr.get_profile(args.profile)
                if profile:
                    logger.info(f"Auth profile loaded: {profile.name} ({profile.type})")
            except Exception as e:
                logger.warning(f"Auth profile '{args.profile}' not found: {e}")

        asyncio.run(
            run_scan(
                args.target,
                args.parallel,
                scan_depth=args.scan_mode,
                scope_mode=args.scope_mode,
                diff_base=args.diff_base,
                non_interactive=args.non_interactive,
                instruction=instruction,
                remediation=args.remediation,
                gating_mode=args.gating_mode,
                mode=args.mode,
                sub_mode=args.sub_mode,
                scope_list=scope_list,
                exclude_list=[s.strip() for s in args.exclude.split(",")] if args.exclude else None,
                akto_dashboard_url=args.akto_dashboard_url,
                akto_api_key=args.akto_api_key,
                strict_poc=args.strict_poc,
                profile=args.profile,
                checkpoint=args.checkpoint,
                graph=args.graph,
            )
        )
        return

    # ====================================================================
    # Legacy scan command
    # ====================================================================
    if args.command == "scan":
        print_banner()

        instruction = args.instruction
        if args.instruction_file:
            file_instruction = _load_instruction_file(args.instruction_file)
            if file_instruction:
                instruction = (instruction + "\n" + file_instruction).strip() if instruction else file_instruction

        output_dir = Path(args.output) if args.output else Path("./itzraven_results")
        runtime_config = {
            "verbose": args.verbose,
            "headless_browser": args.headless,
            "output_dir": output_dir,
            "use_docker": args.docker,
        }
        if args.docker_image:
            runtime_config["docker_image"] = args.docker_image
        set_config(**runtime_config)
        setup_logging(output_dir, args.verbose)
        logger.info(f"Target: {args.target}")
        logger.info(f"Output: {output_dir}")
        asyncio.run(
            run_scan(
                args.target,
                args.parallel,
                scan_depth="deep",
                scope_mode="diff" if args.diff else "full",
                diff=args.diff,
                diff_base=args.diff_base,
                non_interactive=args.non_interactive,
                instruction=instruction,
                remediation=args.remediation,
                gating_mode=args.gating_mode,
                graph=getattr(args, 'graph', False),
            )
        )
        return

    # ====================================================================
    # TUI command
    # ====================================================================
    if args.command == "tui":
        print_banner()
        launch_tui(args.target)
        return

    # ====================================================================
    # Medusa standalone command
    # ====================================================================
    if args.command == "medusa":
        print_banner()
        from itzraven.toolkit.medusa_integration import MedusaIntegration
        if not MedusaIntegration.check_available():
            click.secho("medusa-security not installed. Run: pip install medusa-security", fg="red")
            sys.exit(1)
        click.echo(f"Running Medusa scan on {args.target}...")
        if args.git:
            result = MedusaIntegration.scan_git_repo(args.target, workers=args.workers)
        else:
            result = MedusaIntegration.scan_path(args.target, workers=args.workers)
        if result.error:
            click.secho(f"Error: {result.error}", fg="red")
            sys.exit(1)
        click.echo(f"\nMedusa Scan Results:")
        click.echo(f"  Total Issues: {result.total_issues}")
        click.echo(f"  Files Scanned: {result.files_scanned}")
        click.echo(f"  Security Score: {result.security_score}/100")
        click.echo(f"  Risk Level: {result.risk_level}")
        click.echo(f"  Severity: {result.severity_breakdown}")
        for issue in result.findings:
            if not issue.is_likely_fp:
                click.secho(f"  [{issue.severity}] {issue.issue}", fg="red" if issue.severity in ("CRITICAL", "HIGH") else "yellow")
                click.echo(f"    File: {issue.file}:{issue.line} | Scanner: {issue.scanner}")
        return

    # ====================================================================
    # Skills commands
    # ====================================================================
    if args.command == "skills":
        from rich.console import Console
        from rich.table import Table
        from rich.text import Text
        console = Console()
        from itzraven.skills.manager import SkillsManager
        sm = SkillsManager()
        if args.skills_command == "list":
            summary = sm.summary()
            table = Table(title=f"📚 Skills Ready: {summary['total']} total", title_style="bold cyan", border_style="cyan")
            table.add_column("Category", style="yellow", width=16)
            table.add_column("Count", style="white", justify="right", width=6)
            for cat, count in sorted(summary['categories'].items()):
                table.add_row(cat, str(count))
            console.print(table)
            category = getattr(args, 'category', None)
            skills = sm.get_by_category(category) if category else sm.list_all()
            cat_filter = f" — Category: {category}" if category else ""
            st = Table(title=f"Skills{cat_filter}", title_style="bold green", border_style="green", show_lines=True)
            st.add_column("Name", style="bold yellow", width=28)
            st.add_column("Category", style="cyan", width=14)
            st.add_column("Description", style="white", overflow="fold")
            for s in skills:
                st.add_row(s['name'], s.get('category', 'general'), s['description'])
            console.print(st)
        elif args.skills_command == "search":
            results = sm.search(args.query)
            st = Table(title=f"🔍 Found {len(results)} skills matching '{args.query}'", title_style="bold cyan", border_style="cyan", show_lines=True)
            st.add_column("Name", style="bold yellow", width=28)
            st.add_column("Category", style="cyan", width=14)
            st.add_column("Description", style="white", overflow="fold")
            for s in results:
                st.add_row(s['name'], s.get('category', 'general'), s['description'])
            console.print(st)
        else:
            click.echo("Usage: itzraven skills list|search <query>")
        return

    # ====================================================================
    # Monitor: itzraven monitor add/list/remove
    # ====================================================================
    if args.command == "monitor":
        from itzraven.core.monitor import get_monitor
        monitor = get_monitor()
        cmd = getattr(args, 'monitor_command', '')
        if cmd == "add":
            monitor.add_target(args.target, interval_hours=args.interval, mode=args.mode)
            click.secho(f"Monitoring {args.target} every {args.interval}h (mode={args.mode})", fg="green")
        elif cmd == "list":
            targets = monitor.list_targets()
            if targets:
                click.secho(f"\nMonitored targets ({len(targets)}):", bold=True)
                for t in targets:
                    click.echo(f"  {t['target']:40s} interval={t['interval_hours']}h mode={t['mode']}")
            else:
                click.echo("No monitored targets")
        elif cmd == "remove":
            if monitor.remove_target(args.target):
                click.secho(f"Removed {args.target} from monitoring", fg="yellow")
            else:
                click.secho(f"Target {args.target} not found", fg="red")
        else:
            click.echo("Usage: itzraven monitor add|list|remove")
        return

    # ====================================================================
    # Campaign: itzraven campaign create/add/correlate/list
    # ====================================================================
    if args.command == "campaign":
        from itzraven.core.campaign import CampaignManager
        cmd = getattr(args, 'campaign_command', '')
        if cmd == "create":
            camp = CampaignManager(name=args.name)
            click.secho(f"Campaign '{args.name}' created", fg="green")
        elif cmd == "add":
            camp = CampaignManager(name=args.name)
            camp.add_target(args.target)
            click.secho(f"Added {args.target} to campaign '{args.name}'", fg="green")
        elif cmd == "correlate":
            camp = CampaignManager(name=args.name)
            click.secho(f"Running correlations for campaign '{args.name}'...", bold=True)
            correlations = asyncio.run(camp.correlate_all())
            for c in correlations:
                sev_color = {"critical": "red", "high": "red", "medium": "yellow", "low": "white"}.get(c.severity, "white")
                click.secho(f"  [{c.severity.upper()}] {c.description}", fg=sev_color)
                click.echo(f"    Targets: {', '.join(c.targets[:3])}")
            click.secho(f"Total: {len(correlations)} correlations", bold=True)
        elif cmd == "list":
            click.echo("Usage: campaign create|add|correlate <name> [target]")
        return

    # ====================================================================
    # Autopilot: itzraven autopilot <target>
    # ====================================================================
    if args.command == "autopilot":
        from itzraven.core.autopilot import get_autopilot
        hunter = get_autopilot(args.target)

        if args.status:
            s = hunter.summary()
            click.secho(f"\nAutopilot Status — {s['target']}", bold=True)
            click.echo(f"  Session: {s['session_id']}")
            click.echo(f"  Waves: {s['waves']}")
            click.echo(f"  Endpoints: {s['total_endpoints']}")
            click.echo(f"  Interesting: {s['interesting_endpoints']}")
            click.echo(f"  Findings: {s['total_findings']}")
            click.echo(f"  Active: {'✅' if s['active'] else '❌'}")
            return

        click.secho(f"\n🚀 Autopilot hunting {args.target}", bold=True, fg="cyan")
        max_waves = min(args.waves, 10)
        for wave in range(1, max_waves + 1):
            if not hunter.should_continue():
                click.echo("No promising leads, stopping early.")
                break
            plan = hunter.wave_plan()
            click.echo(f"\n{'='*50}")
            click.secho(f"Wave {plan['wave']}/{max_waves}", bold=True, fg="yellow")
            click.echo(f"  Agents: {', '.join(plan['agents'])}")
            click.echo(f"  Endpoints: {len(plan['endpoints'])}")
            click.echo(f"  Depth: {plan['depth']}")
            interesting = hunter.get_interesting_endpoints()
            if interesting:
                click.echo(f"\n  Hot leads ({len(interesting)}):")
                for ep in interesting[:3]:
                    click.echo(f"    🔥 {ep.url} (score: {ep.depth_score:.1f})")
        s = hunter.summary()
        click.secho(f"\n✅ Hunt complete: {s['waves']} waves, {s['total_findings']} findings, {s['total_endpoints']} endpoints", bold=True, fg="green")
        return

    # ====================================================================
    # Corpus: itzraven corpus populate|status|info
    # ====================================================================
    if args.command == "corpus":
        from itzraven.core.rag_search import get_rag_search
        cmd = getattr(args, 'corpus_command', '')
        if cmd == "refresh":
            from itzraven.core.corpus_populator import refresh_corpus
            click.secho("Refreshing corpus from GitHub repos (zzzteph/bugbounty-monitor)...", bold=True)
            total = refresh_corpus()
            click.secho(f"Refresh complete: {total} total records", bold=True, fg="green")
        elif cmd == "populate":
            from itzraven.core.corpus_populator import populate_from_all_sources, CorpusPopulator

            if args.source == "json" and args.json_dir:
                pop = CorpusPopulator()
                n = pop.from_json_dir(args.json_dir, args.max_reports)
                indexed, elapsed = pop.build_index()
                click.secho(f"Indexed {indexed} reports from JSON in {elapsed:.1f}s", bold=True, fg="green")
            elif args.source == "huggingface":
                n = populate_from_all_sources(max_reports=args.max_reports, force=args.force)
                click.secho(f"Indexed {n} reports from HuggingFace", bold=True, fg="green")
            else:
                n = populate_from_all_sources(max_reports=args.max_reports, force=args.force)
                click.secho(f"Indexed {n} reports from all sources", bold=True, fg="green")

            rag = get_rag_search()
            s = rag.status()
            click.echo(f"RAG status: {s['entries']} entries, FAISS: {s['faiss_available']}")

        elif cmd == "status":
            from itzraven.core.corpus_populator import get_corpus_stats
            stats = get_corpus_stats()
            if stats["total"] == 0:
                click.secho("Corpus not built. Run: itzraven corpus populate", fg="yellow")
            else:
                click.secho(f"\nRAG Corpus Status", bold=True)
                click.echo(f"  Total entries: {stats['total']}")
                click.echo(f"  Sources: {stats['sources']}")
                click.echo(f"  Severity breakdown: {stats['severity']}")
                top_techs = dict(sorted(stats['techniques'].items(), key=lambda x: -x[1])[:10])
                click.echo(f"  Top techniques: {top_techs}")

        elif cmd == "info":
            from itzraven.core.corpus_populator import get_corpus_stats
            stats = get_corpus_stats()
            if stats["total"] == 0:
                click.secho("Corpus not built. Run: itzraven corpus populate", fg="yellow")
            else:
                click.secho("\nCorpus Info", bold=True)
                click.echo(f"  Entries: {stats['total']}")
                click.echo(f"  Status: {stats['status']}")
                click.echo(f"\n  By Source:")
                for src, cnt in sorted(stats['sources'].items()):
                    click.echo(f"    {src}: {cnt}")
                click.echo(f"\n  By Severity:")
                for sev, cnt in sorted(stats['severity'].items()):
                    color = {"critical": "red", "high": "red", "medium": "yellow"}.get(sev, "white")
                    click.secho(f"    {sev}: {cnt}", fg=color)
                click.echo(f"\n  By Technique (top 15):")
                for tech, cnt in sorted(stats['techniques'].items(), key=lambda x: -x[1])[:15]:
                    click.echo(f"    {tech}: {cnt}")
        else:
            click.echo("Usage: itzraven corpus populate|status|info")
        return

    # ====================================================================
    # Web Dashboard: itzraven web --port 8484 -t target.com --mode pentest
    # ====================================================================
    if args.command == "tools":
        from itzraven.toolkit.tools_manager import handle_tools_cli
        return handle_tools_cli(args)

    if args.command == "web":
        host = getattr(args, 'host', '0.0.0.0')
        port = getattr(args, 'port', 8484)
        target = getattr(args, 'target', None)

        import itzraven.web_server as ws

        # If target provided, set up scan state and pending scan before starting server
        if target:
            import uuid
            session_id = uuid.uuid4().hex[:8]
            ws.dashboard_state.update({
                "target": target,
                "mode": getattr(args, 'mode', 'pentest').upper(),
                "sessionId": session_id,
                "agentStatus": "PLANNING",
                "commandsExecuted": 0,
                "dataCollected": "0 MB",
                "findingsCount": 0,
                "findings": [],
                "logs": [],
                "thinkingLines": [],
                "activities": [],
                "discoveries": [],
            })

            # Schedule scan to start when server is ready (via startup event)
            ws._pending_scan = {
                "target": target,
                "mode": getattr(args, 'mode', 'pentest'),
                "session_id": session_id,
            }

        ws.run_server(host=host, port=port)
        return

    # ====================================================================
    # Swarm mode: itzraven swarm --target <target>
    # ====================================================================
    if args.command == "swarm":
        from itzraven.core.swarm import get_blackboard, get_scheduler, SwarmAgent, BlackboardEntry
        from itzraven.core.swarm.scheduler import SwarmContext
        from itzraven.core.playbook_engine import get_playbook_engine
        from itzraven.core.swarm.pheromone import PheromoneConfig

        click.secho("🐝 Itzraven Swarm Mode — stigmergic blackboard coordination", fg="yellow", bold=True)
        click.echo(f"  Target: {args.target}")
        click.echo(f"  Playbook: {args.playbook}")
        click.echo(f"  Bias: {args.bias}")
        click.echo(f"  Budget: {args.budget}min")

        board = get_blackboard()
        scheduler = get_scheduler()
        pheromone_cfg = PheromoneConfig.from_bias(args.bias)

        # Run playbook
        engine = get_playbook_engine()
        result = asyncio.run(engine.run(
            name=args.playbook,
            target=args.target,
        ))
        click.echo(json.dumps(result, indent=2))
        return

    # ====================================================================
    # MCP server: itzraven mcp serve
    # ====================================================================
    if args.command == "mcp":
        if args.mcp_command == "serve":
            from itzraven.core.mcp_server import get_mcp_server
            click.secho("🧩 Itzraven MCP Server — connect via Claude Desktop / Cursor", fg="cyan", bold=True)
            click.echo("Listening on stdio...")
            mcp = get_mcp_server()
            asyncio.run(mcp.run_stdio())
        return

    # ====================================================================
    # Playbook commands: itzraven playbook list|run
    # ====================================================================
    if args.command == "playbook":
        from itzraven.core.playbook_engine import get_playbook_engine
        engine = get_playbook_engine()

        if args.pb_command == "list":
            click.secho("📋 Available Playbooks:", fg="cyan", bold=True)
            for pb in engine.list_playbooks():
                click.echo(f"  • {pb['name']}: {pb['description']} ({pb['steps']} steps)")
            return

        if args.pb_command == "run":
            click.secho(f"🐝 Running playbook: {args.name} → {args.target}", fg="yellow", bold=True)
            result = asyncio.run(engine.run(name=args.name, target=args.target))
            click.echo(json.dumps(result, indent=2))
            return

        click.echo("Usage: itzraven playbook list|run")
        return


if __name__ == "__main__":
    main()
