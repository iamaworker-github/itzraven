"""
Itzraven MCP Tool Exposer — Exposes Itzraven pentest capabilities as MCP tools.
Allows any MCP client (Claude Code, Hermes, etc.) to use Itzraven for scanning.
"""
import json
import asyncio
from typing import Any, Dict, List, Optional
from pathlib import Path

from itzraven.core.logger import get_logger

logger = get_logger()


MCP_TOOLS = [
    {
        "name": "itzraven_scan",
        "description": "Run a security scan on a target (URL/domain/IP/directory)",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target to scan (URL, domain, IP, or directory path)"},
                "scan_depth": {"type": "string", "enum": ["quick", "standard", "deep"], "default": "deep"},
                "mode": {"type": "string", "enum": ["pentest", "bugbounty", "osint", "ctf"], "default": "pentest"},
                "sub_mode": {"type": "string", "enum": ["whitebox", "blackbox"], "default": None},
                "instruction": {"type": "string", "description": "Custom focus instructions"},
                "parallel": {"type": "boolean", "default": False},
            },
            "required": ["target"],
        },
    },
    {
        "name": "itzraven_skill_search",
        "description": "Search through 3400+ security skills by keyword or vulnerability type",
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Search query (e.g., 'sqli', 'xss', 'cloud')"},
                "category": {"type": "string", "description": "Filter by category"},
                "max_results": {"type": "integer", "default": 10},
            },
            "required": ["query"],
        },
    },
    {
        "name": "itzraven_target_memory",
        "description": "Get past scan history and findings for a target from cross-session memory",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target URL/domain to look up"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "itzraven_learned_skills",
        "description": "List all auto-generated pentest skills learned from past findings",
        "input_schema": {
            "type": "object",
            "properties": {},
        },
    },
]


async def handle_mcp_call(tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
    if tool_name == "itzraven_scan":
        return await _handle_scan(arguments)
    elif tool_name == "itzraven_skill_search":
        return _handle_skill_search(arguments)
    elif tool_name == "itzraven_target_memory":
        return _handle_target_memory(arguments)
    elif tool_name == "itzraven_learned_skills":
        return _handle_learned_skills()
    return {"error": f"Unknown tool: {tool_name}"}


async def _handle_scan(args: Dict) -> Dict:
    from itzraven.agents.modes.pentest import PentestOrchestrator

    target = args["target"]
    depth = args.get("scan_depth", "deep")
    mode = args.get("mode", "pentest")
    sub_mode = args.get("sub_mode", None)
    instruction = args.get("instruction", None)
    parallel = args.get("parallel", False)

    orch = PentestOrchestrator(target=target, scan_depth=depth, sub_mode=sub_mode, instruction=instruction)
    orch.load_agents()

    result = await orch.run_parallel() if parallel else await orch.run_sequential()

    return {
        "target": target,
        "total_findings": result.total_findings,
        "severity_breakdown": result.findings_by_severity,
        "findings": [f.to_dict() for f in result.all_findings[:20]],
        "duration_seconds": result.duration,
    }


def _handle_skill_search(args: Dict) -> Dict:
    from itzraven.skills.registry import get_skill_registry

    registry = get_skill_registry()
    query = args["query"]
    max_results = args.get("max_results", 10)

    results = registry.get_by_tag(query, max_count=max_results)
    return {
        "query": query,
        "count": len(results),
        "results": [{"name": s.name, "description": s.description[:150], "category": s.category} for s in results],
    }


def _handle_target_memory(args: Dict) -> Dict:
    from itzraven.core.memory import get_memory

    memory = get_memory()
    target = args["target"]
    history = memory.get_target_history(target)
    past = memory.get_past_findings(target)
    return {
        "target": target,
        "history": history,
        "past_findings": past[:10],
    }


def _handle_learned_skills() -> Dict:
    from itzraven.core.skill_learner import get_skill_learner

    learner = get_skill_learner()
    skills = learner.get_all_learned()
    return {"count": len(skills), "skills": skills}


def get_mcp_tools_json() -> str:
    return json.dumps({"tools": MCP_TOOLS})
