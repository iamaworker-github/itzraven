"""
MCP Server — JSON-RPC 2.0 over stdio for Claude Desktop, Cursor, VS Code.
Pentest-Swarm-AI inspired: agents ko external AI tools se control kar sakte hain.
"""
import json
import sys
import asyncio
import uuid
from typing import Dict, Any, Optional, Callable
from datetime import datetime

from itzraven.core.swarm.blackboard import get_blackboard, BlackboardEntry, BlackboardQuery
from itzraven.core.swarm.scheduler import SwarmScheduler, SwarmContext
from itzraven.core.logger import get_logger

logger = get_logger()


class MCPServer:
    """Model Context Protocol server — JSON-RPC 2.0 over stdio.
    
    Tools exposed:
    - scan(target, scope, mode) — Launch scan
    - list_findings(target, min_severity) — Query findings
    - get_recommendations(target) — AI recommendations
    - get_blackboard_state(target) — View swarm state
    - run_playbook(name, target) — Run a playbook
    """

    def __init__(self):
        self._tools: Dict[str, Callable] = {}
        self._request_id = 0
        self._register_default_tools()

    def _register_default_tools(self):
        self.register_tool("scan", self._tool_scan, {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "scope": {"type": "string"},
                "mode": {"type": "string", "enum": ["swarm", "pentest", "quick"]},
            },
            "required": ["target"],
        })
        self.register_tool("list_findings", self._tool_list_findings, {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "min_weight": {"type": "number"},
                "finding_type": {"type": "string"},
            },
        })
        self.register_tool("get_recommendations", self._tool_recommendations, {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "technologies": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["target"],
        })
        self.register_tool("blackboard_state", self._tool_blackboard_state, {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
            },
        })
        self.register_tool("run_playbook", self._tool_run_playbook, {
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "target": {"type": "string"},
            },
            "required": ["name", "target"],
        })

    def register_tool(self, name: str, handler: Callable, schema: dict):
        self._tools[name] = (handler, schema)

    async def _tool_scan(self, params: dict) -> dict:
        target = params["target"]
        scope = params.get("scope", target)
        mode = params.get("mode", "swarm")

        from itzraven.core.swarm.scheduler import SwarmScheduler, SwarmContext
        from itzraven.agents.modes.pentest import PentestOrchestrator

        board = get_blackboard()
        scheduler = SwarmScheduler(board)

        # Register trigger agents
        await self._register_swarm_agents(scheduler, target)

        context = SwarmContext(
            target=target,
            scan_id=f"mcp_{uuid.uuid4().hex[:8]}",
            mode=mode,
            scan_depth="deep",
            blackboard=board,
        )

        results = await scheduler.run(context)
        return {
            "status": "completed",
            "scan_id": context.scan_id,
            "findings_count": len(results),
            "elapsed": datetime.now().isoformat(),
        }

    async def _register_swarm_agents(self, scheduler: SwarmScheduler, target: str):
        from itzraven.core.swarm.scheduler import SwarmAgent
        from itzraven.core.swarm.trigger import (
            RECON_TRIGGER, TECH_DISCOVERY_TRIGGER, VULN_SCAN_TRIGGER,
            CVE_MATCH_TRIGGER, EXPLOIT_TRIGGER, CHAIN_TRIGGER,
        )
        from itzraven.core.swarm.blackboard import BlackboardEntry

        # Recon agent
        async def recon_handler(entry, ctx):
            board = ctx["blackboard"]
            board.write(BlackboardEntry(
                finding_type="SUBDOMAIN",
                agent_name="recon",
                target=ctx["target"],
                title=f"Recon started for {ctx['target']}",
                data={"tool": "ai_recon"},
                pheromone_base=0.8,
                half_life_sec=600,
            ))
            return [{"agent": "recon", "status": "started"}]

        scheduler.register_agent(SwarmAgent(
            name="recon",
            trigger=RECON_TRIGGER,
            handler=recon_handler,
            max_concurrency=1,
        ))

        # Vuln scan trigger (tech found → scan)
        async def vuln_scan_handler(entry, ctx):
            return [{"agent": "vuln_scan", "trigger": entry.finding_type}]

        scheduler.register_agent(SwarmAgent(
            name="vuln_scanner",
            trigger=VULN_SCAN_TRIGGER,
            handler=vuln_scan_handler,
        ))

    async def _tool_list_findings(self, params: dict) -> dict:
        board = get_blackboard()
        query = BlackboardQuery(
            target=params.get("target"),
            min_weight=params.get("min_weight", 0.05),
            finding_types=[params["finding_type"]] if params.get("finding_type") else None,
        )
        entries = board.query(query)
        return {
            "count": len(entries),
            "findings": [e.to_dict() for e in entries],
        }

    async def _tool_recommendations(self, params: dict) -> dict:
        target = params["target"]
        board = get_blackboard()
        entries = board.query(BlackboardQuery(target=target, min_weight=0.1))

        types_found = set(e.finding_type for e in entries)
        recommendations = []

        if "PORT_OPEN" in types_found:
            recommendations.append("Ports open → run service enumeration + vulnerability scan")
        if "TECHNOLOGY" in types_found:
            recommendations.append("Technologies detected → check for known CVEs")
        if "HTTP_ENDPOINT" in types_found and "VULNERABILITY" not in types_found:
            recommendations.append("Endpoints found but no vulnerabilities yet → run web agent scan")

        return {
            "target": target,
            "recommendations": recommendations,
            "active_findings": len(entries),
        }

    async def _tool_blackboard_state(self, params: dict) -> dict:
        board = get_blackboard()
        stats = board.get_stats()
        if params.get("target"):
            entries = board.query(BlackboardQuery(target=params["target"], min_weight=0.0))
            stats["target_entries"] = len(entries)
            stats["by_type"] = {}
            for e in entries:
                stats["by_type"][e.finding_type] = stats["by_type"].get(e.finding_type, 0) + 1
        return stats

    async def _tool_run_playbook(self, params: dict) -> dict:
        from itzraven.core.playbook_engine import get_playbook_engine
        engine = get_playbook_engine()
        result = await engine.run(params["name"], params["target"])
        return result

    async def handle_request(self, request: dict) -> dict:
        req_id = request.get("id", 0)
        method = request.get("method", "")
        params = request.get("params", {})

        if method == "mcp.list_tools":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "tools": [
                        {
                            "name": name,
                            "description": handler.__doc__ or "",
                            "inputSchema": schema,
                        }
                        for name, (handler, schema) in self._tools.items()
                    ]
                },
            }

        if method == "mcp.call_tool":
            tool_name = params.get("name", "")
            tool_params = params.get("arguments", {})
            if tool_name in self._tools:
                handler, _ = self._tools[tool_name]
                try:
                    result = await handler(tool_params)
                    return {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {"content": [{"type": "text", "text": json.dumps(result, indent=2)}]},
                    }
                except Exception as e:
                    return {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "error": {"code": -32000, "message": str(e)},
                    }
            else:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32601, "message": f"Unknown tool: {tool_name}"},
                }

        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32601, "message": f"Unknown method: {method}"},
        }

    async def run_stdio(self):
        """Run MCP server over stdin/stdout (for Claude Desktop, Cursor)."""
        while True:
            try:
                line = sys.stdin.readline()
                if not line:
                    break
                line = line.strip()
                if not line:
                    continue
                request = json.loads(line)
                response = await self.handle_request(request)
                sys.stdout.write(json.dumps(response) + "\n")
                sys.stdout.flush()
            except json.JSONDecodeError as e:
                sys.stdout.write(json.dumps({
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": f"Parse error: {e}"},
                }) + "\n")
                sys.stdout.flush()
            except Exception as e:
                logger.debug(f"MCP error: {e}")


_instance_mcp: Optional[MCPServer] = None


def get_mcp_server() -> MCPServer:
    global _instance_mcp
    if _instance_mcp is None:
        _instance_mcp = MCPServer()
    return _instance_mcp
