import asyncio
from typing import Any, Dict, Optional

from itzraven.core.logger import get_logger
from itzraven.mcp.tools import (
    run_scan, get_status, list_findings, list_tools, get_attack_surface, medusa_scan,
    bounty_search_programs, bounty_get_program, bounty_triage_finding,
    bounty_find_programs, bounty_submit_report,
    health_check, check_tool, diagnose, list_allowed_tools,
    writeup_search, writeup_get, writeup_techniques, writeup_payloads, writeup_ingest,
)
from itzraven.mcp.transports import handle_stdio, handle_sse

logger = get_logger()


class MCPApp:
    def __init__(self):
        self._send_callback = None

    def set_send_callback(self, callback):
        self._send_callback = callback

    async def process_message(self, msg: Dict[str, Any]) -> Dict[str, Any]:
        method = msg.get("method", "")
        params = msg.get("params", {})
        msg_id = msg.get("id")

        try:
            if method == "run_scan":
                result = await run_scan(
                    target=params["target"],
                    mode=params.get("mode", "auto"),
                    depth=params.get("depth", "deep"),
                )
                return {"id": msg_id, "result": result}
            elif method == "get_status":
                result = await get_status(scan_id=params["scan_id"])
                return {"id": msg_id, "result": result}
            elif method == "list_findings":
                result = await list_findings(scan_id=params["scan_id"])
                return {"id": msg_id, "result": result}
            elif method == "list_tools":
                result = await list_tools()
                return {"id": msg_id, "result": result}
            elif method == "get_attack_surface":
                result = await get_attack_surface(scan_id=params["scan_id"])
                return {"id": msg_id, "result": result}
            elif method == "medusa_scan":
                result = await medusa_scan(
                    target=params["target"],
                    git_mode=params.get("git_mode", False),
                )
                return {"id": msg_id, "result": result}
            elif method == "bounty_search_programs":
                result = await bounty_search_programs(
                    platform=params["platform"],
                    query=params.get("query", ""),
                )
                return {"id": msg_id, "result": result}
            elif method == "bounty_get_program":
                result = await bounty_get_program(
                    platform=params["platform"],
                    name=params["name"],
                )
                return {"id": msg_id, "result": result}
            elif method == "bounty_triage_finding":
                result = await bounty_triage_finding(
                    finding_dict=params["finding"],
                )
                return {"id": msg_id, "result": result}
            elif method == "bounty_find_programs":
                result = await bounty_find_programs(
                    target=params["target"],
                )
                return {"id": msg_id, "result": result}
            elif method == "bounty_submit_report":
                result = await bounty_submit_report(
                    platform=params["platform"],
                    report_data=params["report"],
                )
                return {"id": msg_id, "result": result}
            elif method == "health_check":
                result = await health_check()
                return {"id": msg_id, "result": result}
            elif method == "check_tool":
                result = await check_tool(tool_name=params["tool_name"])
                return {"id": msg_id, "result": result}
            elif method == "diagnose":
                result = await diagnose()
                return {"id": msg_id, "result": result}
            elif method == "list_allowed_tools":
                result = await list_allowed_tools()
                return {"id": msg_id, "result": result}
            elif method == "writeup_search":
                result = await writeup_search(
                    query=params.get("query", ""),
                    technique=params.get("technique", ""),
                    k=params.get("k", 5),
                )
                return {"id": msg_id, "result": result}
            elif method == "writeup_get":
                result = await writeup_get(writeup_id=params["writeup_id"])
                return {"id": msg_id, "result": result}
            elif method == "writeup_techniques":
                result = await writeup_techniques(vuln_class=params["vuln_class"])
                return {"id": msg_id, "result": result}
            elif method == "writeup_payloads":
                result = await writeup_payloads(vuln_class=params["vuln_class"])
                return {"id": msg_id, "result": result}
            elif method == "writeup_ingest":
                result = await writeup_ingest(
                    source=params["source"],
                    title=params["title"],
                    description=params.get("description", ""),
                    technique=params.get("technique", ""),
                    severity=params.get("severity", "medium"),
                    content=params.get("content", ""),
                )
                return {"id": msg_id, "result": result}
            elif method == "ping":
                return {"id": msg_id, "result": "pong"}
            else:
                return {"id": msg_id, "error": f"Unknown method: {method}"}
        except KeyError as e:
            return {"id": msg_id, "error": f"Missing parameter: {e}"}
        except Exception as e:
            return {"id": msg_id, "error": str(e)}


def create_mcp_server() -> MCPApp:
    return MCPApp()


async def run_mcp_server(transport: str = "stdio", port: int = 8000) -> None:
    app = create_mcp_server()
    logger.info(f"Starting MCP server ({transport} transport)")

    if transport == "stdio":
        await handle_stdio(app)
    elif transport == "sse":
        await handle_sse(app, port=port)
    else:
        raise ValueError(f"Unknown transport: {transport}")
