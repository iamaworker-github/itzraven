"""
MCP (Model Context Protocol) Integration — tool interoperability.

Connects to MCP servers exposing security tools (Nuclei, Burp, Metasploit, etc.)
as model-agnostic tools that any LLM can invoke.
"""

import json
import asyncio
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from itzraven.core.logger import get_logger

logger = get_logger()
MCP_ENABLED = os.environ.get("MCP_ENABLED", "false").lower() in ("true", "1", "yes")


@dataclass
class MCPTool:
    name: str
    description: str
    input_schema: Dict[str, Any] = field(default_factory=dict)
    server: str = ""


@dataclass
class MCPResult:
    success: bool
    output: str
    tool: str = ""
    server: str = ""
    error: str = ""


class MCPServer:
    def __init__(self, name: str, command: str, args: Optional[List[str]] = None, env: Optional[Dict[str, str]] = None):
        self.name = name
        self.command = command
        self.args = args or []
        self.env = env or {}
        self._process: Optional[asyncio.subprocess.Process] = None
        self._tools: Dict[str, MCPTool] = {}

    async def connect(self) -> bool:
        try:
            env = {**os.environ, **self.env}
            self._process = await asyncio.create_subprocess_exec(
                self.command, *self.args,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
            )
            resp = await self._send({"type": "list_tools"})
            if resp and isinstance(resp, dict):
                for t in resp.get("tools", []):
                    self._tools[t["name"]] = MCPTool(name=t["name"], description=t.get("description", ""), input_schema=t.get("inputSchema", {}), server=self.name)
            logger.info(f"MCP server connected: {self.name} ({len(self._tools)} tools)")
            return True
        except Exception as e:
            logger.debug(f"MCP server {self.name} connect failed: {e}")
            return False

    async def call_tool(self, name: str, params: Dict[str, Any]) -> MCPResult:
        if name not in self._tools:
            return MCPResult(success=False, output="", tool=name, server=self.name, error=f"Unknown tool: {name}")
        try:
            resp = await self._send({"type": "call_tool", "tool": name, "params": params})
            if isinstance(resp, dict):
                return MCPResult(success=resp.get("success", True), output=str(resp.get("output", "")), tool=name, server=self.name)
            return MCPResult(success=True, output=str(resp), tool=name, server=self.name)
        except Exception as e:
            return MCPResult(success=False, output="", tool=name, server=self.name, error=str(e))

    async def _send(self, msg: Dict[str, Any]) -> Optional[Any]:
        if not self._process or not self._process.stdin:
            return None
        try:
            payload = (json.dumps(msg) + "\n").encode()
            self._process.stdin.write(payload)
            await self._process.stdin.drain()
            line = await asyncio.wait_for(self._process.stdout.readline(), timeout=30)
            return json.loads(line.decode())
        except Exception:
            return None

    async def disconnect(self):
        if self._process:
            self._process.terminate()
            try:
                await asyncio.wait_for(self._process.wait(), timeout=5)
            except asyncio.TimeoutError:
                self._process.kill()
            self._process = None


class MCPManager:
    _instance: Optional["MCPManager"] = None

    def __init__(self):
        self._servers: Dict[str, MCPServer] = {}
        self._tool_map: Dict[str, str] = {}  # tool_name -> server_name

    def register_server(self, server: MCPServer):
        self._servers[server.name] = server

    async def connect_all(self) -> int:
        if not MCP_ENABLED:
            return 0
        connected = 0
        for name, server in self._servers.items():
            if await server.connect():
                connected += 1
                for tname in server._tools:
                    self._tool_map[tname] = name
        logger.info(f"MCP: {connected}/{len(self._servers)} servers connected")
        return connected

    async def call_tool(self, name: str, params: Dict[str, Any]) -> MCPResult:
        server_name = self._tool_map.get(name)
        if not server_name:
            return MCPResult(success=False, output="", tool=name, error=f"No MCP server provides tool '{name}'")
        server = self._servers.get(server_name)
        if not server:
            return MCPResult(success=False, output="", tool=name, error=f"MCP server '{server_name}' not found")
        return await server.call_tool(name, params)

    def list_tools(self) -> List[Dict[str, Any]]:
        tools = []
        for server in self._servers.values():
            for t in server._tools.values():
                tools.append({"name": t.name, "description": t.description, "server": t.server})
        return tools

    async def disconnect_all(self):
        for server in self._servers.values():
            await server.disconnect()
        self._tool_map.clear()

    @classmethod
    def get_instance(cls) -> "MCPManager":
        if cls._instance is None:
            cls._instance = MCPManager()
        return cls._instance


_mcp_manager: Optional[MCPManager] = None


def get_mcp_manager() -> MCPManager:
    global _mcp_manager
    if _mcp_manager is None:
        _mcp_manager = MCPManager()
    return _mcp_manager
