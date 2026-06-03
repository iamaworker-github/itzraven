"""
Active Directory tool wrappers: Certipy, Kerbrute, Responder, BloodHound, Impacket
"""

from typing import Dict, Any, Optional
from itzraven.core.tool_runner import ToolRunner, ToolOutput
from itzraven.core.logger import get_logger

logger = get_logger()


class CertipyTool:
    def __init__(self, runner: Optional[ToolRunner] = None):
        self.runner = runner or ToolRunner()

    async def find(self, target: str, user: str = "", password: str = "",
                   timeout: int = 300) -> ToolOutput:
        args = f"find -target {target}"
        if user:
            args += f" -u {user}"
        if password:
            args += f" -p {password}"
        return await self.runner.execute(
            "active_directory.Certipy",
            args=args,
            timeout=timeout,
        )


class KerbruteTool:
    def __init__(self, runner: Optional[ToolRunner] = None):
        self.runner = runner or ToolRunner()

    async def brute_user(self, domain: str, wordlist: str,
                         timeout: int = 300) -> ToolOutput:
        return await self.runner.execute(
            "active_directory.Kerbrute",
            args=f"userenum -d {domain} {wordlist}",
            timeout=timeout,
        )


class ResponderTool:
    def __init__(self, runner: Optional[ToolRunner] = None):
        self.runner = runner or ToolRunner()

    async def analyze(self, interface: str = "eth0",
                     timeout: int = 60) -> ToolOutput:
        return await self.runner.execute(
            "active_directory.Responder",
            args=f"-I {interface} -A",
            timeout=timeout,
        )


class BloodHoundTool:
    def __init__(self, runner: Optional[ToolRunner] = None):
        self.runner = runner or ToolRunner()

    async def collect(self, target: str, method: str = "all",
                     timeout: int = 600) -> ToolOutput:
        args = f"-c {method} -d {target}"
        return await self.runner.execute(
            "active_directory.BloodHound",
            args=args,
            timeout=timeout,
        )


class ImpacketTool:
    def __init__(self, runner: Optional[ToolRunner] = None):
        self.runner = runner or ToolRunner()

    async def run(self, module: str, args: str = "",
                  timeout: int = 120) -> ToolOutput:
        return await self.runner.execute(
            "active_directory.Impacket",
            command=f"{module} {args}",
            timeout=timeout,
        )
