"""
Cloud security tool wrappers: Pacu, Prowler, ScoutSuite, Trivy
"""

from typing import Dict, Any, Optional
from itzraven.core.tool_runner import ToolRunner, ToolOutput
from itzraven.core.logger import get_logger

logger = get_logger()


class PacuTool:
    def __init__(self, runner: Optional[ToolRunner] = None):
        self.runner = runner or ToolRunner()

    async def run_module(self, module: str, args: str = "",
                         timeout: int = 600) -> ToolOutput:
        return await self.runner.execute(
            "cloud_security.Pacu",
            command=f"pacu --module {module} {args}",
            timeout=timeout,
        )


class ProwlerTool:
    def __init__(self, runner: Optional[ToolRunner] = None):
        self.runner = runner or ToolRunner()

    async def scan(self, provider: str = "aws", timeout: int = 600) -> ToolOutput:
        return await self.runner.execute(
            "cloud_security.Prowler",
            args=f"-p {provider}",
            timeout=timeout,
        )


class ScoutSuiteTool:
    def __init__(self, runner: Optional[ToolRunner] = None):
        self.runner = runner or ToolRunner()

    async def scan(self, provider: str = "aws", timeout: int = 600) -> ToolOutput:
        return await self.runner.execute(
            "cloud_security.ScoutSuite",
            args=provider,
            timeout=timeout,
        )


class TrivyTool:
    def __init__(self, runner: Optional[ToolRunner] = None):
        self.runner = runner or ToolRunner()

    async def scan_image(self, image: str, timeout: int = 300) -> ToolOutput:
        return await self.runner.execute(
            "cloud_security.Trivy",
            args=f"image {image}",
            timeout=timeout,
        )

    async def scan_repo(self, path: str, timeout: int = 300) -> ToolOutput:
        return await self.runner.execute(
            "cloud_security.Trivy",
            args=f"fs {path}",
            timeout=timeout,
        )
