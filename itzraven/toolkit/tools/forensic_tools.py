"""
Forensic tool wrappers: Binwalk, Volatility, pspy
"""

from typing import Dict, Any, Optional
from itzraven.core.tool_runner import ToolRunner, ToolOutput
from itzraven.core.logger import get_logger

logger = get_logger()


class BinwalkTool:
    def __init__(self, runner: Optional[ToolRunner] = None):
        self.runner = runner or ToolRunner()

    async def analyze(self, filepath: str, timeout: int = 120) -> ToolOutput:
        return await self.runner.execute(
            "forensics.Binwalk",
            args=filepath,
            timeout=timeout,
        )

    async def extract(self, filepath: str, timeout: int = 300) -> ToolOutput:
        return await self.runner.execute(
            "forensics.Binwalk",
            args=f"-e {filepath}",
            timeout=timeout,
        )


class VolatilityTool:
    def __init__(self, runner: Optional[ToolRunner] = None):
        self.runner = runner or ToolRunner()

    async def analyze(self, image_path: str, plugin: str = "windows.info",
                      timeout: int = 300) -> ToolOutput:
        return await self.runner.execute(
            "forensics.Volatility",
            command=f"volatility -f {image_path} {plugin}",
            timeout=timeout,
        )

    async def scan_loop(self, image_path: str) -> Dict[str, Any]:
        result = await self.analyze(image_path)
        info = {"image": image_path, "raw": result.to_dict()}
        if result.is_success():
            info["sections"] = [l.strip() for l in result.stdout.splitlines()[:50]]
        return info


class PspyTool:
    def __init__(self, runner: Optional[ToolRunner] = None):
        self.runner = runner or ToolRunner()

    async def monitor(self, timeout: int = 60) -> ToolOutput:
        return await self.runner.execute(
            "forensics.Pspy",
            command="pspy -i 1",
            timeout=timeout,
        )
