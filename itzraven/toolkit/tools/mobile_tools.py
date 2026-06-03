"""
Mobile security tool wrappers: MobSF, Frida
"""

from typing import Dict, Any, Optional
from itzraven.core.tool_runner import ToolRunner, ToolOutput
from itzraven.core.logger import get_logger

logger = get_logger()


class MobSFTool:
    def __init__(self, runner: Optional[ToolRunner] = None):
        self.runner = runner or ToolRunner()

    async def scan_apk(self, apk_path: str, timeout: int = 600) -> ToolOutput:
        return await self.runner.execute(
            "mobile_security.MobSF",
            command=f"mobsf scan --file {apk_path} --json",
            timeout=timeout,
        )

    async def scan_ipa(self, ipa_path: str, timeout: int = 600) -> ToolOutput:
        return await self.runner.execute(
            "mobile_security.MobSF",
            command=f"mobsf scan --file {ipa_path} --json",
            timeout=timeout,
        )


class FridaTool:
    def __init__(self, runner: Optional[ToolRunner] = None):
        self.runner = runner or ToolRunner()

    async def list_apps(self, timeout: int = 30) -> ToolOutput:
        return await self.runner.execute(
            "mobile_security.Frida",
            command="frida-ps -Uai",
            timeout=timeout,
        )

    async def run_script(self, app: str, script_path: str,
                         timeout: int = 60) -> ToolOutput:
        return await self.runner.execute(
            "mobile_security.Frida",
            command=f"frida -U -f {app} -l {script_path}",
            timeout=timeout,
            force=True,
        )
