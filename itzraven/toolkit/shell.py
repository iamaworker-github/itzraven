"""
Terminal shell executor for command execution
"""

import asyncio
import os
import shlex
from typing import Optional, Dict, Any, List
from dataclasses import dataclass
from datetime import datetime
from itzraven.core.config import get_config
from itzraven.core.logger import get_logger
from itzraven.core.scope import ScopeValidator

logger = get_logger()


@dataclass
class CommandResult:
    """Result of a shell command execution"""
    command: str
    stdout: str
    stderr: str
    return_code: int
    execution_time: float
    timestamp: datetime


class ShellExecutor:
    """Execute shell commands in a controlled environment"""

    def __init__(self, timeout: int = 30, working_dir: Optional[str] = None, scope_validator: Optional[ScopeValidator] = None):
        self.timeout = timeout
        self.working_dir = working_dir
        self.command_history: List[CommandResult] = []
        self.scope_validator = scope_validator

    async def execute(self, command: str, env: Optional[Dict[str, str]] = None) -> CommandResult:
        """Execute a shell command"""
        start_time = asyncio.get_event_loop().time()

        if self.scope_validator and not self.scope_validator.validate_command(command):
            logger.warning(f"Scope violation blocked: {command}")
            return CommandResult(
                command=command, stdout="", stderr="SCOPE_VIOLATION: Command target is out of scope",
                return_code=-1, execution_time=0.0, timestamp=datetime.now()
            )

        try:
            config = get_config()
            cmd_parts = shlex.split(command)
            subprocess_cwd = self.working_dir
            subprocess_env = env

            if config.get("use_docker"):
                docker_image = config.get("docker_image")
                host_workdir = os.path.abspath(self.working_dir or os.getcwd())
                container_workdir = "/workspace"

                cmd_parts = [
                    "docker",
                    "run",
                    "--rm",
                    "-v",
                    f"{host_workdir}:{container_workdir}",
                    "-w",
                    container_workdir,
                ]

                if env:
                    for key, value in env.items():
                        cmd_parts.extend(["-e", f"{key}={value}"])

                cmd_parts.extend([docker_image, "sh", "-lc", command])
                subprocess_cwd = None
                subprocess_env = None

            # Create subprocess
            process = await asyncio.create_subprocess_exec(
                *cmd_parts,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=subprocess_cwd,
                env=subprocess_env
            )

            # Wait for completion with timeout
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=self.timeout
                )
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                raise TimeoutError(f"Command timed out after {self.timeout}s")

            execution_time = asyncio.get_event_loop().time() - start_time

            result = CommandResult(
                command=command,
                stdout=stdout.decode('utf-8', errors='replace'),
                stderr=stderr.decode('utf-8', errors='replace'),
                return_code=process.returncode,
                execution_time=execution_time,
                timestamp=datetime.now()
            )

            self.command_history.append(result)

            if result.return_code == 0:
                logger.debug(f"Command executed: {command}")
            else:
                logger.warning(f"Command failed (code {result.return_code}): {command}")

            return result

        except Exception as e:
            logger.error(f"Command execution error: {e}")
            execution_time = asyncio.get_event_loop().time() - start_time

            result = CommandResult(
                command=command,
                stdout="",
                stderr=str(e),
                return_code=-1,
                execution_time=execution_time,
                timestamp=datetime.now()
            )
            self.command_history.append(result)
            return result

    async def execute_multiple(self, commands: List[str]) -> List[CommandResult]:
        """Execute multiple commands sequentially"""
        results = []
        for cmd in commands:
            result = await self.execute(cmd)
            results.append(result)
            # Stop on first failure
            if result.return_code != 0:
                logger.warning(f"Stopping execution chain due to failure")
                break
        return results

    async def test_command_injection(self, base_command: str, injection: str) -> bool:
        """Test for command injection vulnerability"""
        try:
            # Try to inject command
            malicious_cmd = f"{base_command} {injection}"
            result = await self.execute(malicious_cmd)

            # Check if injection was successful
            if "injected" in result.stdout.lower() or result.return_code == 0:
                logger.warning(f"Potential command injection: {injection}")
                return True
            return False
        except Exception:
            return False

    def get_history(self) -> List[CommandResult]:
        """Get command execution history"""
        return self.command_history.copy()

    def clear_history(self) -> None:
        """Clear command history"""
        self.command_history.clear()
