import asyncio
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from itzraven.core.logger import get_logger

logger = get_logger()

CTF_SANDBOX_IMAGE = os.environ.get("CTF_SANDBOX_IMAGE", "itzraven-ctf-sandbox:latest")
CTF_SANDBOX_TIMEOUT = int(os.environ.get("CTF_SANDBOX_TIMEOUT", "1800"))
CTF_SANDBOX_MEMORY = os.environ.get("CTF_SANDBOX_MEMORY", "1024m")
CTF_SANDBOX_CPU = os.environ.get("CTF_SANDBOX_CPU", "2.0")
CTF_SANDBOX_NETWORK = os.environ.get("CTF_SANDBOX_NETWORK", "none")


class CtfSandbox:
    def __init__(
        self,
        image: str = CTF_SANDBOX_IMAGE,
        timeout: int = CTF_SANDBOX_TIMEOUT,
        memory: str = CTF_SANDBOX_MEMORY,
        cpu: str = CTF_SANDBOX_CPU,
        network: str = CTF_SANDBOX_NETWORK,
    ):
        self.image = image
        self.timeout = timeout
        self.memory = memory
        self.cpu = cpu
        self.network = network
        self._containers: Dict[str, str] = {}
        self._tasks: Dict[str, asyncio.Task] = {}
        self._available: bool = True
        self._temp_dirs: Dict[str, str] = {}

    @property
    def available(self) -> bool:
        return self._available

    async def _check_docker(self) -> bool:
        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "info",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
            if proc.returncode != 0:
                self._available = False
                logger.warning("Docker is not available, sandbox disabled")
                return False
            return True
        except FileNotFoundError:
            self._available = False
            logger.warning("Docker not found, sandbox disabled")
            return False

    async def start_sandbox(self, solver_id: str) -> Optional[str]:
        if not self._available:
            await self._check_docker()
            if not self._available:
                return None

        container_name = f"itzraven-ctf-{solver_id}"
        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "run", "-d", "--rm",
                "--memory", self.memory,
                "--cpus", self.cpu,
                "--network", self.network,
                "--name", container_name,
                self.image,
                "sleep", "infinity",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=60)
            if proc.returncode != 0:
                err = stderr.decode().strip()
                logger.warning(f"Sandbox start failed for {solver_id}: {err[:200]}")
                return None

            container_id = stdout.decode().strip()
            self._containers[solver_id] = container_name

            timeout_task = asyncio.create_task(self._timeout_watchdog(solver_id))
            self._tasks[solver_id] = timeout_task

            logger.info(f"CTF sandbox started for {solver_id}: {container_id[:12]}")
            return container_name
        except asyncio.TimeoutError:
            logger.warning(f"Sandbox start timed out for {solver_id}")
            return None
        except Exception as e:
            logger.error(f"Failed to start sandbox for {solver_id}: {e}")
            return None

    async def _timeout_watchdog(self, solver_id: str):
        await asyncio.sleep(self.timeout)
        if solver_id in self._containers:
            logger.warning(f"Sandbox timeout for {solver_id}, killing container")
            await self.stop_sandbox(solver_id)

    async def stop_sandbox(self, solver_id: str):
        container_name = self._containers.pop(solver_id, None)
        if container_name is None:
            return

        if solver_id in self._tasks:
            self._tasks[solver_id].cancel()
            del self._tasks[solver_id]

        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "rm", "-f", container_name,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await proc.communicate()
            logger.info(f"Sandbox stopped for {solver_id}")
        except Exception as e:
            logger.debug(f"Failed to stop sandbox {solver_id}: {e}")

        temp_dir = self._temp_dirs.pop(solver_id, None)
        if temp_dir:
            try:
                for root, dirs, files in os.walk(temp_dir, topdown=False):
                    for name in files:
                        os.remove(os.path.join(root, name))
                    for name in dirs:
                        os.rmdir(os.path.join(root, name))
                os.rmdir(temp_dir)
            except Exception:
                pass

    async def run_in_sandbox(self, solver_id: str, command: str, timeout: Optional[int] = None) -> Dict[str, Any]:
        container_name = self._containers.get(solver_id)
        if container_name is None:
            return {"exit_code": -1, "stdout": "", "stderr": "Sandbox not running", "success": False}

        effective_timeout = timeout or self.timeout
        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "exec", container_name,
                "sh", "-c", command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=effective_timeout)
            stdout_str = stdout.decode("utf-8", errors="replace")
            stderr_str = stderr.decode("utf-8", errors="replace")
            return {
                "exit_code": proc.returncode or 0,
                "stdout": stdout_str,
                "stderr": stderr_str,
                "success": proc.returncode == 0,
            }
        except asyncio.TimeoutError:
            logger.warning(f"Command timed out in sandbox {solver_id}: {command[:100]}")
            return {"exit_code": -1, "stdout": "", "stderr": "timeout", "success": False}
        except Exception as e:
            return {"exit_code": -1, "stdout": "", "stderr": str(e), "success": False}

    async def copy_to_sandbox(self, solver_id: str, local_path: str, container_path: str) -> bool:
        container_name = self._containers.get(solver_id)
        if container_name is None:
            return False

        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "cp", local_path, f"{container_name}:{container_path}",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await proc.communicate()
            if proc.returncode != 0:
                logger.warning(f"Copy to sandbox failed: {stderr.decode()[:200]}")
                return False
            return True
        except Exception as e:
            logger.debug(f"Copy to sandbox error: {e}")
            return False

    async def copy_from_sandbox(self, solver_id: str, container_path: str, local_path: str) -> bool:
        container_name = self._containers.get(solver_id)
        if container_name is None:
            return False

        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "cp", f"{container_name}:{container_path}", local_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await proc.communicate()
            if proc.returncode != 0:
                logger.warning(f"Copy from sandbox failed: {stderr.decode()[:200]}")
                return False
            return True
        except Exception as e:
            logger.debug(f"Copy from sandbox error: {e}")
            return False

    async def get_flag(self, solver_id: str, flag_pattern: str = r"flag\{[^}]+\}") -> Optional[str]:
        container_name = self._containers.get(solver_id)
        if container_name is None:
            return None

        cmd = f"grep -roP '{flag_pattern}' / 2>/dev/null || echo ''"
        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "exec", container_name,
                "sh", "-c", cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
            output = stdout.decode("utf-8", errors="replace").strip()
            if not output:
                return None
            flags = re.findall(flag_pattern, output, re.IGNORECASE)
            return flags[0] if flags else None
        except (asyncio.TimeoutError, Exception) as e:
            logger.debug(f"Flag search in {solver_id} failed: {e}")
            return None

    async def health_check(self, solver_id: str) -> bool:
        container_name = self._containers.get(solver_id)
        if container_name is None:
            return False

        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "inspect", "--format", "{{.State.Running}}", container_name,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            return stdout.decode().strip() == "true"
        except Exception:
            return False

    async def cleanup_all(self):
        for solver_id in list(self._containers.keys()):
            await self.stop_sandbox(solver_id)

    def get_tool_list(self) -> Dict[str, List[str]]:
        return {
            "binary": ["radare2", "gdb", "binutils", "strings"],
            "pwn": ["pwntools", "ROPgadget", "one_gadget"],
            "crypto": ["pycryptodome", "z3-solver", "gmpy2"],
            "forensics": ["volatility3", "foremost", "binwalk", "exiftool"],
            "stego": ["steghide", "zsteg"],
            "web": ["curl", "python3-requests"],
            "misc": ["Pillow", "numpy", "exiftool"],
        }

    def get_dockerfile_content(self) -> str:
        return """FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \\
    build-essential \\
    curl \\
    file \\
    binutils \\
    gdb \\
    radare2 \\
    foremost \\
    binwalk \\
    steghide \\
    exiftool \\
    git \\
    wget \\
    xxd \\
    netcat-openbsd \\
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir \\
    pwntools \\
    pycryptodome \\
    z3-solver \\
    gmpy2 \\
    pillow \\
    numpy \\
    requests \\
    capstone \\
    keystone-engine \\
    unicorn \\
    angr

RUN npm install -g zsteg 2>/dev/null || true

RUN git clone --depth 1 https://github.com/volatilityfoundation/volatility3 /opt/volatility3 && \\
    pip install --no-cache-dir -r /opt/volatility3/requirements.txt

RUN pip install --no-cache-dir \\
    ROPgadget \\
    one-gadget

WORKDIR /workspace

CMD ["sleep", "infinity"]
"""


_ctf_sandbox: Optional[CtfSandbox] = None


def get_ctf_sandbox() -> CtfSandbox:
    global _ctf_sandbox
    if _ctf_sandbox is None:
        _ctf_sandbox = CtfSandbox()
    return _ctf_sandbox
