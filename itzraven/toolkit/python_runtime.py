"""
Python runtime sandbox for executing exploit code
"""

import asyncio
import sys
import io
from typing import Optional, Dict, Any
from dataclasses import dataclass
from datetime import datetime
from contextlib import redirect_stdout, redirect_stderr
from itzraven.core.logger import get_logger

logger = get_logger()


@dataclass
class PythonExecutionResult:
    """Result of Python code execution"""
    code: str
    stdout: str
    stderr: str
    return_value: Any
    exception: Optional[str]
    execution_time: float
    timestamp: datetime


class PythonRuntime:
    """Sandboxed Python runtime for exploit development"""

    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.execution_history: list = []

        # Safe builtins (restricted environment)
        self.safe_builtins = {
            'print': print,
            'len': len,
            'str': str,
            'int': int,
            'float': float,
            'bool': bool,
            'list': list,
            'dict': dict,
            'tuple': tuple,
            'set': set,
            'range': range,
            'enumerate': enumerate,
            'zip': zip,
            'map': map,
            'filter': filter,
            'sorted': sorted,
            'sum': sum,
            'min': min,
            'max': max,
            'abs': abs,
            'round': round,
        }

    async def execute(self, code: str, globals_dict: Optional[Dict] = None) -> PythonExecutionResult:
        """Execute Python code in sandboxed environment"""
        start_time = asyncio.get_event_loop().time()

        stdout_capture = io.StringIO()
        stderr_capture = io.StringIO()

        # Prepare globals
        exec_globals = self.safe_builtins.copy()
        if globals_dict:
            exec_globals.update(globals_dict)

        return_value = None
        exception_str = None

        try:
            # Redirect stdout/stderr
            with redirect_stdout(stdout_capture), redirect_stderr(stderr_capture):
                # Compile and execute
                compiled_code = compile(code, '<string>', 'exec')
                exec(compiled_code, exec_globals)

                # Get return value if any
                if 'result' in exec_globals:
                    return_value = exec_globals['result']

        except Exception as e:
            exception_str = f"{type(e).__name__}: {str(e)}"
            logger.error(f"Python execution error: {exception_str}")

        execution_time = asyncio.get_event_loop().time() - start_time

        result = PythonExecutionResult(
            code=code,
            stdout=stdout_capture.getvalue(),
            stderr=stderr_capture.getvalue(),
            return_value=return_value,
            exception=exception_str,
            execution_time=execution_time,
            timestamp=datetime.now()
        )

        self.execution_history.append(result)
        return result

    async def execute_exploit(self, exploit_code: str, target_url: str) -> PythonExecutionResult:
        """Execute exploit code against a target"""
        # Inject target URL into globals
        globals_dict = {
            'target_url': target_url,
            'TARGET': target_url,
        }

        logger.info(f"Executing exploit against: {target_url}")
        return await self.execute(exploit_code, globals_dict)

    async def test_payload(self, payload_generator: str) -> list:
        """Execute payload generator code and return payloads"""
        result = await self.execute(payload_generator)

        if result.exception:
            logger.error(f"Payload generation failed: {result.exception}")
            return []

        # Try to extract payloads from result
        if isinstance(result.return_value, list):
            return result.return_value

        return []

    def get_history(self) -> list:
        """Get execution history"""
        return self.execution_history.copy()

    def clear_history(self) -> None:
        """Clear execution history"""
        self.execution_history.clear()
