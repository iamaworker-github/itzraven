"""
Autonomous Tool Generator — LLM naya tool/script likhe jab existing tools kaam na kare.
Code-as-tool: agent dynamically naya tool create kare, test kare, use kare.
"""

import json
import tempfile
import subprocess
import os
import time
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field

from itzraven.core.logger import get_logger
from itzraven.agents.llm_client import LLMClient

logger = get_logger()

TOOL_STORE = Path.home() / ".itzraven" / "generated_tools"


@dataclass
class GeneratedTool:
    name: str
    description: str
    code: str
    language: str = "python"
    dependencies: List[str] = field(default_factory=list)
    verified: bool = False
    test_result: Optional[str] = None
    created_at: float = field(default_factory=time.time)
    use_count: int = 0
    success_count: int = 0
    file_path: Optional[str] = None

    def record_usage(self, success: bool):
        self.use_count += 1
        if success:
            self.success_count += 1

    @property
    def reliability(self) -> float:
        return self.success_count / max(self.use_count, 1)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "language": self.language,
            "verified": self.verified,
            "use_count": self.use_count,
            "success_rate": self.reliability,
        }


class ToolGenerator:
    _instance = None

    def __init__(self):
        self.llm = LLMClient()
        self.generated_tools: Dict[str, GeneratedTool] = {}
        TOOL_STORE.mkdir(parents=True, exist_ok=True)
        self._load()

    @classmethod
    def get_instance(cls) -> "ToolGenerator":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    async def generate_tool(self, requirement: str, technique: str,
                             target_context: str = "") -> Optional[GeneratedTool]:
        prompt = (
            f"Generate a Python security testing tool for the following requirement:\n\n"
            f"Requirement: {requirement}\n"
            f"Technique: {technique}\n"
            f"Target context: {target_context}\n\n"
            "The tool should:\n"
            "1. Be a complete, runnable Python script\n"
            "2. Use only standard library + requests/httpx/aiohttp\n"
            "3. Accept target URL as command line argument\n"
            "4. Output results as JSON to stdout\n"
            "5. Handle errors gracefully\n"
            "6. Include timeout handling\n\n"
            "Output JSON:\n"
            "{\n"
            '  "name": "tool_name",\n'
            '  "description": "brief description",\n'
            '  "code": "complete python code",\n'
            '  "dependencies": ["required pip packages"]\n'
            "}"
        )
        system = "You are a security tool developer. Generate clean, working Python tools."

        try:
            resp = await self.llm.generate(prompt=prompt, system=system, max_tokens=3000, task="generate_tool")
            raw = resp.content
            if isinstance(raw, str):
                if raw.startswith("```"):
                    raw = raw.split("```")[1]
                    if raw.startswith("json"):
                        raw = raw[4:].strip()
                parsed = json.loads(raw)
            else:
                parsed = raw
        except Exception as e:
            logger.debug(f"Tool generation failed: {e}")
            return None

        tool = GeneratedTool(
            name=parsed.get("name", f"custom_{technique}_{int(time.time())}"),
            description=parsed.get("description", ""),
            code=parsed.get("code", ""),
            dependencies=parsed.get("dependencies", []),
        )
        self.generated_tools[tool.name] = tool
        self._save_tool(tool)
        self._save_index()

        logger.info(f"ToolGenerator: created '{tool.name}' for {technique}")
        return tool

    async def verify_tool(self, tool: GeneratedTool, test_target: str = "http://localhost:8080") -> bool:
        if not tool.code:
            return False

        code = tool.code.replace("TARGET", test_target).replace("{{target}}", test_target)

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            script_path = f.name

        try:
            result = subprocess.run(
                ["python3", "-c", f"import ast; ast.parse(open('{script_path}').read())"],
                capture_output=True, text=True, timeout=10,
            )
            syntax_ok = result.returncode == 0

            if syntax_ok:
                run_result = subprocess.run(
                    ["python3", script_path, test_target],
                    capture_output=True, text=True, timeout=15,
                )
                tool.test_result = f"Exit: {run_result.returncode}, stdout: {run_result.stdout[:200]}"
                tool.verified = run_result.returncode == 0
            else:
                tool.test_result = f"Syntax error: {result.stderr[:200]}"
                tool.verified = False

        except subprocess.TimeoutExpired:
            tool.test_result = "Timeout during verification"
            tool.verified = False
        except Exception as e:
            tool.test_result = str(e)
            tool.verified = False
        finally:
            os.unlink(script_path)

        logger.info(f"ToolGenerator: verified '{tool.name}' → {tool.verified}")
        return tool.verified

    def get_tool(self, name: str) -> Optional[GeneratedTool]:
        return self.generated_tools.get(name)

    def search_tools(self, query: str) -> List[GeneratedTool]:
        q = query.lower()
        results = []
        for tool in self.generated_tools.values():
            if q in tool.name.lower() or q in tool.description.lower():
                results.append(tool)
        results.sort(key=lambda t: t.reliability, reverse=True)
        return results[:10]

    def get_best_tool(self, technique: str) -> Optional[GeneratedTool]:
        candidates = [t for t in self.generated_tools.values()
                      if technique.lower() in t.description.lower() and t.verified]
        if not candidates:
            return None
        return max(candidates, key=lambda t: t.reliability)

    def _save_tool(self, tool: GeneratedTool):
        tool_dir = TOOL_STORE / tool.name
        tool_dir.mkdir(parents=True, exist_ok=True)
        file_path = tool_dir / "tool.py"
        file_path.write_text(tool.code)
        tool.file_path = str(file_path)
        (tool_dir / "metadata.json").write_text(json.dumps(tool.to_dict(), indent=2))

    def _save_index(self):
        index = {k: v.to_dict() for k, v in self.generated_tools.items()}
        (TOOL_STORE / "index.json").write_text(json.dumps(index, indent=2))

    def _load(self):
        try:
            index_path = TOOL_STORE / "index.json"
            if index_path.exists():
                data = json.loads(index_path.read_text())
                for name, d in data.items():
                    tool = GeneratedTool(name=name, description=d.get("description", ""),
                                         code=d.get("code", ""), language=d.get("language", "python"),
                                         verified=d.get("verified", False), use_count=d.get("use_count", 0))
                    self.generated_tools[name] = tool
                logger.info(f"ToolGenerator: loaded {len(self.generated_tools)} tools")
        except Exception as e:
            logger.debug(f"Failed to load tools: {e}")

    def get_stats(self) -> dict:
        verified = sum(1 for t in self.generated_tools.values() if t.verified)
        return {
            "total_tools": len(self.generated_tools),
            "verified_tools": verified,
            "tools": [t.to_dict() for t in self.generated_tools.values()],
        }


get_tool_generator = ToolGenerator.get_instance
