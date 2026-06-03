"""
Enhanced ReAct v2 — chain-of-thought with real-time tool execution.
LLM decides: "mujhe X chahiye → tool call → result analyze → next step"
"""

import json
import time
from typing import Dict, List, Optional, Any, Callable, Awaitable
from dataclasses import dataclass, field
from enum import Enum

from itzraven.core.logger import get_logger
from itzraven.agents.llm_client import LLMClient
from itzraven.core.thinking_chain import get_thinking_chain

logger = get_logger()


class ThoughtType(Enum):
    REASONING = "reasoning"
    PLANNING = "planning"
    OBSERVATION = "observation"
    DECISION = "decision"
    CRITIQUE = "critique"
    SUMMARY = "summary"


@dataclass
class Thought:
    content: str
    thought_type: ThoughtType
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {"content": self.content, "type": self.thought_type.value, "timestamp": self.timestamp}


@dataclass
class ToolCall:
    tool_name: str
    params: Dict[str, Any]
    result: Optional[Any] = None
    error: Optional[str] = None
    latency_ms: float = 0.0
    timestamp: float = field(default_factory=time.time)


@dataclass
class ReActStep:
    iteration: int
    thought_chain: List[Thought]
    tool_calls: List[ToolCall]
    final_action: str
    final_params: Dict[str, Any]
    observation: str
    success: bool = False
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "iteration": self.iteration,
            "thoughts": [t.to_dict() for t in self.thought_chain],
            "tool_calls": [{"tool": tc.tool_name, "params": tc.params, "error": tc.error} for tc in self.tool_calls],
            "action": self.final_action,
            "observation": self.observation[:200],
            "success": self.success,
        }


class ToolRegistry:
    def __init__(self):
        self._tools: Dict[str, Dict[str, Any]] = {}
        self._handlers: Dict[str, Callable[..., Awaitable[Any]]] = {}

    def register(self, name: str, description: str, handler: Callable[..., Awaitable[Any]],
                 params_schema: Dict[str, str] = None):
        self._tools[name] = {
            "name": name, "description": description,
            "params_schema": params_schema or {},
        }
        self._handlers[name] = handler

    def get_tool_descriptions(self) -> str:
        lines = []
        for t in self._tools.values():
            params_str = ", ".join(f"{k}: {v}" for k, v in t["params_schema"].items())
            lines.append(f"- {t['name']}: {t['description']} | Params: {{{params_str}}}")
        return "\n".join(lines)

    async def execute(self, name: str, params: Dict[str, Any]) -> Any:
        handler = self._handlers.get(name)
        if not handler:
            raise ValueError(f"Unknown tool: {name}")
        return await handler(**params)


class ReActEngineV2:
    def __init__(self, target: str, llm_client: Optional[LLMClient] = None):
        self.target = target
        self.llm = llm_client or LLMClient()
        self.tools = ToolRegistry()
        self.history: List[ReActStep] = []
        self.max_iterations = 15
        self._register_default_tools()
        self._context: Dict[str, Any] = {"findings": [], "discovered_urls": [], "tech_stack": {}}

    def _register_default_tools(self):
        import httpx

        async def http_get(path: str = "/", headers: str = ""):
            headers_dict = {}
            if headers:
                for h in headers.split(","):
                    if ":" in h:
                        k, v = h.split(":", 1)
                        headers_dict[k.strip()] = v.strip()
            async with httpx.AsyncClient(timeout=15, follow_redirects=True) as c:
                r = await c.get(f"{self.target.rstrip('/')}{path}", headers=headers_dict)
            return {"status": r.status_code, "headers": dict(r.headers), "body": r.text[:2000]}

        async def emit_finding(title: str, severity: str, description: str, evidence: str = ""):
            finding = {"title": title, "severity": severity, "description": description, "evidence": evidence}
            self._context["findings"].append(finding)
            return f"Finding recorded: {title}"

        self.tools.register("http_get", "Send HTTP GET request", http_get,
                          {"path": "URL path", "headers": "Optional headers (key:val,key2:val2)"})
        self.tools.register("emit_finding", "Record a discovered vulnerability finding", emit_finding,
                          {"title": "Finding title", "severity": "critical/high/medium/low/info",
                           "description": "Detailed description", "evidence": "Proof/evidence"})

    async def run(self) -> List[Dict]:
        for iteration in range(1, self.max_iterations + 1):
            logger.info(f"ReAct v2: Iteration {iteration}/{self.max_iterations}")

            thoughts = await self._think(iteration)
            tool_calls = []
            final_action = "done"
            final_params = {"summary": "Assessment complete"}

            decision = await self._decide(thoughts)
            if decision.get("action") == "done":
                break

            final_action = decision.get("action", "done")
            final_params = decision.get("params", {})

            if final_action != "done":
                tc = ToolCall(tool_name=final_action, params=final_params)
                try:
                    start = time.time()
                    result = await self.tools.execute(final_action, final_params)
                    tc.latency_ms = (time.time() - start) * 1000
                    tc.result = result
                except Exception as e:
                    tc.error = str(e)
                tool_calls.append(tc)
                observation = str(result)[:500] if not tc.error else f"Error: {tc.error}"
            else:
                observation = "No action needed"

            step = ReActStep(
                iteration=iteration,
                thought_chain=thoughts,
                tool_calls=tool_calls,
                final_action=final_action,
                final_params=final_params,
                observation=observation,
                success=not any(tc.error for tc in tool_calls),
            )
            self.history.append(step)

            get_thinking_chain().add_block(
                agent_name="ReActV2",
                thought=f"Iter {iteration}: {thoughts[-1].content[:100] if thoughts else '...'} → {final_action}",
                thought_type="react",
                phase="execution",
            )

        return self._context.get("findings", [])

    async def _think(self, iteration: int) -> List[Thought]:
        system = self._build_system_prompt()
        prompt = self._build_prompt(iteration)

        response = await self.llm.generate(prompt=prompt, system=system, max_tokens=2000, task="react_think")

        thoughts = []
        lines = response.content.strip().split("\n")
        for line in lines:
            line = line.strip()
            if not line:
                continue
            if line.lower().startswith(("i need", "let me", "first", "next", "so,")):
                thoughts.append(Thought(content=line, thought_type=ThoughtType.REASONING))

        if not thoughts:
            thoughts.append(Thought(content=response.content[:200], thought_type=ThoughtType.REASONING))

        return thoughts

    async def _decide(self, thoughts: List[Thought]) -> Dict:
        thought_text = "\n".join(t.content for t in thoughts)
        tools_desc = self.tools.get_tool_descriptions()
        context = self._build_context_string()

        prompt = (
            f"Target: {self.target}\n"
            f"Current context:\n{context}\n\n"
            f"My reasoning:\n{thought_text}\n\n"
            f"Available tools:\n{tools_desc}\n\n"
            "Based on my reasoning, what should I do next? "
            "Choose ONE action. Respond with JSON: {\"action\": \"tool_name\", \"params\": {...}}\n"
            "Use 'done' with {\"summary\": \"...\"} if testing is complete."
        )
        system = "You are a security testing AI. Choose the best next action based on your reasoning chain."

        resp = await self.llm.generate(prompt=prompt, system=system, max_tokens=500, task="react_decide")
        try:
            parsed = json.loads(resp.content)
            if isinstance(parsed, str):
                parsed = json.loads(parsed)
            return parsed
        except Exception:
            return {"action": "done", "params": {"summary": "Decision parse failed"}}

    def _build_system_prompt(self) -> str:
        return (
            "You are an autonomous security AI using chain-of-thought reasoning. "
            "For each step:\n"
            "1. Analyze what you know and what you've found\n"
            "2. Identify what you need to discover next\n"
            "3. Consider alternative approaches\n"
            "4. Decide on the best next action\n\n"
            "Output your reasoning step by step, then make a decision."
        )

    def _build_prompt(self, iteration: int) -> str:
        return (
            f"Target: {self.target} | Iteration: {iteration}\n\n"
            f"History:\n"
            + "\n".join(f"  Iter {s.iteration}: {s.final_action} -> {s.observation[:100]}"
                        for s in self.history[-5:]) + "\n\n"
            f"Findings so far: {len(self._context['findings'])}\n"
            f"Discovered URLs: {self._context.get('discovered_urls', [])[:5]}\n\n"
            "What should I do next? Reason step by step."
        )

    def _build_context_string(self) -> str:
        findings = self._context.get("findings", [])
        urls = self._context.get("discovered_urls", [])
        return (
            f"Findings ({len(findings)}): "
            + "; ".join(f"{f['title']} ({f['severity']})" for f in findings[-5:])
            + f"\nURLs: {urls[:5]}"
        )


get_react_v2 = lambda target: ReActEngineV2(target)
