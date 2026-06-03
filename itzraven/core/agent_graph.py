"""
Graph-based Agent Orchestration Runtime — inspired by LangGraph + AutoGen.

Key patterns:
1. StateGraph: directed graph of nodes (agents/steps) with conditional edges
2. Agent as composed configuration (OpenHands): don't subclass, configure
3. Group Chat: multi-agent coordination with selector/routing
4. Swarm: decentralized agent coordination via shared context
5. ReAct loop: model → tools → observation → repeat
6. Durable state: persist and resume long-running workflows
"""

import asyncio
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import (
    Any, Callable, Dict, List, Optional, Set, Tuple, Type, Union,
    Generic, TypeVar,
)
from collections import defaultdict, deque

from itzraven.core.logger import get_logger

logger = get_logger()


# ─── Types ──────────────────────────────────────────────────────────────────

T = TypeVar('T')


class NodeType(Enum):
    AGENT = "agent"
    TOOL = "tool"
    CONDITION = "condition"
    INPUT = "input"
    OUTPUT = "output"
    MIDDLEWARE = "middleware"


@dataclass
class GraphState:
    """Mutable state passed through the graph. Single source of truth."""
    messages: List[Dict[str, Any]] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    step_count: int = 0
    start_time: float = field(default_factory=time.time)
    current_node: str = ""

    def to_dict(self) -> dict:
        return {
            "messages": self.messages[-20:],  # keep last 20
            "findings": self.findings[-50:],
            "metadata": self.metadata,
            "step_count": self.step_count,
            "elapsed": time.time() - self.start_time,
        }


# ─── Node Definition ────────────────────────────────────────────────────────

@dataclass
class GraphNode:
    name: str
    node_type: NodeType
    handler: Callable[['GraphState'], 'GraphState']
    description: str = ""
    config: Dict[str, Any] = field(default_factory=dict)

    async def run(self, state: GraphState) -> GraphState:
        try:
            state.current_node = self.name
            result = self.handler(state)
            if asyncio.iscoroutine(result):
                result = await result
            return result if result else state
        except Exception as e:
            state.errors.append(f"[{self.name}] {e}")
            logger.error(f"Node '{self.name}' failed: {e}")
            return state


# ─── Edge / Condition ───────────────────────────────────────────────────────

@dataclass
class Edge:
    source: str
    target: str
    condition: Optional[Callable[['GraphState'], str]] = None
    # If condition is None, edge is unconditional
    # If condition returns a target node name, route there


# ─── StateGraph ─────────────────────────────────────────────────────────────

class StateGraph:
    """Directed graph of nodes with conditional routing (LangGraph-style).

    Usage:
        graph = StateGraph()
        graph.add_node("scan", scan_handler)
        graph.add_node("analyze", analyze_handler)
        graph.add_edge("scan", "analyze")
        graph.set_entry("scan")
        result = await graph.run(initial_state)
    """

    def __init__(self, name: str = "default"):
        self.name = name
        self._nodes: Dict[str, GraphNode] = {}
        self._edges: Dict[str, List[Edge]] = defaultdict(list)
        self._entry: Optional[str] = None
        self._middleware: List[Callable] = []

    def add_node(self, name: str, handler: Callable,
                 node_type: NodeType = NodeType.AGENT,
                 description: str = "", config: Optional[Dict] = None):
        self._nodes[name] = GraphNode(
            name=name, node_type=node_type, handler=handler,
            description=description, config=config or {},
        )

    def add_edge(self, source: str, target: str,
                 condition: Optional[Callable] = None):
        self._edges[source].append(Edge(source=source, target=target, condition=condition))

    def set_entry(self, node_name: str):
        self._entry = node_name

    def add_middleware(self, hook: Callable):
        self._middleware.append(hook)

    def get_node(self, name: str) -> Optional[GraphNode]:
        return self._nodes.get(name)

    async def run(self, initial_state: Optional[GraphState] = None,
                  max_steps: int = 50) -> GraphState:
        state = initial_state or GraphState()
        if not self._entry:
            raise ValueError("No entry point set. Call set_entry() first.")

        current = self._entry
        for _ in range(max_steps):
            node = self._nodes.get(current)
            if not node:
                break

            # Pre-middleware
            for mw in self._middleware:
                try:
                    mw("pre", node.name, state)
                except Exception:
                    pass

            state = await node.run(state)
            state.step_count += 1

            # Post-middleware
            for mw in self._middleware:
                try:
                    mw("post", node.name, state)
                except Exception:
                    pass

            # Find next node
            edges = self._edges.get(current, [])
            next_node = None
            for edge in edges:
                if edge.condition:
                    result = edge.condition(state)
                    if result == edge.target:
                        next_node = edge.target
                        break
                else:
                    next_node = edge.target
                    break

            if next_node is None:
                break  # End of graph
            current = next_node

        state.current_node = "__done__"
        return state

    def visualize(self) -> str:
        lines = [f"digraph {self.name} {{"]
        for name, node in self._nodes.items():
            lines.append(f'  "{name}" [label="{name}\\n{node.node_type.value}"];')
        for src, edges in self._edges.items():
            for e in edges:
                label = f" [{e.condition.__name__}]" if e.condition else ""
                lines.append(f'  "{src}" -> "{e.target}"{label};')
        lines.append("}")
        return "\n".join(lines)


# ─── Multi-Agent Patterns ───────────────────────────────────────────────────

@dataclass
class AgentSpec:
    """Agent as composition of components (OpenHands pattern)."""
    name: str
    system_prompt: str
    tools: List[str] = field(default_factory=list)
    skills: List[str] = field(default_factory=list)
    config: Dict[str, Any] = field(default_factory=dict)
    llm_config: Dict[str, Any] = field(default_factory=dict)


class GroupChat:
    """Multi-agent group chat with selector (AutoGen Group Chat pattern).

    Agents share a common message thread. A selector agent chooses the next speaker.
    """

    def __init__(self, agents: List[AgentSpec],
                 max_turns: int = 20,
                 selector_prompt: Optional[str] = None):
        self.agents = agents
        self.max_turns = max_turns
        self._selector_prompt = selector_prompt or (
            "Given the conversation below, choose the next agent to speak. "
            "Available agents: {agents}. Respond with just the agent name."
        )
        self._messages: List[Dict] = []

    def add_message(self, role: str, content: str, agent: str = ""):
        self._messages.append({
            "role": role, "content": content, "agent": agent,
            "timestamp": time.time(),
        })

    def get_context(self) -> str:
        return "\n".join(
            f"[{m['agent'] or m['role']}]: {m['content'][:200]}"
            for m in self._messages[-10:]
        )

    async def run_turn(self, agent_name: str, task: str) -> str:
        """Run a single turn for a given agent."""
        self.add_message("user", task, agent_name)
        # In production, this would call the LLM
        result = f"{agent_name} processed: {task[:50]}..."
        self.add_message("assistant", result, agent_name)
        return result


class Swarm:
    """Decentralized multi-agent coordination (AutoGen Swarm pattern).

    Agents discover each other via shared context and route tasks with tools.
    """

    def __init__(self, agents: List[AgentSpec]):
        self.agents = agents
        self._shared_context: Dict[str, Any] = {}
        self._routing_table: Dict[str, List[str]] = {}  # capability → agent names

    def register_capability(self, agent: str, capability: str):
        if capability not in self._routing_table:
            self._routing_table[capability] = []
        self._routing_table[capability].append(agent)

    def route_task(self, task: str) -> List[str]:
        """Find agents capable of handling a task."""
        matched = []
        for capability, agents in self._routing_table.items():
            if capability.lower() in task.lower():
                matched.extend(agents)
        return matched or [a.name for a in agents]

    def share_context(self, key: str, value: Any):
        self._shared_context[key] = value


# ─── Condenser (Memory Management) ──────────────────────────────────────────

class Condenser:
    """Conversation history compression (OpenHands Condenser pattern).

    Compresses long conversations to fit within token limits
    while retaining critical information.
    """

    def __init__(self, max_messages: int = 20, summarize_threshold: int = 10):
        self.max_messages = max_messages
        self.summarize_threshold = summarize_threshold

    def compress(self, messages: List[Dict]) -> List[Dict]:
        if len(messages) <= self.max_messages:
            return messages

        # Keep first message (context), summarize middle, keep last N
        keep = messages[:1]  # system context
        middle = messages[1:-self.summarize_threshold]

        if middle:
            summary = self._summarize(middle)
            keep.append({"role": "system", "content": f"[Compressed: {summary}]"})

        keep.extend(messages[-self.summarize_threshold:])
        return keep

    def _summarize(self, messages: List[Dict]) -> str:
        tool_calls = sum(1 for m in messages if m.get("role") == "tool_call")
        findings = sum(1 for m in messages if "finding" in m.get("content", "").lower())
        return f"{len(messages)} messages ({tool_calls} tool calls, {findings} findings)"


# ─── Tool System (OpenHands Action/Observation pattern) ─────────────────────

@dataclass
class ToolAction:
    """Typed action input (OpenHands Action pattern)."""
    tool_name: str
    params: Dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: str(uuid.uuid4()))


@dataclass
class ToolObservation:
    """Typed action output (OpenHands Observation pattern)."""
    action_id: str
    tool_name: str
    success: bool
    output: str = ""
    error: Optional[str] = None
    duration_ms: float = 0.0
    findings: List[Dict] = field(default_factory=list)


class ToolExecutor:
    """Validates and executes typed actions (OpenHands Executor pattern)."""

    def __init__(self):
        self._tools: Dict[str, Callable] = {}

    def register(self, name: str, handler: Callable, schema: Optional[Dict] = None):
        self._tools[name] = handler

    def get_schemas(self) -> List[Dict]:
        return [{"name": n, "description": f.__doc__ or ""} for n, f in self._tools.items()]

    async def execute(self, action: ToolAction) -> ToolObservation:
        start = time.time()
        handler = self._tools.get(action.tool_name)
        if not handler:
            return ToolObservation(
                action_id=action.id, tool_name=action.tool_name,
                success=False, error=f"Unknown tool: {action.tool_name}",
            )
        try:
            result = handler(**action.params)
            if asyncio.iscoroutine(result):
                result = await result
            return ToolObservation(
                action_id=action.id, tool_name=action.tool_name,
                success=True, output=str(result),
                duration_ms=(time.time() - start) * 1000,
            )
        except Exception as e:
            return ToolObservation(
                action_id=action.id, tool_name=action.tool_name,
                success=False, error=str(e),
                duration_ms=(time.time() - start) * 1000,
            )
