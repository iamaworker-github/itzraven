"""
AI Executor — AI brain jo directly agents ko control karta hai.
Ye passive logger nahi hai, ye actual decision maker hai jo:
- Decide karta hai NEXT kaunsa agent run hoga
- Decide karta hai kaunsa technique try karna hai
- Decide karta hai strategy kab shift karni hai
- Decide karta hai exploit kab generate karna hai
- Decide karta hai target kab chhodna hai
"""

import asyncio
import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Callable, Awaitable
from enum import Enum

from itzraven.core.logger import get_logger
from itzraven.agents.llm_client import LLMClient
from itzraven.agents.base_agent import Finding

logger = get_logger()


class ExecutorDecision(Enum):
    CONTINUE = "continue"
    SHIFT_STRATEGY = "shift_strategy"
    TRY_ALTERNATE = "try_alternate"
    DEEP_DIVE = "deep_dive"
    CHAIN_EXPLOIT = "chain_exploit"
    GENERATE_TOOL = "generate_tool"
    ABORT = "abort"


@dataclass
class AICommand:
    """AI ka ek concrete command jo agents execute karein."""
    decision: ExecutorDecision
    reason: str
    action: str
    params: Dict[str, Any]
    target_agent: Optional[str] = None
    confidence: float = 0.8
    priority: int = 5
    command_id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])

    def to_dict(self) -> dict:
        return {
            "command_id": self.command_id,
            "decision": self.decision.value,
            "reason": self.reason[:100],
            "action": self.action,
            "target_agent": self.target_agent,
            "confidence": self.confidence,
            "priority": self.priority,
        }


@dataclass
class ExecutionState:
    """Current state of the scan — AI ko feed karta hai decisions ke liye."""
    target: str
    mode: str
    scan_depth: str
    current_phase: str = "planning"
    findings: List[Dict] = field(default_factory=list)
    agent_results: List[Dict] = field(default_factory=list)
    failed_techniques: List[str] = field(default_factory=list)
    successful_techniques: List[str] = field(default_factory=list)
    consecutive_failures: int = 0
    total_steps: int = 0
    tech_stack: List[str] = field(default_factory=list)
    open_ports: List[int] = field(default_factory=list)
    waf_detected: Optional[str] = None
    errors: List[str] = field(default_factory=list)
    execution_time: float = 0.0
    completed_goals: List[str] = field(default_factory=list)
    pending_agents: int = 0
    completed_agents: int = 0

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "phase": self.current_phase,
            "total_findings": len(self.findings),
            "agents_done": self.completed_agents,
            "agents_pending": self.pending_agents,
            "consecutive_failures": self.consecutive_failures,
            "failed_techniques": self.failed_techniques[-5:],
            "successful_techniques": self.successful_techniques[-5:],
            "tech_stack": self.tech_stack[:5],
            "waf": self.waf_detected,
            "errors": self.errors[-3:],
            "time_elapsed": round(self.execution_time, 1),
        }


class AIExecutor:
    """
    AI Executor — ye brain hai jo decide karta hai aage kya karna hai.
    Jaise mai (DeepSeek) sochta hoon waise hi ye LLM se decisions leta hai
    aur agents ko commands bhejta hai.
    """

    _instance = None

    def __init__(self):
        self.llm = LLMClient()
        self.state: Optional[ExecutionState] = None
        self.command_queue: List[AICommand] = []
        self.executed_commands: List[AICommand] = []
        self._agent_registry: Dict[str, Callable] = {}
        self._running = False

    @classmethod
    def get_instance(cls) -> "AIExecutor":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def start_session(self, target: str, mode: str = "pentest",
                       scan_depth: str = "deep") -> ExecutionState:
        self.state = ExecutionState(
            target=target, mode=mode, scan_depth=scan_depth
        )
        self.command_queue.clear()
        self.executed_commands.clear()
        self._running = True
        logger.info(f"🤖 AI Executor started for {target} ({mode})")
        return self.state

    def register_agent(self, name: str, runner: Callable[..., Awaitable[Any]]):
        """Agent ko register karo taake AI usse call kar sake."""
        self._agent_registry[name] = runner

    def record_finding(self, finding: Finding):
        if self.state:
            self.state.findings.append({
                "title": finding.title,
                "severity": finding.severity,
                "category": finding.category,
                "confidence": finding.confidence,
            })

    def record_agent_result(self, agent_name: str, findings_count: int,
                             success: bool, error: str = ""):
        if not self.state:
            return
        self.state.completed_agents += 1
        self.state.total_steps += 1
        if success:
            self.state.successful_techniques.append(agent_name)
            self.state.consecutive_failures = 0
        else:
            self.state.failed_techniques.append(agent_name)
            self.state.consecutive_failures += 1
            if error:
                self.state.errors.append(f"{agent_name}: {error}")

    # ─────────────────────────────────────────────────────────────
    # CORE: AI DECISION MAKING LOOP
    # ─────────────────────────────────────────────────────────────

    async def think_and_decide(self) -> AICommand:
        """AI sochta hai → decision leta hai → command return karta hai."""
        state_dict = self.state.to_dict() if self.state else {}
        recent_commands = [c.to_dict() for c in self.executed_commands[-5:]]

        current_findings = [
            {"title": f.get("title", ""), "severity": f.get("severity", "")}
            for f in (self.state.findings if self.state else [])
        ][-10:]

        prompt = (
            "You are the AI executor of a security testing platform. "
            "Analyze the CURRENT STATE and decide what to do NEXT.\n\n"
            f"STATE:\n{json.dumps(state_dict, indent=2)}\n\n"
            f"RECENT COMMANDS EXECUTED:\n{json.dumps(recent_commands, indent=2)}\n\n"
            f"FINDINGS SO FAR:\n{json.dumps(current_findings, indent=2)}\n\n"
            "AVAILABLE AGENTS:\n"
            + "\n".join(f"  - {name}" for name in self._agent_registry.keys()) + "\n\n"
            "DECIDE what to do next. Be strategic:\n"
            "- If finding nothing → shift strategy\n"
            "- If WAF blocking → bypass technique\n"
            "- If multiple low findings → chain them\n"
            "- If technique failed 3x → try different\n"
            "- If critical found → deep dive\n"
            "- If stuck → generate custom tool\n\n"
            "Output ONLY valid JSON:\n"
            "{\n"
            '  "decision": "continue/shift_strategy/try_alternate/deep_dive/chain_exploit/generate_tool/abort",\n'
            '  "reason": "why this decision",\n'
            '  "action": "what specific action to take",\n'
            '  "params": {"key": "value"},\n'
            '  "target_agent": "which agent to run/null",\n'
            '  "confidence": 0.0-1.0,\n'
            '  "priority": 1-10\n'
            "}"
        )
        system = (
            "You are an autonomous security AI executor. You think like a pentester: "
            "observe current state, correlate findings, hypothesize attack paths, "
            "decide next action. Be decisive and specific."
        )

        try:
            resp = await self.llm.generate(
                prompt=prompt, system=system, max_tokens=800, task="executor_decide"
            )
            raw = resp.content
            parsed = json.loads(raw) if isinstance(raw, dict) else json.loads(raw)
        except Exception as e:
            logger.debug(f"AI Executor decision failed: {e}")
            parsed = {
                "decision": "continue",
                "reason": "LLM error, defaulting",
                "action": "continue_scan",
                "params": {},
                "target_agent": None,
                "confidence": 0.3,
                "priority": 1,
            }

        try:
            decision = ExecutorDecision(parsed.get("decision", "continue"))
        except ValueError:
            decision = ExecutorDecision.CONTINUE

        cmd = AICommand(
            decision=decision,
            reason=parsed.get("reason", "No reason"),
            action=parsed.get("action", "continue"),
            params=parsed.get("params", {}),
            target_agent=parsed.get("target_agent"),
            confidence=float(parsed.get("confidence", 0.5)),
            priority=int(parsed.get("priority", 5)),
        )

        self.command_queue.append(cmd)
        self.executed_commands.append(cmd)
        logger.info(
            f"🤖 AI Executor → {decision.value} | {cmd.reason[:80]} | "
            f"action={cmd.action[:40]} | confidence={cmd.confidence:.2f}"
        )

        # Apply decision to state
        if decision == ExecutorDecision.SHIFT_STRATEGY and self.state:
            self.state.current_phase = f"shifted:{cmd.action[:20]}"
        elif decision == ExecutorDecision.CHAIN_EXPLOIT and self.state:
            self.state.current_phase = "exploit_chaining"

        return cmd

    async def execute_command(self, cmd: AICommand) -> Dict:
        """Command ko execute kare — actual agent run kare ya tool generate kare."""
        result = {"command_id": cmd.command_id, "decision": cmd.decision.value, "success": False}

        if cmd.decision == ExecutorDecision.GENERATE_TOOL:
            from itzraven.core.tool_generator import get_tool_generator
            tg = get_tool_generator()
            technique = cmd.params.get("technique", cmd.action)
            requirement = cmd.params.get("requirement", f"Tool for {cmd.action}")
            tool = await tg.generate_tool(requirement, technique)
            if tool:
                verified = await tg.verify_tool(tool)
                result["tool"] = tool.name
                result["verified"] = verified
                result["success"] = verified
                logger.info(f"🤖 AI spawned tool: {tool.name} (verified={verified})")

        elif cmd.decision == ExecutorDecision.CHAIN_EXPLOIT:
            from itzraven.core.vuln_chaining_ai import get_vuln_chaining
            vc = get_vuln_chaining()
            findings_obj = [Finding(**f) for f in (self.state.findings if self.state else [])]
            chains = await vc.discover_chains(findings_obj)
            if chains:
                best = chains[0]
                exploit = await vc.generate_exploit(best)
                result["chain"] = best.name
                result["exploit_generated"] = exploit is not None
                result["success"] = exploit is not None
                logger.info(f"🤖 AI generated exploit: {best.name}")

        elif cmd.target_agent and cmd.target_agent in self._agent_registry:
            try:
                runner = self._agent_registry[cmd.target_agent]
                agent_result = await runner(cmd.params)
                result["agent_result"] = str(agent_result)[:200]
                result["success"] = True
                logger.info(f"🤖 AI ran agent: {cmd.target_agent}")
            except Exception as e:
                result["error"] = str(e)
                logger.warning(f"🤖 AI agent failed: {cmd.target_agent}: {e}")

                # Failover: agent fail → alternative command generate karo
                from itzraven.core.failover_engine import get_failover_engine
                fe = get_failover_engine()
                plan = await fe.handle_failure(
                    cmd.command_id, cmd.action, cmd.params,
                    str(e), f"Agent {cmd.target_agent} failed",
                )
                if plan:
                    result["failover"] = plan.strategy.value
                    cmd.params["fallback_strategy"] = plan.strategy.value
                    logger.info(f"🤖 AI failover: {plan.strategy.value}")

        elif cmd.decision == ExecutorDecision.ABORT:
            self._running = False
            result["success"] = True
            result["message"] = "Scan aborted by AI"
            logger.info("🤖 AI aborted scan")

        else:
            result["message"] = f"No action defined for: {cmd.decision.value}"
            result["success"] = True

        return result

    async def run_loop(self, max_decisions: int = 20) -> List[Dict]:
        """Main AI loop — bar bar think → decide → execute karo."""
        results = []
        decisions_made = 0

        while self._running and decisions_made < max_decisions:
            cmd = await self.think_and_decide()
            result = await self.execute_command(cmd)
            results.append(result)
            decisions_made += 1

            if cmd.decision == ExecutorDecision.ABORT:
                break

        logger.info(f"🤖 AI Executor loop complete: {decisions_made} decisions, {len(results)} results")
        return results

    def get_execution_log(self) -> Dict:
        return {
            "state": self.state.to_dict() if self.state else {},
            "commands_executed": [c.to_dict() for c in self.executed_commands],
            "total_decisions": len(self.executed_commands),
            "running": self._running,
        }


get_ai_executor = AIExecutor.get_instance
