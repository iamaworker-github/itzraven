import asyncio
import uuid
import time
from enum import Enum
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass, field
from threading import Lock

from itzraven.agents.base_agent import BaseAgent, Finding, AgentResult, AgentStatus
from itzraven.agents.llm_client import LLMClient, get_route_for_task
from itzraven.core.logger import get_logger

try:
    from itzraven.core.ctf_sandbox import CtfSandbox
    HAS_SANDBOX = True
except ImportError:
    HAS_SANDBOX = False

logger = get_logger()


class ChallengeCategory(Enum):
    PWN = "pwn"
    REV = "rev"
    CRYPTO = "crypto"
    FORENSICS = "forensics"
    WEB = "web"
    OSINT = "osint"
    MISC = "misc"
    STEGO = "stego"
    AI_ML = "ai_ml"
    MALWARE = "malware"
    BLOCKCHAIN = "blockchain"


DEFAULT_MODEL_LINEUP = [
    {"name": "deep", "model": "anthropic/claude-sonnet-4", "reasoning": "high", "task": "ctf_solve", "temperature": 0.3},
    {"name": "fast", "model": "openai/gpt-4o-mini", "reasoning": "medium", "task": "default", "temperature": 0.5},
    {"name": "analysis", "model": "google/gemini-2.5-flash", "reasoning": "low", "task": "osint_analysis", "temperature": 0.7},
]


@dataclass
class SolverResult:
    solver_id: str
    model_name: str
    model_config: Dict[str, Any]
    challenge_id: str
    flag: Optional[str] = None
    solution_data: Optional[Dict[str, Any]] = None
    trace: List[str] = field(default_factory=list)
    status: str = "running"
    error: Optional[str] = None
    start_time: float = 0.0
    end_time: Optional[float] = None


@dataclass
class BusMessage:
    from_solver: str
    message: str
    message_type: str = "info"
    timestamp: float = field(default_factory=time.time)


class MessageBus:
    def __init__(self):
        self._messages: List[BusMessage] = []
        self._lock = Lock()

    def post(self, from_solver: str, message: str, message_type: str = "info"):
        with self._lock:
            self._messages.append(BusMessage(from_solver=from_solver, message=message, message_type=message_type))

    def get_messages(self, since: float = 0.0) -> List[BusMessage]:
        with self._lock:
            return [m for m in self._messages if m.timestamp >= since]

    def get_for_solver(self, solver_id: str, since: float = 0.0) -> List[BusMessage]:
        with self._lock:
            return [m for m in self._messages if m.timestamp >= since and (m.from_solver == solver_id or m.message_type == "broadcast")]

    def clear(self):
        with self._lock:
            self._messages.clear()


class RacingCTFAgent(BaseAgent):
    def __init__(self, target: str, event_bus=None, memory_manager=None):
        super().__init__(name="Racing CTF Solver", target=target, event_bus=event_bus, memory_manager=memory_manager)
        self.description = "Multi-model racing CTF solver with coordinator-swarm pattern"
        self._llm = LLMClient()
        self._sandbox: Optional[Any] = None
        self._message_bus = MessageBus()
        self._results_lock = Lock()
        self._solver_results: Dict[str, SolverResult] = {}
        self._operator_hints: Dict[str, List[str]] = {}
        self._hints_lock = Lock()
        self._model_lineup: List[Dict[str, Any]] = DEFAULT_MODEL_LINEUP
        self._poll_interval: float = 10.0
        self._challenge_pool: List[Dict[str, Any]] = []
        self._active_swarms: Dict[str, List[asyncio.Task]] = {}
        self._flags_found: List[str] = []
        self._coordinator_task: Optional[asyncio.Task] = None
        self._poll_task: Optional[asyncio.Task] = None

        if HAS_SANDBOX:
            try:
                self._sandbox = CtfSandbox()
                logger.info(f"{self.name}: CtfSandbox initialized")
            except Exception as e:
                logger.warning(f"{self.name}: CtfSandbox init failed: {e}")
                self._sandbox = None

    async def execute(self) -> AgentResult:
        findings = []
        try:
            logger.info(f"{self.name}: Starting multi-model racing CTF solver on {self.target}")

            self._poll_task = asyncio.create_task(self._poll_for_challenges())
            self._coordinator_task = asyncio.create_task(self._run_coordinator())

            await asyncio.gather(self._poll_task, self._coordinator_task, return_exceptions=True)

        except asyncio.CancelledError:
            logger.info(f"{self.name}: Racing CTF solver cancelled")
        except Exception as e:
            logger.error(f"{self.name}: Racing CTF solver error: {e}", exc_info=True)
            finding = Finding(
                title="Racing CTF Error",
                description=f"Error during racing CTF solving: {str(e)}",
                severity="info",
                category="CTF",
                evidence=str(e),
                agent_name=self.name,
            )
            findings.append(finding)
            self.add_finding(finding)
        finally:
            await self._cleanup_racing()

        for flag_value in self._flags_found:
            finding = Finding(
                title="CTF Flag Found via Racing Solver",
                description=f"Flag captured by multi-model racing solver",
                severity="critical",
                category="CTF",
                evidence=flag_value,
                proof_of_concept="Discovered via multi-model parallel solving",
                remediation="N/A - CTF Challenge",
                agent_name=self.name,
            )
            findings.append(finding)
            self.add_finding(finding)

        if findings:
            summary = Finding(
                title=f"Racing CTF Complete - {len(self._flags_found)} flags found",
                description=f"Solved {len(self._flags_found)} challenges using racing solver pattern",
                severity="info",
                category="CTF",
                evidence=f"Flags: {', '.join(self._flags_found)}",
                proof_of_concept=f"Models: {', '.join(m['name'] for m in self._model_lineup)}",
                remediation="N/A - CTF Challenge",
                agent_name=self.name,
            )
            findings.append(summary)
            self.add_finding(summary)

        return AgentResult(
            agent_name=self.name,
            status=self.status,
            findings=self.findings,
            execution_time=0,
        )

    async def _cleanup_racing(self):
        for swarm_id, tasks in list(self._active_swarms.items()):
            for t in tasks:
                if not t.done():
                    t.cancel()
            remaining = [t for t in tasks if not t.done()]
            if remaining:
                await asyncio.gather(*remaining, return_exceptions=True)
        self._active_swarms.clear()

        if self._coordinator_task and not self._coordinator_task.done():
            self._coordinator_task.cancel()
        if self._poll_task and not self._poll_task.done():
            self._poll_task.cancel()

        if self._sandbox:
            try:
                await self._sandbox.cleanup()
            except Exception:
                pass

    async def _poll_for_challenges(self):
        logger.info(f"{self.name}: Starting challenge poller")
        while not self._cancelled:
            try:
                new_challenges = await self._check_for_new_challenges()
                for challenge in new_challenges:
                    cid = challenge.get("id", str(uuid.uuid4()))
                    if cid not in [c.get("id") for c in self._challenge_pool]:
                        self._challenge_pool.append(challenge)
                        logger.info(f"{self.name}: New challenge detected: {challenge.get('name', cid)}")
                        swarm_task = asyncio.create_task(self._spawn_solver_swarm(challenge))
                        if cid not in self._active_swarms:
                            self._active_swarms[cid] = []
                        self._active_swarms[cid].append(swarm_task)
            except Exception as e:
                logger.debug(f"{self.name}: Poll error: {e}")
            await asyncio.sleep(self._poll_interval)

    async def _check_for_new_challenges(self) -> List[Dict[str, Any]]:
        await asyncio.sleep(0.5)
        return []

    async def _run_coordinator(self):
        logger.info(f"{self.name}: Coordinator started")
        last_summary_time = 0.0
        while not self._cancelled:
            await asyncio.sleep(5.0)
            if self._cancelled:
                break

            active = [r for r in self._solver_results.values() if r.status == "running"]
            completed = [r for r in self._solver_results.values() if r.status in ("solved", "failed")]

            if not active and completed:
                logger.info(f"{self.name}: Coordinator: all solvers finished ({len(completed)} total)")
                break

            if active or completed:
                bus_msgs = self._message_bus.get_messages(since=last_summary_time)
                if bus_msgs:
                    last_summary_time = time.time()
                    summary = self._build_coordinator_context(active, completed, bus_msgs)
                    guidance = await self._get_coordinator_guidance(summary)
                    if guidance and self._operator_hints:
                        for solver_id in list(self._operator_hints.keys()):
                            with self._hints_lock:
                                if solver_id not in self._operator_hints:
                                    self._operator_hints[solver_id] = []
                                self._operator_hints[solver_id].append(guidance)

    def _build_coordinator_context(self, active: List[SolverResult], completed: List[SolverResult], bus_msgs: List[BusMessage]) -> str:
        lines = [f"Active solvers: {len(active)}", f"Completed solvers: {len(completed)}", ""]
        if self._flags_found:
            lines.append(f"Flags found: {', '.join(self._flags_found)}")
            lines.append("")
        for r in active:
            lines.append(f"[ACTIVE] {r.solver_id} ({r.model_name}): running for {time.time() - r.start_time:.1f}s")
        for r in completed:
            status_icon = "SOLVED" if r.status == "solved" else "FAILED"
            lines.append(f"[{status_icon}] {r.solver_id} ({r.model_name})")
            if r.trace:
                lines.append(f"  Last trace: {r.trace[-1]}")
        if bus_msgs:
            lines.append("")
            lines.append("Message bus:")
            for m in bus_msgs[-10:]:
                lines.append(f"  [{m.from_solver}] {m.message}")
        return "\n".join(lines)

    async def _get_coordinator_guidance(self, context: str) -> Optional[str]:
        system = "You are a senior CTF competition coordinator. Analyze solver progress and provide strategic guidance if needed. Be concise."
        prompt = f"Current competition state:\n\n{context}\n\nProvide strategic guidance for the active solvers. If everything is on track, respond with 'OK'."
        try:
            resp = await self._llm.generate(
                prompt=prompt,
                system=system,
                max_tokens=500,
                model="anthropic/claude-sonnet-4",
                temperature=0.3,
            )
            content = resp.content.strip()
            if content.upper() == "OK":
                return None
            return content
        except Exception as e:
            logger.debug(f"{self.name}: Coordinator guidance error: {e}")
            return None

    async def _spawn_solver_swarm(self, challenge: Dict[str, Any]):
        cid = challenge.get("id", str(uuid.uuid4()))
        logger.info(f"{self.name}: Spawning solver swarm for challenge {challenge.get('name', cid)}")

        solver_tasks = []
        for model_config in self._model_lineup:
            solver_id = f"solver-{cid}-{model_config['name']}-{uuid.uuid4().hex[:6]}"
            task = asyncio.create_task(self._run_solver(challenge, model_config, solver_id))
            solver_tasks.append(task)

        self._message_bus.post("coordinator", f"Swarm spawned for {challenge.get('name', cid)} with {len(solver_tasks)} solvers", "broadcast")

        done, pending = await asyncio.wait(solver_tasks, return_when=asyncio.FIRST_COMPLETED)

        for task in pending:
            task.cancel()

        if pending:
            await asyncio.gather(*pending, return_exceptions=True)

        for task in done:
            try:
                result = task.result()
                if result and result.flag:
                    self._message_bus.post("coordinator", f"Flag found by {result.solver_id}: {result.flag}", "broadcast")
                    with self._results_lock:
                        if result.flag not in self._flags_found:
                            self._flags_found.append(result.flag)
            except Exception as e:
                logger.debug(f"{self.name}: Swarm task error: {e}")

        logger.info(f"{self.name}: Swarm completed for challenge {challenge.get('name', cid)}")

    async def _run_solver(self, challenge: Dict[str, Any], model_config: Dict[str, Any], solver_id: str) -> Optional[SolverResult]:
        logger.info(f"{self.name}: Solver {solver_id} starting with model {model_config['name']}")

        cid = challenge.get("id", "unknown")
        result = SolverResult(
            solver_id=solver_id,
            model_name=model_config["name"],
            model_config=model_config,
            challenge_id=cid,
            start_time=time.time(),
        )
        with self._results_lock:
            self._solver_results[solver_id] = result

        try:
            challenge_desc = challenge.get("description", f"Solve CTF challenge: {challenge.get('name', self.target)}")
            challenge_data = challenge.get("data", "")

            system = (
                "You are a CTF challenge solver. Analyze the challenge and attempt to find the flag.\n"
                "Think step by step about what the challenge requires.\n"
                "If you find the flag, output it in the format FLAG{...} or CTF{...} or similar.\n"
                "Share interesting findings via the message bus by outputting 'BUS: <message>'."
            )

            bus_msgs_before = len(self._message_bus.get_messages())

            prompt = f"Challenge: {challenge_desc}\n"
            if challenge_data:
                prompt += f"Data: {challenge_data}\n"
            prompt += "\nAttempt to solve this challenge. Report your findings."

            route = get_route_for_task(model_config.get("task", "ctf_solve"))
            resp = await self._llm.generate(
                prompt=prompt,
                system=system,
                max_tokens=route.get("max_tokens", 2000),
                model=model_config["model"],
                temperature=model_config.get("temperature", 0.5),
            )

            content = resp.content
            result.trace.append(f"LLM response ({model_config['name']}): {content[:200]}...")

            for line in content.split("\n"):
                line_stripped = line.strip()
                if line_stripped.upper().startswith("BUS:"):
                    bus_msg = line_stripped[4:].strip()
                    self._post_to_bus(solver_id, bus_msg)

            flag = self._extract_flag(content)
            if flag:
                result.flag = flag
                result.status = "solved"
                result.solution_data = {"method": "llm_solve", "model": model_config["name"], "response": content}
                logger.info(f"{self.name}: Solver {solver_id} found flag: {flag}")
            else:
                result.trace.append("No flag found in initial response, attempting further analysis")
                follow_up = await self._llm.generate(
                    prompt=f"The previous attempt didn't yield a flag. Challenge: {challenge_desc}\n\nData: {challenge_data}\n\nTry a different approach. What techniques could work?",
                    system=system,
                    max_tokens=1500,
                    model=model_config["model"],
                    temperature=model_config.get("temperature", 0.7),
                )
                content2 = follow_up.content
                result.trace.append(f"Follow-up ({model_config['name']}): {content2[:200]}...")
                flag2 = self._extract_flag(content2)
                if flag2:
                    result.flag = flag2
                    result.status = "solved"
                    result.solution_data = {"method": "llm_solve_followup", "model": model_config["name"], "response": content2}

            hints = self._get_hints_for_solver(solver_id)
            if hints and not result.flag:
                hint_text = "\n".join(hints)
                hint_prompt = f"Hints from coordinator/operator:\n{hint_text}\n\nApply these hints to the challenge:\n{challenge_desc}"
                hint_resp = await self._llm.generate(
                    prompt=hint_prompt,
                    system=system,
                    max_tokens=1500,
                    model=model_config["model"],
                    temperature=model_config.get("temperature", 0.3),
                )
                result.trace.append(f"Hint-assisted ({model_config['name']}): {hint_resp.content[:200]}...")
                flag3 = self._extract_flag(hint_resp.content)
                if flag3:
                    result.flag = flag3
                    result.status = "solved"
                    result.solution_data = {"method": "hint_assisted", "model": model_config["name"], "response": hint_resp.content}

            if not result.flag:
                result.status = "failed"
                result.trace.append("Solver exhausted approaches without finding flag")

        except asyncio.CancelledError:
            result.status = "cancelled"
            result.trace.append("Cancelled by another solver winning the race")
            logger.info(f"{self.name}: Solver {solver_id} cancelled (race lost)")
        except Exception as e:
            result.status = "failed"
            result.error = str(e)
            result.trace.append(f"Error: {str(e)}")
            logger.debug(f"{self.name}: Solver {solver_id} error: {e}")

        result.end_time = time.time()
        with self._results_lock:
            self._solver_results[solver_id] = result

        return result

    def _extract_flag(self, text: str) -> Optional[str]:
        import re
        patterns = [
            r'[Ff][Ll][Aa][Gg]\s*[=:]\s*(\S+)',
            r'(?:CTF|FLAG|FL\{)[\w!@#$%^&*()\-=+\[\]{}|;:,.<>?/~`]+\}',
            r'[Ff][Ll][Aa][Gg].*?(\{[\w!@#$%^&*()\-=+\[\]{}|;:,.<>?/~`]+\})',
        ]
        for pat in patterns:
            m = re.search(pat, text)
            if m:
                return m.group(0) if not m.group(1) else m.group(1)
        return None

    def _post_to_bus(self, from_solver: str, message: str):
        self._message_bus.post(from_solver, message)
        logger.info(f"{self.name}: Bus [{from_solver}]: {message[:100]}")

    def _get_hints_for_solver(self, solver_id: str) -> List[str]:
        with self._hints_lock:
            hints = self._operator_hints.get(solver_id, [])
            global_hints = self._operator_hints.get("__global__", [])
            combined = list(hints)
            for h in global_hints:
                if h not in combined:
                    combined.append(h)
            return combined

    def send_operator_hint(self, solver_id: str, hint: str):
        with self._hints_lock:
            if solver_id not in self._operator_hints:
                self._operator_hints[solver_id] = []
            self._operator_hints[solver_id].append(hint)
        logger.info(f"{self.name}: Operator hint sent to {solver_id}: {hint[:100]}")

    def get_solver_status(self, solver_id: Optional[str] = None) -> Dict[str, Any]:
        with self._results_lock:
            if solver_id:
                r = self._solver_results.get(solver_id)
                if r:
                    return {"solver_id": r.solver_id, "model": r.model_name, "status": r.status, "flag": r.flag, "error": r.error}
                return {"error": "solver not found"}
            return {
                "total": len(self._solver_results),
                "solved": sum(1 for r in self._solver_results.values() if r.status == "solved"),
                "failed": sum(1 for r in self._solver_results.values() if r.status == "failed"),
                "running": sum(1 for r in self._solver_results.values() if r.status == "running"),
                "cancelled": sum(1 for r in self._solver_results.values() if r.status == "cancelled"),
                "flags_found": list(self._flags_found),
            }
