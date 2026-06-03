"""
AI Features Orchestrator — sabhi AI improvements ko ek saath integrate karta hai.
"""

import time
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field

from itzraven.core.logger import get_logger
from itzraven.agents.llm_client import LLMClient
from itzraven.agents.base_agent import Finding, BaseAgent, AgentResult

logger = get_logger()


@dataclass
class AIEnhancementResult:
    reflection_insights: List[Dict] = field(default_factory=list)
    evolved_prompts: List[Dict] = field(default_factory=list)
    attack_chains: List[Dict] = field(default_factory=list)
    debate_results: List[Dict] = field(default_factory=list)
    healing_results: List[Dict] = field(default_factory=list)
    generated_tools: List[Dict] = field(default_factory=list)
    strategy_recommendation: Optional[Dict] = None
    rl_update: Optional[Dict] = None
    failover_history: List[Dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "reflections": len(self.reflection_insights),
            "prompts_evolved": len(self.evolved_prompts),
            "chains_discovered": len(self.attack_chains),
            "debates": len(self.debate_results),
            "heals": len(self.healing_results),
            "tools_generated": len(self.generated_tools),
            "has_strategy": self.strategy_recommendation is not None,
        }


class AIOrchestrator:
    _instance = None

    def __init__(self):
        self.llm = LLMClient()
        self._modules = {}
        self._init_modules()
        self.results: Dict[str, AIEnhancementResult] = {}

    def _init_modules(self):
        try:
            from itzraven.core.self_reflection_engine import get_self_reflection
            self._modules["reflection"] = get_self_reflection()
        except Exception as e:
            logger.debug(f"Reflection module not available: {e}")

        try:
            from itzraven.core.prompt_evolution import get_prompt_evolution
            self._modules["prompt_evolution"] = get_prompt_evolution()
        except Exception as e:
            logger.debug(f"Prompt evolution not available: {e}")

        try:
            from itzraven.core.vuln_chaining_ai import get_vuln_chaining
            self._modules["vuln_chaining"] = get_vuln_chaining()
        except Exception as e:
            logger.debug(f"Vuln chaining not available: {e}")

        try:
            from itzraven.core.debate_engine import get_debate_engine
            self._modules["debate"] = get_debate_engine()
        except Exception as e:
            logger.debug(f"Debate engine not available: {e}")

        try:
            from itzraven.core.self_healing_exploits import get_self_healing
            self._modules["self_healing"] = get_self_healing()
        except Exception as e:
            logger.debug(f"Self healing not available: {e}")

        try:
            from itzraven.core.tool_generator import get_tool_generator
            self._modules["tool_generator"] = get_tool_generator()
        except Exception as e:
            logger.debug(f"Tool generator not available: {e}")

        try:
            from itzraven.core.reinforcement_learning import get_rl_engine
            self._modules["rl"] = get_rl_engine()
        except Exception as e:
            logger.debug(f"RL engine not available: {e}")

        try:
            from itzraven.core.target_profiler import get_target_profiler
            self._modules["target_profiler"] = get_target_profiler()
        except Exception as e:
            logger.debug(f"Target profiler not available: {e}")

        try:
            from itzraven.core.failover_engine import get_failover_engine
            self._modules["failover"] = get_failover_engine()
        except Exception as e:
            logger.debug(f"Failover engine not available: {e}")

        try:
            from itzraven.core.react_agent_v2 import get_react_v2
            self._modules["react_v2"] = get_react_v2
        except Exception as e:
            logger.debug(f"ReAct v2 not available: {e}")

    @classmethod
    def get_instance(cls) -> "AIOrchestrator":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def get_module(self, name: str):
        return self._modules.get(name)

    async def enhance_agent(self, agent: BaseAgent, target: str,
                             findings: List[Finding], session_id: str) -> AIEnhancementResult:
        result = AIEnhancementResult()

        if "reflection" in self._modules:
            ref_engine = self._modules["reflection"]
            session = ref_engine.start_session(agent.name, session_id)
            for f in findings:
                session.record_step(f.category or "unknown", f.severity not in ("info", "low"))
                session.findings.append({"title": f.title, "severity": f.severity})
            insight = await ref_engine.deep_reflect(session_id)
            if insight:
                result.reflection_insights = [{
                    "observation": insight.observation,
                    "root_cause": insight.root_cause,
                    "recommendation": insight.recommendation,
                    "strategy_shift": insight.strategy_shift,
                    "blind_spot": insight.blind_spot,
                }]

        if "prompt_evolution" in self._modules:
            pe = self._modules["prompt_evolution"]
            from itzraven.core.self_reflection_engine import get_self_reflection
            ref_session = get_self_reflection().get_session(session_id)
            if ref_session and len(ref_session.errors) >= 2:
                evolved = await pe.evolve_prompt(
                    technique=agent.name,
                    target_tech=target.split(".")[-1] if "." in target else "unknown",
                    failure_context="\n".join(ref_session.errors[-5:]),
                )
                if evolved:
                    result.evolved_prompts = [{"technique": agent.name, "hash": evolved.hash}]

        if "vuln_chaining" in self._modules:
            vc = self._modules["vuln_chaining"]
            chains = await vc.discover_chains(findings)
            if chains:
                result.attack_chains = [c.to_dict() for c in chains]

        if "debate" in self._modules and len(findings) >= 2:
            de = self._modules["debate"]
            agent_separated = {agent.name: findings}
            other_findings = findings[:3]
            agent_separated["Validator"] = other_findings
            debate_results = await de.cross_validate_findings(findings[:3], agent_separated)
            result.debate_results = [
                {"finding": r.finding_title, "consensus": r.consensus[:100],
                 "confidence": r.confidence}
                for r in debate_results
            ]

        if "rl" in self._modules:
            rl = self._modules["rl"]
            for f in findings:
                rl.record_scan_outcome(
                    target_tech=target.split(".")[-1] if "." in target else "unknown",
                    ports=[],
                    has_waf=False,
                    findings_count=len(findings),
                    technique=f.category or "unknown",
                    success=f.severity not in ("info", "low"),
                )
            result.rl_update = {"state_count": len(rl.q_table)}

        if "target_profiler" in self._modules:
            tp = self._modules["target_profiler"]
            profile = tp.get_or_create(target)
            profile.record_scan(
                findings_count=len(findings),
                techniques=[f.category for f in findings],
                successful=[f.category for f in findings if f.severity not in ("info", "low")],
                failed=[f.category for f in findings if f.severity == "info"],
                duration=time.time() - time.time(),
            )
            strategy = await tp.recommend_strategy(target)
            result.strategy_recommendation = strategy

        self.results[session_id] = result
        return result

    async def run_react_v2(self, target: str) -> List[Dict]:
        if "react_v2" not in self._modules:
            logger.warning("ReAct v2 not available")
            return []
        engine = self._modules["react_v2"](target)
        return await engine.run()

    async def generate_tool(self, requirement: str, technique: str) -> Optional[Dict]:
        if "tool_generator" not in self._modules:
            return None
        tg = self._modules["tool_generator"]
        tool = await tg.generate_tool(requirement, technique)
        if tool:
            await tg.verify_tool(tool)
            return tool.to_dict()
        return None

    async def heal_exploit(self, payload: str, technique: str, execute_fn) -> Optional[Dict]:
        if "self_healing" not in self._modules:
            return None
        sh = self._modules["self_healing"]
        result = await sh.heal_and_retry(payload, technique, execute_fn)
        return {
            "success": result.success,
            "attempts": len(result.attempts),
            "healing_path": result.healing_path,
        }

    async def handle_failover(self, failover_id: str, action: str, params: Dict,
                               error: str, context: str = "") -> Optional[Dict]:
        if "failover" not in self._modules:
            return None
        fe = self._modules["failover"]
        plan = await fe.handle_failure(failover_id, action, params, error, context)
        if plan:
            return {"strategy": plan.strategy.value, "description": plan.description}
        return None

    def get_summary(self) -> Dict:
        return {
            "modules_loaded": list(self._modules.keys()),
            "session_results": {k: v.to_dict() for k, v in self.results.items()},
        }


get_ai_orchestrator = AIOrchestrator.get_instance
