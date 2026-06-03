"""
Enhanced Chain Executor — XBOW-inspired automated attack chain detection.

Auto-discovers multi-step attack paths from agent findings and executes
them with dynamic step detection, progress tracking, and intelligent
priority ordering.
"""

import asyncio
from typing import List, Optional, Dict, Any, Set
from dataclasses import dataclass, field

from itzraven.core.logger import get_logger
from itzraven.core.chain_matrix import (
    ExploitChain, ChainStep, get_chain, find_matching_chains,
    get_next_suggestions, CHAINS,
)
from itzraven.core.blackboard import Blackboard, FindingCategory, get_blackboard
from itzraven.agents.base_agent import Finding
from itzraven.core.attack_surface import AttackSurfaceManager, get_attack_surface
from itzraven.core.learning_engine import get_learning_engine

logger = get_logger()


@dataclass
class AttackPath:
    chain_name: str
    category: str
    severity: str
    steps_completed: int
    total_steps: int
    next_step: Optional[str]
    confidence: float
    prerequisite_met: bool
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "chain_name": self.chain_name,
            "category": self.category,
            "severity": self.severity,
            "steps_completed": self.steps_completed,
            "total_steps": self.total_steps,
            "next_step": self.next_step,
            "confidence": round(self.confidence, 2),
            "prerequisite_met": self.prerequisite_met,
        }


@dataclass
class ChainExecutionResult:
    chain_name: str
    success: bool
    steps_completed: int
    total_steps: int
    steps_results: List[Dict[str, Any]] = field(default_factory=list)
    findings_generated: int = 0
    attack_path: Optional[AttackPath] = None
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "chain_name": self.chain_name,
            "success": self.success,
            "steps_completed": self.steps_completed,
            "total_steps": self.total_steps,
            "findings_generated": self.findings_generated,
            "error": self.error,
        }


class ChainExecutor:
    def __init__(
        self,
        target: str,
        blackboard: Optional[Blackboard] = None,
        scope: Optional[List[str]] = None,
    ):
        self.target = target
        self._bb = blackboard or get_blackboard()
        self._scope = scope or []
        self._results: List[ChainExecutionResult] = []
        self._executed_chains: Dict[str, ChainExecutionResult] = {}
        self._surface = get_attack_surface(target)
        self._learning = get_learning_engine()
        self._discovered_paths: List[AttackPath] = []

    async def execute_chain(
        self,
        chain: ExploitChain,
        findings: List[Finding],
    ) -> ChainExecutionResult:
        if chain.name in self._executed_chains:
            return self._executed_chains[chain.name]

        logger.info(f"ChainExecutor: executing '{chain.name}' ({len(chain.steps)} steps)")
        steps_results = []
        steps_completed = 0
        findings_generated = 0

        for i, step in enumerate(chain.steps):
            logger.info(f"  Step {i+1}/{len(chain.steps)}: {step.name}")
            try:
                step_result = await self._execute_step_dynamic(step, chain, findings)
                steps_results.append(step_result)
                if step_result.get("success"):
                    steps_completed += 1
                    if step_result.get("findings"):
                        findings_generated += len(step_result["findings"])
                    self._surface.register(
                        SurfaceCategory.ENDPOINT,
                        f"chain:{chain.name}:{step.name}",
                        priority=0.8,
                        tags=chain.tags,
                        parent=f"chain:{chain.name}",
                    )
                    self._surface.mark_checked(f"chain:{chain.name}:{step.name}", success=True)
                else:
                    logger.warning(f"  Step {i+1} failed: {step_result.get('error', 'unknown')}")
                    self._surface.register(
                        SurfaceCategory.ENDPOINT,
                        f"chain:{chain.name}:{step.name}",
                        priority=0.3,
                        tags=chain.tags + ["failed"],
                        parent=f"chain:{chain.name}",
                    )
                    break
            except Exception as e:
                logger.error(f"  Step {i+1} error: {e}")
                steps_results.append({"step": step.name, "success": False, "error": str(e)})
                break

        total_steps = len(chain.steps)
        success = steps_completed >= total_steps
        attack_path = AttackPath(
            chain_name=chain.name,
            category=chain.category.value,
            severity=chain.severity,
            steps_completed=steps_completed,
            total_steps=total_steps,
            next_step=chain.steps[steps_completed].name if steps_completed < total_steps else None,
            confidence=steps_completed / max(total_steps, 1),
            prerequisite_met=steps_completed > 0,
            tags=chain.tags,
        )

        result = ChainExecutionResult(
            chain_name=chain.name,
            success=success,
            steps_completed=steps_completed,
            total_steps=total_steps,
            steps_results=steps_results,
            findings_generated=findings_generated,
            attack_path=attack_path,
        )
        self._executed_chains[chain.name] = result
        self._results.append(result)
        self._discovered_paths.append(attack_path)

        if success:
            logger.success(f"ChainExecutor: '{chain.name}' COMPLETED ({findings_generated} findings)")
            self._learning.record_technique(
                technique=f"chain:{chain.name}",
                target_tech=self.target,
                success=True,
                execution_time=sum(
                    r.get("duration", 0) for r in steps_results
                ),
                tags=chain.tags,
            )
        else:
            logger.info(f"ChainExecutor: '{chain.name}' partial ({steps_completed}/{total_steps})")
            self._learning.record_technique(
                technique=f"chain:{chain.name}",
                target_tech=self.target,
                success=False,
                tags=chain.tags,
            )

        self._post_to_blackboard(chain, result)
        return result

    async def _execute_step_dynamic(
        self,
        step: ChainStep,
        chain: ExploitChain,
        findings: List[Finding],
    ) -> Dict[str, Any]:
        """Enhanced step execution with multi-signal detection."""
        from itzraven.core.http_client import SharedHttpClient
        client = await SharedHttpClient.get_instance()
        step_findings: List[Finding] = []
        step_success = False
        step_error: Optional[str] = None
        start_time = asyncio.get_event_loop().time()

        for technique in step.techniques:
            try:
                if "http://" in technique or "https://" in technique:
                    url = technique.replace("TARGET", self.target)
                    resp = await client.get(url, timeout=30.0)
                    if resp.status_code < 500:
                        text_lower = resp.text.lower()

                        for indicator in step.success_indicators:
                            if indicator.lower() in text_lower:
                                step_success = True
                                evidence = resp.text[:500]
                                if len(evidence) > 500:
                                    evidence = evidence[:497] + "..."
                                step_findings.append(Finding(
                                    title=f"[{chain.name}] {step.name}",
                                    description=f"Step succeeded via {technique}",
                                    severity=chain.severity,
                                    category=chain.category.value,
                                    evidence=evidence,
                                ))
                                break

                        for fail_indicator in step.failure_indicators:
                            if fail_indicator.lower() in text_lower:
                                step_success = False
                                step_error = f"Failure indicator matched: {fail_indicator}"
                                break
                else:
                    logger.debug(f"Non-HTTP technique for step {step.name}: {technique}")
            except Exception as e:
                step_error = str(e)

        duration = asyncio.get_event_loop().time() - start_time

        if not step_success and step_error is None:
            for finding in findings:
                text = (finding.title + " " + finding.description + " " + finding.evidence).lower()
                if any(indicator.lower() in text for indicator in step.success_indicators):
                    step_success = True
                    step_findings.append(finding)
                    break

        return {
            "step": step.name,
            "success": step_success,
            "findings": step_findings,
            "error": step_error,
            "duration": duration,
        }

    def _post_to_blackboard(self, chain: ExploitChain, result: ChainExecutionResult):
        self._bb.post(
            category=FindingCategory.EXPLOIT_CHAIN,
            key=f"chain:{chain.name}",
            data={
                "chain_name": chain.name,
                "success": result.success,
                "steps_completed": result.steps_completed,
                "total_steps": result.total_steps,
                "findings_generated": result.findings_generated,
            },
            source_agent="ChainExecutor",
            pheromone=1.0 if result.success else 0.5,
            tags=chain.tags,
        )

    def auto_discover_attack_paths(
        self, findings: List[Finding]
    ) -> List[AttackPath]:
        """XBOW-inspired: automatically discover attack paths from findings."""
        finding_titles = [f.title for f in findings]
        finding_texts = " ".join(
            f.title + " " + f.description + " " + f.evidence for f in findings
        ).lower()

        matched_chains = find_matching_chains(finding_titles)
        attack_paths = []

        for mc in matched_chains:
            chain = get_chain(mc["chain"])
            if not chain:
                continue

            completed = mc["steps_completed"]
            next_step_name = chain.steps[completed].name if completed < len(chain.steps) else None

            prereq_met = mc.get("prerequisites_met", "0/0")
            prereq_parts = prereq_met.split("/")
            prereq_ratio = int(prereq_parts[0]) / max(int(prereq_parts[1]), 1) if len(prereq_parts) == 2 else 0

            confidence = 0.0
            if completed > 0:
                confidence = completed / len(chain.steps) * 0.7 + prereq_ratio * 0.3
            else:
                confidence = prereq_ratio * 0.5

            attack_paths.append(AttackPath(
                chain_name=chain.name,
                category=chain.category.value,
                severity=self._calculate_path_severity(chain, completed),
                steps_completed=completed,
                total_steps=len(chain.steps),
                next_step=next_step_name,
                confidence=confidence,
                prerequisite_met=completed > 0 or prereq_ratio > 0,
                tags=chain.tags,
            ))

        attack_paths.sort(key=lambda p: (p.confidence, p.severity), reverse=True)
        self._discovered_paths = attack_paths
        return attack_paths

    def _calculate_path_severity(self, chain: ExploitChain, steps_completed: int) -> str:
        sevs = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        base = sevs.get(chain.severity, 2)
        progress_bonus = steps_completed / len(chain.steps)
        adjusted = base + progress_bonus
        reverse_map = {v: k for k, v in sevs.items()}
        capped = min(4, int(adjusted))
        return reverse_map.get(capped, "medium")

    async def suggest_and_execute(
        self,
        findings: List[Finding],
        max_chains: int = 3,
    ) -> List[ChainExecutionResult]:
        finding_titles = [f.title for f in findings]
        attack_paths = self.auto_discover_attack_paths(findings)

        executed = []
        matched_chains = find_matching_chains(finding_titles)
        prioritized = sorted(
            matched_chains,
            key=lambda x: (x["steps_completed"], x.get("prerequisites_met", "0/0")),
            reverse=True,
        )

        for mc in prioritized[:max_chains]:
            chain = get_chain(mc["chain"])
            if chain and chain.name not in self._executed_chains:
                result = await self.execute_chain(chain, findings)
                executed.append(result)

        return executed

    def get_attack_paths(self) -> List[AttackPath]:
        return self._discovered_paths

    def get_results(self) -> List[ChainExecutionResult]:
        return self._results

    def get_summary(self) -> Dict[str, Any]:
        return {
            "total_chains": len(CHAINS),
            "executed_chains": len(self._executed_chains),
            "successful_chains": sum(1 for r in self._results if r.success),
            "failed_chains": sum(1 for r in self._results if not r.success),
            "discovered_paths": [p.to_dict() for p in self._discovered_paths],
            "results": [r.to_dict() for r in self._results],
        }


_chain_executor: Optional[ChainExecutor] = None


def get_chain_executor(target: str) -> ChainExecutor:
    global _chain_executor
    if _chain_executor is None or _chain_executor.target != target:
        _chain_executor = ChainExecutor(target=target)
    return _chain_executor
