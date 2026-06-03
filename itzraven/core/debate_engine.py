"""
Collaborative Multi-Agent Debate — agents apne findings pe debate kare.
Do agents same target scan kare, phir LLM unke disagreement resolve kare.
"""

import json
import time
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field

from itzraven.core.logger import get_logger
from itzraven.agents.llm_client import LLMClient
from itzraven.agents.base_agent import Finding

logger = get_logger()


@dataclass
class DebatePosition:
    agent_name: str
    claim: str
    evidence: List[str]
    confidence: float
    counter_arguments: List[str] = field(default_factory=list)


@dataclass
class DebateRound:
    topic: str
    positions: List[DebatePosition]
    consensus: Optional[str] = None
    consensus_confidence: float = 0.0
    resolved: bool = False
    timestamp: float = field(default_factory=time.time)


@dataclass
class DebateResult:
    finding_title: str
    agent_a_verdict: str
    agent_b_verdict: str
    consensus: str
    evidence_summary: str
    confidence: float


class DebateEngine:
    _instance = None

    def __init__(self):
        self.llm = LLMClient()
        self.debates: List[DebateRound] = []
        self.results: List[DebateResult] = []

    @classmethod
    def get_instance(cls) -> "DebateEngine":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    async def debate_finding(self, finding: Finding,
                             agent_a_findings: List[Finding],
                             agent_b_findings: List[Finding]) -> DebateResult:
        prompt = (
            "Two security AI agents have analyzed the same target and disagree on a finding.\n\n"
            f"Finding being debated:\n"
            f"Title: {finding.title}\n"
            f"Description: {finding.description[:300]}\n"
            f"Severity: {finding.severity}\n\n"
            f"Agent A findings:\n"
            + "\n".join(f"  - [{f.severity}] {f.title}" for f in agent_a_findings[:5]) + "\n\n"
            f"Agent B findings:\n"
            + "\n".join(f"  - [{f.severity}] {f.title}" for f in agent_b_findings[:5]) + "\n\n"
            "Analyze both perspectives and:\n"
            "1. Identify where they agree\n"
            "2. Identify where they disagree\n"
            "3. Determine which position has stronger evidence\n"
            "4. Reach a consensus verdict\n\n"
            "Output JSON:\n"
            "{\n"
            '  "agent_a_verdict": "verdict from agent A perspective",\n'
            '  "agent_b_verdict": "verdict from agent B perspective",\n'
            '  "consensus": "final consensus",\n'
            '  "evidence_summary": "key evidence summary",\n'
            '  "confidence": 0.0-1.0,\n'
            '  "key_disagreements": ["point1", "point2"]\n'
            "}"
        )
        system = (
            "You are a senior security judge mediating a debate between two AI agents. "
            "You objectively evaluate evidence from both sides and reach a fair consensus."
        )

        try:
            resp = await self.llm.generate(prompt=prompt, system=system, max_tokens=1000, task="debate")
            raw = resp.content
            parsed = json.loads(raw) if isinstance(raw, str) else raw
        except Exception as e:
            logger.debug(f"Debate parse failed: {e}")
            parsed = {
                "agent_a_verdict": f"Found {finding.title}",
                "agent_b_verdict": f"Did not find {finding.title}",
                "consensus": "Debate engine failed to reach consensus",
                "evidence_summary": str(e),
                "confidence": 0.5,
            }

        result = DebateResult(
            finding_title=finding.title,
            agent_a_verdict=parsed.get("agent_a_verdict", "N/A"),
            agent_b_verdict=parsed.get("agent_b_verdict", "N/A"),
            consensus=parsed.get("consensus", "No consensus"),
            evidence_summary=parsed.get("evidence_summary", ""),
            confidence=float(parsed.get("confidence", 0.5)),
        )
        self.results.append(result)

        round_record = DebateRound(
            topic=finding.title,
            positions=[
                DebatePosition(agent_name="Agent A", claim=parsed.get("agent_a_verdict", ""),
                               evidence=[], confidence=0.7),
                DebatePosition(agent_name="Agent B", claim=parsed.get("agent_b_verdict", ""),
                               evidence=[], confidence=0.7),
            ],
            consensus=parsed.get("consensus"),
            consensus_confidence=float(parsed.get("confidence", 0.5)),
            resolved=True,
        )
        self.debates.append(round_record)
        logger.info(f"Debate: {finding.title} → consensus={result.consensus[:50]}... confidence={result.confidence:.2f}")

        return result

    async def cross_validate_findings(self, all_findings: List[Finding],
                                       agent_separated: Dict[str, List[Finding]]) -> List[DebateResult]:
        results = []
        for finding in all_findings:
            if len(agent_separated) < 2:
                continue
            agents = list(agent_separated.keys())
            result = await self.debate_finding(finding, agent_separated[agents[0]], agent_separated[agents[1]])
            results.append(result)
        return results

    def get_consensus_findings(self, min_confidence: float = 0.7) -> List[DebateResult]:
        return [r for r in self.results if r.confidence >= min_confidence]

    def get_disputed_findings(self) -> List[DebateResult]:
        return [r for r in self.results if r.confidence < 0.6]

    def get_stats(self) -> dict:
        return {
            "total_debates": len(self.debates),
            "resolved": sum(1 for d in self.debates if d.resolved),
            "consensus_findings": len(self.get_consensus_findings()),
            "disputed_findings": len(self.get_disputed_findings()),
        }


get_debate_engine = DebateEngine.get_instance
