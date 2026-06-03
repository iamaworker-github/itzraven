"""
CBH-style 7-Question Validation Gate for finding quality control.

PASS / DOWNGRADE / KILL / CHAIN verdict with structured output.
Integrated into the finding pipeline to prevent low-quality reports.
"""

from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Tuple
from enum import Enum

from itzraven.agents.base_agent import Finding
from itzraven.core.logger import get_logger

logger = get_logger()


class GateVerdict(Enum):
    PASS = "PASS"
    DOWNGRADE = "DOWNGRADE"
    KILL = "KILL"
    CHAIN = "CHAIN"


NEVER_SUBMIT_LIST = [
    "server header disclosure",
    "cookie not secure",
    "x-powered-by header",
    "x-aspnet-version header",
    "directory listing enabled",
    "email disclosure",
    "internal ip disclosure",
    "ssl certificate info",
    "robots.txt disclosure",
    "composer.json exposure",
    "debug mode enabled",
    "stack trace disclosure",
    "x-frame-options missing",
    "x-content-type-options missing",
    "ssl weak cipher",
    "hsts missing",
    "missing security headers",
    "information disclosure via headers",
]


@dataclass
class QuestionResult:
    number: int
    name: str
    status: str  # PASS / DOWNGRADE / KILL / CHAIN
    confidence: float
    reason: str


@dataclass
class TriageResult:
    finding_id: str
    verdict: GateVerdict
    question_results: List[QuestionResult] = field(default_factory=list)
    summary: str = ""
    confidence: float = 0.0

    @property
    def is_killed(self) -> bool:
        return self.verdict == GateVerdict.KILL

    @property
    def is_passed(self) -> bool:
        return self.verdict == GateVerdict.PASS

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "verdict": self.verdict.value,
            "confidence": round(self.confidence, 2),
            "summary": self.summary,
            "questions": [
                {"q": q.number, "name": q.name, "status": q.status,
                 "confidence": round(q.confidence, 2), "reason": q.reason}
                for q in self.question_results
            ],
        }


class TriageGate:
    """CBH-style 7-Question Validation Gate for finding quality control."""

    Q1_REPRODUCIBLE = "Reproducible with real HTTP request"
    Q2_ACCEPTED_IMPACT = "Impact on accepted-impact list"
    Q3_IN_SCOPE = "Asset in scope"
    Q4_NO_ADMIN_ASSUMPTION = "No admin-only privilege assumption"
    Q5_NOT_ALREADY_KNOWN = "Not already known or documented behavior"
    Q6_CONCRETE_IMPACT = "Concrete provable impact"
    Q7_NOT_NEVER_SUBMIT = "Not on never-submit list"

    def evaluate(self, finding: Finding) -> TriageResult:
        title_lower = (finding.title or "").lower()

        if self._is_never_submit(title_lower):
            questions = [
                QuestionResult(7, self.Q7_NOT_NEVER_SUBMIT, "KILL", 0.05,
                               f"'{finding.title}' is on NEVER_SUBMIT_LIST"),
            ]
            return TriageResult(
                finding_id=finding.finding_id or "",
                verdict=GateVerdict.KILL,
                question_results=questions,
                summary="Auto-killed: finding on never-submit list",
                confidence=0.05,
            )

        questions = [
            self._q1_reproducible(finding),
            self._q2_accepted_impact(finding),
            self._q3_in_scope(finding),
            self._q4_no_admin_assumption(finding),
            self._q5_not_already_known(finding),
            self._q6_concrete_impact(finding),
            self._q7_not_never_submit(finding),
        ]

        verdict = self._resolve_verdict(questions)
        summary = self._build_summary(verdict, questions, finding)
        avg_conf = sum(q.confidence for q in questions) / max(len(questions), 1)

        return TriageResult(
            finding_id=finding.finding_id or "",
            verdict=verdict,
            question_results=questions,
            summary=summary,
            confidence=avg_conf,
        )

    def _is_never_submit(self, title_lower: str) -> bool:
        for pattern in NEVER_SUBMIT_LIST:
            if pattern in title_lower:
                return True
        return False

    # --- Q1: Reproducible? ---
    def _q1_reproducible(self, finding: Finding) -> QuestionResult:
        evidence = (finding.evidence or "").strip()
        poc = (finding.proof_of_concept or "").strip()
        steps = finding.reproducibility_steps or []

        has_strong_evidence = len(evidence) >= 50
        has_poc = bool(poc)
        has_steps = len(steps) >= 2

        if has_strong_evidence and has_poc and has_steps:
            return QuestionResult(1, self.Q1_REPRODUCIBLE, "PASS", 0.95,
                                  "Strong evidence with PoC and reproducibility steps")
        if has_strong_evidence and has_steps:
            return QuestionResult(1, self.Q1_REPRODUCIBLE, "PASS", 0.80,
                                  "Strong evidence with reproducibility steps (no PoC)")
        if has_poc:
            return QuestionResult(1, self.Q1_REPRODUCIBLE, "CHAIN", 0.55,
                                  "PoC present but evidence quality low; chain for review")
        if has_strong_evidence:
            return QuestionResult(1, self.Q1_REPRODUCIBLE, "DOWNGRADE", 0.45,
                                  "Evidence present but lacks PoC and reproducibility steps")
        if has_steps:
            return QuestionResult(1, self.Q1_REPRODUCIBLE, "DOWNGRADE", 0.35,
                                  "Steps present but evidence is weak")

        return QuestionResult(1, self.Q1_REPRODUCIBLE, "KILL", 0.05,
                              "No evidence, PoC, or reproducibility steps")

    # --- Q2: Accepted Impact? ---
    def _q2_accepted_impact(self, finding: Finding) -> QuestionResult:
        sev = finding.severity.lower()
        text = self._build_text(finding)
        impact_keywords = ["data", "pii", "breach", "authentication", "bypass",
                           "admin", "privilege", "account", "takeover", "execution",
                           "exfiltration", "unauthorized", "access"]
        matches = sum(1 for kw in impact_keywords if kw in text)

        if sev == "critical":
            return QuestionResult(2, self.Q2_ACCEPTED_IMPACT, "PASS", 0.95,
                                  "Critical severity finding with direct business impact")
        if sev == "high":
            return QuestionResult(2, self.Q2_ACCEPTED_IMPACT, "PASS", 0.85,
                                  "High severity finding with significant business impact")
        if sev == "medium":
            if matches >= 2:
                return QuestionResult(2, self.Q2_ACCEPTED_IMPACT, "CHAIN", 0.65,
                                      f"Medium severity but context suggests higher impact ({matches} signals)")
            return QuestionResult(2, self.Q2_ACCEPTED_IMPACT, "DOWNGRADE", 0.55,
                                  "Medium severity with moderate impact")
        if sev == "low":
            return QuestionResult(2, self.Q2_ACCEPTED_IMPACT, "DOWNGRADE", 0.30,
                                  "Low severity with limited business impact")
        return QuestionResult(2, self.Q2_ACCEPTED_IMPACT, "KILL", 0.10,
                              "Informational finding with no measurable business impact")

    # --- Q3: In Scope? ---
    def _q3_in_scope(self, finding: Finding) -> QuestionResult:
        scope = getattr(finding, '_scope', None) or []
        text = self._build_text(finding)

        if scope:
            for pattern in scope:
                if pattern.lower() in text:
                    return QuestionResult(3, self.Q3_IN_SCOPE, "PASS", 0.90,
                                          f"Target matches scope pattern: {pattern}")
            return QuestionResult(3, self.Q3_IN_SCOPE, "KILL", 0.10,
                                  "Target is outside defined scope")

        oos_keywords = ["third-party", "out of scope", "cdn", "external service",
                        "acquired domain", "deprecated"]
        oos_matches = sum(1 for kw in oos_keywords if kw in text)
        if oos_matches > 0:
            return QuestionResult(3, self.Q3_IN_SCOPE, "KILL", 0.15,
                                  f"Finding references out-of-scope assets ({oos_matches} signals)")

        return QuestionResult(3, self.Q3_IN_SCOPE, "PASS", 0.85,
                              "No scope restrictions; considered in scope")

    # --- Q4: No Admin-Only Assumption? ---
    def _q4_no_admin_assumption(self, finding: Finding) -> QuestionResult:
        text = self._build_text(finding)
        admin_phrases = ["requires admin", "admin access", "authenticated as admin",
                         "assumes admin", "if attacker is admin", "admin privileges",
                         "internal network access", "requires vpn"]
        matches = sum(1 for kw in admin_phrases if kw in text)

        if matches >= 2:
            return QuestionResult(4, self.Q4_NO_ADMIN_ASSUMPTION, "DOWNGRADE", 0.30,
                                  f"Finding assumes admin/internal access ({matches} signals)")
        if matches >= 1:
            return QuestionResult(4, self.Q4_NO_ADMIN_ASSUMPTION, "CHAIN", 0.50,
                                  f"Possible admin-only assumption ({matches} signal); verify")
        return QuestionResult(4, self.Q4_NO_ADMIN_ASSUMPTION, "PASS", 0.90,
                              "No privileged access assumed")

    # --- Q5: Not Already Known? ---
    def _q5_not_already_known(self, finding: Finding) -> QuestionResult:
        text = self._build_text(finding)

        fp_patterns = ["false positive", "non-exploitable", "cannot reproduce",
                       "expected behavior", "by design", "won't fix"]
        fp_matches = sum(1 for kw in fp_patterns if kw in text)

        known_patterns = ["known vulnerability", "advisory", "cve-", "cwe-",
                          "nvd", "metasploit", "exploit-db", "disclosed"]
        known_matches = sum(1 for kw in known_patterns if kw in text)

        if fp_matches > 0:
            return QuestionResult(5, self.Q5_NOT_ALREADY_KNOWN, "KILL", 0.10,
                                  f"Flagged as known false positive ({fp_matches} signals)")
        if known_matches >= 2:
            return QuestionResult(5, self.Q5_NOT_ALREADY_KNOWN, "DOWNGRADE", 0.40,
                                  "Matches known vulnerability; verify novelty")
        return QuestionResult(5, self.Q5_NOT_ALREADY_KNOWN, "PASS", 0.80,
                              "Finding appears novel or unreported")

    # --- Q6: Concrete Impact? ---
    def _q6_concrete_impact(self, finding: Finding) -> QuestionResult:
        poc = (finding.proof_of_concept or "").strip()
        sev = finding.severity.lower()

        if not poc:
            if sev in ("critical", "high"):
                return QuestionResult(6, self.Q6_CONCRETE_IMPACT, "DOWNGRADE", 0.30,
                                      "No PoC for critical/high finding; downgrading")
            return QuestionResult(6, self.Q6_CONCRETE_IMPACT, "KILL", 0.10,
                                  "No PoC; cannot prove concrete impact")

        chain_keywords = ["combined with", "chained with", "requires",
                          "dependent on", "if attacker has"]
        has_chain = any(kw in poc.lower() for kw in chain_keywords)

        try:
            compile(poc, "<poc>", "exec")
            if has_chain:
                return QuestionResult(6, self.Q6_CONCRETE_IMPACT, "CHAIN", 0.65,
                                      "Executable PoC requires chained conditions")
            return QuestionResult(6, self.Q6_CONCRETE_IMPACT, "PASS", 0.95,
                                  "Valid executable Python PoC provided")
        except SyntaxError:
            if has_chain:
                return QuestionResult(6, self.Q6_CONCRETE_IMPACT, "CHAIN", 0.45,
                                      "Non-executable PoC with chained attack")
            return QuestionResult(6, self.Q6_CONCRETE_IMPACT, "DOWNGRADE", 0.35,
                                  "PoC is not executable Python code")

    # --- Q7: Not on Never-Submit List? ---
    def _q7_not_never_submit(self, finding: Finding) -> QuestionResult:
        title_lower = (finding.title or "").lower()
        for pattern in NEVER_SUBMIT_LIST:
            if pattern in title_lower:
                return QuestionResult(7, self.Q7_NOT_NEVER_SUBMIT, "KILL", 0.05,
                                      f"On never-submit list: {pattern}")
        return QuestionResult(7, self.Q7_NOT_NEVER_SUBMIT, "PASS", 0.95,
                              "Not on never-submit list")

    # --- Helpers ---
    def _resolve_verdict(self, questions: List[QuestionResult]) -> GateVerdict:
        statuses = [q.status for q in questions]
        if "KILL" in statuses:
            return GateVerdict.KILL
        if "DOWNGRADE" in statuses and "CHAIN" not in statuses:
            return GateVerdict.DOWNGRADE
        if "CHAIN" in statuses:
            return GateVerdict.CHAIN
        if all(s == "PASS" for s in statuses):
            return GateVerdict.PASS
        return GateVerdict.PASS

    def _build_summary(self, verdict: GateVerdict, questions: List[QuestionResult],
                       finding: Finding) -> str:
        pass_count = sum(1 for q in questions if q.status == "PASS")
        kill_count = sum(1 for q in questions if q.status == "KILL")
        dg_count = sum(1 for q in questions if q.status == "DOWNGRADE")
        chain_count = sum(1 for q in questions if q.status == "CHAIN")
        avg_conf = sum(q.confidence for q in questions) / max(len(questions), 1)

        parts = [
            f"7-Q Gate: {verdict.value}",
            f"P={pass_count} K={kill_count} D={dg_count} C={chain_count}",
            f"conf={avg_conf:.2f}",
        ]
        if verdict == GateVerdict.KILL:
            reasons = "; ".join(q.reason for q in questions if q.status == "KILL")
            parts.append(f"killed: {reasons}")
        elif verdict == GateVerdict.DOWNGRADE:
            reasons = "; ".join(q.reason for q in questions if q.status == "DOWNGRADE")
            parts.append(f"downgraded: {reasons}")
        elif verdict == GateVerdict.CHAIN:
            reasons = "; ".join(q.reason for q in questions if q.status == "CHAIN")
            parts.append(f"chain: {reasons}")

        return " | ".join(parts)

    def _build_text(self, finding: Finding) -> str:
        parts = [
            finding.title or "",
            finding.description or "",
            finding.category or "",
            finding.evidence or "",
            finding.proof_of_concept or "",
            finding.remediation or "",
        ]
        return " ".join(parts).lower()


_triage_gate: Optional[TriageGate] = None


def get_triage_gate() -> TriageGate:
    global _triage_gate
    if _triage_gate is None:
        _triage_gate = TriageGate()
    return _triage_gate
