"""
Shadow-mode agent gating evaluator (Phase-1).

This module computes "would run / defer / skip" decisions without changing
actual orchestrator execution behavior.

Also provides the 7-Question Validation Gate for detailed finding validation.
"""

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from itzraven.agents.base_agent import Finding
from itzraven.core.logger import get_logger

logger = get_logger()

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
class GatingDecision:
    """Decision artifact for shadow-mode reporting."""

    agent_name: str
    decision: str  # run|defer|skip
    confidence: float
    hard_gates_met: List[str]
    soft_signals: List[str]
    blockers: List[str]
    reason: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "agent_name": self.agent_name,
            "decision": self.decision,
            "confidence": round(self.confidence, 2),
            "hard_gates_met": self.hard_gates_met,
            "soft_signals": self.soft_signals,
            "blockers": self.blockers,
            "reason": self.reason,
        }


class GatingEvaluator:
    """Evaluate Strix-style gating decisions from observed findings/signals."""

    SKIP_THRESHOLD = 0.45
    RUN_THRESHOLD = 0.70

    def evaluate(self, findings: List[Finding]) -> List[Dict[str, Any]]:
        text = self._build_text(findings)
        decisions = [
            self._evaluate_xss(text),
            self._evaluate_sqli(text),
            self._evaluate_auth(text),
            self._evaluate_ssrf(text),
            self._evaluate_cmd_injection(text),
            self._evaluate_idor(text),
            self._evaluate_path_traversal(text),
            self._evaluate_template_injection(text),
        ]
        return [decision.to_dict() for decision in decisions]

    # ------------------------------------------------------------------
    # 7-Question Validation Gate
    # ------------------------------------------------------------------

    def validate_finding(self, finding: Finding) -> Dict[str, Any]:
        title_lower = (finding.title or "").lower()

        if self._is_never_submit(title_lower):
            return {
                "finding_id": finding.finding_id,
                "overall": "KILL",
                "q_scores": [],
                "summary": (
                    f"Auto-killed: '{finding.title}' is on NEVER_SUBMIT_LIST "
                    "(informational/low-value finding)."
                ),
            }

        q_scores = [
            self._q_reproducible(finding),
            self._q_attack_vector(finding),
            self._q_business_impact(finding),
            self._q_known_vulnerability(finding),
            self._q_provable_poc(finding),
            self._q_in_scope(finding),
            self._q_valid_fix(finding),
        ]

        overall = self._resolve_overall(q_scores)
        summary = self._build_summary(overall, q_scores, finding)

        return {
            "finding_id": finding.finding_id,
            "overall": overall,
            "q_scores": q_scores,
            "summary": summary,
        }

    def _is_never_submit(self, title_lower: str) -> bool:
        for pattern in NEVER_SUBMIT_LIST:
            if pattern in title_lower:
                return True
        return False

    # --- Q1: Reproducible? ---

    def _q_reproducible(self, finding: Finding) -> Dict[str, Any]:
        evidence = (finding.evidence or "").strip()
        poc = (finding.proof_of_concept or "").strip()
        steps = finding.reproducibility_steps or []

        has_strong_evidence = len(evidence) >= 50
        has_poc = bool(poc)
        has_steps = len(steps) >= 2

        if has_strong_evidence and has_poc and has_steps:
            return {"status": "PASS", "reason": "Strong evidence with PoC and reproducibility steps.", "confidence": 0.95}
        if has_strong_evidence and has_steps:
            return {"status": "PASS", "reason": "Strong evidence with reproducibility steps (no PoC).", "confidence": 0.80}
        if has_poc:
            return {"status": "CHAIN", "reason": "PoC present but evidence quality is low; chain for manual review.", "confidence": 0.55}
        if has_strong_evidence:
            return {"status": "DOWNGRADE", "reason": "Evidence present but lacks reproducibility steps and PoC.", "confidence": 0.45}
        if has_steps:
            return {"status": "DOWNGRADE", "reason": "Reproducibility steps present but evidence is weak.", "confidence": 0.35}

        return {"status": "KILL", "reason": "No evidence, no PoC, no reproducibility steps.", "confidence": 0.05}

    # --- Q2: Attack Vector? ---

    def _q_attack_vector(self, finding: Finding) -> Dict[str, Any]:
        text = self._build_text([finding])
        av_keywords = [
            "parameter", "endpoint", "request", "inject", "payload",
            "vector", "url", "input", "bypass", "exploit", "trigger",
            "header", "cookie", "query",
        ]
        matches = sum(1 for kw in av_keywords if kw in text)

        if matches >= 4:
            return {"status": "PASS", "reason": f"Clear attack vector described ({matches} signals).", "confidence": 0.90}
        if matches >= 2:
            return {"status": "PASS", "reason": f"Attack vector is present ({matches} signals).", "confidence": 0.70}
        if matches >= 1:
            return {"status": "DOWNGRADE", "reason": "Vague attack vector; only weak signals found.", "confidence": 0.40}

        return {"status": "KILL", "reason": "No attack vector described.", "confidence": 0.05}

    # --- Q3: Business Impact? ---

    def _q_business_impact(self, finding: Finding) -> Dict[str, Any]:
        sev = finding.severity.lower()
        text = self._build_text([finding])
        impact_keywords = [
            "data", "pii", "breach", "authentication", "bypass", "admin",
            "privilege", "account", "takeover", "execution", "exfiltration",
        ]
        impact_matches = sum(1 for kw in impact_keywords if kw in text)

        if sev == "critical":
            return {"status": "PASS", "reason": "Critical severity finding with direct business impact.", "confidence": 0.95}
        if sev == "high":
            return {"status": "PASS", "reason": "High severity finding with significant business impact.", "confidence": 0.85}
        if sev == "medium":
            if impact_matches >= 2:
                return {"status": "CHAIN", "reason": f"Medium severity but context suggests higher impact ({impact_matches} signals).", "confidence": 0.65}
            return {"status": "DOWNGRADE", "reason": "Medium severity finding with moderate business impact.", "confidence": 0.60}
        if sev == "low":
            return {"status": "DOWNGRADE", "reason": "Low severity finding with limited business impact.", "confidence": 0.35}
        return {"status": "KILL", "reason": "Informational finding with no measurable business impact.", "confidence": 0.10}

    # --- Q4: Known Vulnerability? ---

    def _q_known_vulnerability(self, finding: Finding) -> Dict[str, Any]:
        text = self._build_text([finding])

        cve_pattern = r"cve-\d{4}-\d{4,7}"
        has_cve = bool(re.search(cve_pattern, text, re.IGNORECASE))

        known_patterns = [
            "known vulnerability", "advisory", "cve", "cwe", "nvd",
            "metasploit", "exploit-db", "known exploit", "hacktivity",
            "bug bounty", "disclosed", "0day", "zeroday",
        ]
        known_matches = sum(1 for kw in known_patterns if kw in text)

        false_positive_patterns = [
            "false positive", "non-exploitable", "cannot reproduce",
            "expected behavior", "by design", "won't fix",
        ]
        fp_matches = sum(1 for kw in false_positive_patterns if kw in text)

        if fp_matches > 0:
            return {"status": "KILL", "reason": f"Flagged as known false positive ({fp_matches} signals).", "confidence": 0.10}
        if has_cve:
            return {"status": "PASS", "reason": "Matches a known CVE reference.", "confidence": 0.95}
        if known_matches >= 2:
            return {"status": "PASS", "reason": f"Matches known vulnerability patterns ({known_matches} signals).", "confidence": 0.80}
        if known_matches >= 1:
            return {"status": "CHAIN", "reason": "Weakly matches known vulnerability patterns; chain for research.", "confidence": 0.50}

        return {"status": "PASS", "reason": "No known vulnerability reference but finding appears novel.", "confidence": 0.60}

    # --- Q5: Provable PoC? ---

    def _q_provable_poc(self, finding: Finding) -> Dict[str, Any]:
        poc = (finding.proof_of_concept or "").strip()
        severity = finding.severity.lower()

        if not poc:
            if severity in {"critical", "high"}:
                return {"status": "DOWNGRADE", "reason": "No PoC for critical/high finding; downgrading.", "confidence": 0.30}
            return {"status": "KILL", "reason": "No PoC provided; cannot prove vulnerability.", "confidence": 0.10}

        chain_keywords = ["combined with", "chained with", "requires", "dependent on", "if attacker has"]
        has_chain = any(kw in poc.lower() for kw in chain_keywords)

        try:
            compile(poc, "<poc>", "exec")
            if has_chain:
                return {"status": "CHAIN", "reason": "Executable PoC requires chained conditions.", "confidence": 0.70}
            return {"status": "PASS", "reason": "Valid executable Python PoC provided.", "confidence": 0.95}
        except SyntaxError:
            if has_chain:
                return {"status": "CHAIN", "reason": "Non-executable PoC with chained attack description.", "confidence": 0.50}
            return {"status": "DOWNGRADE", "reason": "PoC is not executable Python code.", "confidence": 0.35}

    # --- Q6: In Scope? ---

    def _q_in_scope(self, finding: Finding) -> Dict[str, Any]:
        target = getattr(finding, 'target', '') or ''
        scope = getattr(finding, '_scope', None)

        if scope:
            target_lower = target.lower()
            for pattern in scope:
                if pattern.lower() in target_lower:
                    return {"status": "PASS", "reason": f"Target matches scope pattern: {pattern}.", "confidence": 0.90}
            return {"status": "KILL", "reason": "Target is outside defined scope.", "confidence": 0.10}

        text = self._build_text([finding])
        out_of_scope = [
            "third-party", "out of scope", "cdn", "external service",
            "acquired domain", "deprecated",
        ]
        oos_matches = sum(1 for kw in out_of_scope if kw in text)
        if oos_matches > 0:
            return {"status": "KILL", "reason": f"Finding references out-of-scope assets ({oos_matches} signals).", "confidence": 0.15}

        return {"status": "PASS", "reason": "No scope restrictions; finding is considered in scope.", "confidence": 0.85}

    # --- Q7: Valid Fix? ---

    def _q_valid_fix(self, finding: Finding) -> Dict[str, Any]:
        remediation = (finding.remediation or "").strip()
        fix_hint = (finding.fix_hint or "").strip()

        has_remediation = bool(remediation)
        has_fix_hint = bool(fix_hint)

        quality_keywords = [
            "implement", "configure", "validate", "sanitize", "escape",
            "encode", "filter", "disable", "remove", "update", "upgrade",
            "patch", "use prepared statement", "parameterized query",
            "input validation", "output encoding", "access control",
            "rate limit", "authentication", "authorization",
        ]

        combined_text = (remediation + " " + fix_hint).lower()
        quality_matches = sum(1 for kw in quality_keywords if kw in combined_text)

        if has_remediation and quality_matches >= 2:
            return {"status": "PASS", "reason": f"Detailed remediation with actionable steps ({quality_matches} signals).", "confidence": 0.90}
        if has_remediation:
            return {"status": "PASS", "reason": "Remediation provided.", "confidence": 0.70}
        if has_fix_hint:
            return {"status": "DOWNGRADE", "reason": "Only a fix hint provided; no full remediation.", "confidence": 0.40}

        return {"status": "KILL", "reason": "No remediation or fix hint provided.", "confidence": 0.10}

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _resolve_overall(self, q_scores: List[Dict[str, Any]]) -> str:
        statuses = [q["status"] for q in q_scores]
        if "KILL" in statuses:
            return "KILL"
        if "DOWNGRADE" in statuses and "CHAIN" not in statuses:
            return "DOWNGRADE"
        if "CHAIN" in statuses:
            return "CHAIN"
        if all(s == "PASS" for s in statuses):
            return "PASS"
        return "PASS"

    def _build_summary(self, overall: str, q_scores: List[Dict[str, Any]], finding: Finding) -> str:
        pass_count = sum(1 for q in q_scores if q["status"] == "PASS")
        kill_count = sum(1 for q in q_scores if q["status"] == "KILL")
        dg_count = sum(1 for q in q_scores if q["status"] == "DOWNGRADE")
        chain_count = sum(1 for q in q_scores if q["status"] == "CHAIN")
        avg_conf = sum(q["confidence"] for q in q_scores) / max(len(q_scores), 1)

        parts = [
            f"7-Q Gate: {overall}",
            f"PASS={pass_count} KILL={kill_count} DOWNGRADE={dg_count} CHAIN={chain_count}",
            f"avg_confidence={avg_conf:.2f}",
        ]
        if overall == "KILL":
            killed = [q for q in q_scores if q["status"] == "KILL"]
            reasons = "; ".join(q["reason"] for q in killed)
            parts.append(f"killed_by: {reasons}")
        elif overall == "DOWNGRADE":
            downgraded = [q for q in q_scores if q["status"] == "DOWNGRADE"]
            reasons = "; ".join(q["reason"] for q in downgraded)
            parts.append(f"downgraded_by: {reasons}")
        elif overall == "CHAIN":
            chained = [q for q in q_scores if q["status"] == "CHAIN"]
            reasons = "; ".join(q["reason"] for q in chained)
            parts.append(f"chained_by: {reasons}")

        return " | ".join(parts)

    def _build_text(self, findings: List[Finding]) -> str:
        chunks: List[str] = []
        for finding in findings:
            chunks.extend(
                [
                    finding.title or "",
                    finding.description or "",
                    finding.category or "",
                    finding.evidence or "",
                    finding.proof_of_concept or "",
                    finding.remediation or "",
                ]
            )
        return " ".join(chunks).lower()

    def _evaluate_xss(self, text: str) -> GatingDecision:
        hard, soft, blockers = self._base_signals(
            text=text,
            hard_checks=[
                ("reflected_input_sink", ["xss", "cross-site scripting", "reflected xss"]),
                ("user_controlled_html_js_context", ["user input", "query parameter", "form input", "javascript context"]),
            ],
            soft_checks=[
                ("form_fields_present", ["form", "input field", "<input"]),
                ("query_parameters_present", ["query param", "url parameter", "parameter"]),
                ("weak_csp_hints", ["csp", "content-security-policy"]),
            ],
        )
        return self._finalize("XSS Agent", hard, soft, blockers)

    def _evaluate_sqli(self, text: str) -> GatingDecision:
        hard, soft, blockers = self._base_signals(
            text=text,
            hard_checks=[
                ("db_injection_signal", ["sql injection", "sqli", "sql error", "database error"]),
                ("injectable_param_signal", ["parameter", "id=", "query", "payload"]),
            ],
            soft_checks=[
                ("db_backend_hints", ["mysql", "postgres", "sqlite", "database"]),
                ("timing_or_error_patterns", ["time-based", "stack trace", "sql syntax"]),
                ("orm_query_hints", ["orm", "query builder", "raw query"]),
            ],
        )
        return self._finalize("SQLi Agent", hard, soft, blockers)

    def _evaluate_auth(self, text: str) -> GatingDecision:
        hard, soft, blockers = self._base_signals(
            text=text,
            hard_checks=[
                ("auth_surface_detected", ["login", "signin", "authentication", "session", "jwt", "cookie"]),
            ],
            soft_checks=[
                ("token_handling_hints", ["bearer", "refresh token", "access token"]),
                ("role_boundary_hints", ["admin", "privilege", "role"]),
            ],
        )
        return self._finalize("Auth/Session Agent", hard, soft, blockers)

    def _evaluate_ssrf(self, text: str) -> GatingDecision:
        hard, soft, blockers = self._base_signals(
            text=text,
            hard_checks=[
                ("server_side_fetch_input", ["fetch url", "webhook", "callback url", "url import", "ssrf"]),
            ],
            soft_checks=[
                ("outbound_request_hints", ["internal ip", "metadata service", "169.254.169.254"]),
                ("proxy_or_fetch_feature", ["proxy endpoint", "remote fetch"]),
            ],
        )
        return self._finalize("SSRF Agent", hard, soft, blockers)

    def _evaluate_cmd_injection(self, text: str) -> GatingDecision:
        hard, soft, blockers = self._base_signals(
            text=text,
            hard_checks=[
                ("command_execution_path", ["command injection", "os command", "shell", "bash", "cmd.exe"]),
            ],
            soft_checks=[
                ("shell_error_hints", ["command not found", "sh:", "/bin/sh"]),
                ("unsafe_exec_hints", ["exec(", "subprocess", "popen"]),
            ],
        )
        return self._finalize("Command Injection Agent", hard, soft, blockers)

    def _evaluate_idor(self, text: str) -> GatingDecision:
        hard, soft, blockers = self._base_signals(
            text=text,
            hard_checks=[
                ("object_reference_surface", ["idor", "insecure direct object reference", "/users/", "/orders/", "resource id"]),
                ("auth_context_present", ["authorization", "role", "access control", "forbidden"]),
            ],
            soft_checks=[
                ("predictable_identifier_hints", ["incremental id", "uuid", "numeric id"]),
            ],
        )
        return self._finalize("IDOR Agent", hard, soft, blockers)

    def _evaluate_path_traversal(self, text: str) -> GatingDecision:
        hard, soft, blockers = self._base_signals(
            text=text,
            hard_checks=[
                ("file_path_input_surface", ["path traversal", "../", "..\\", "file read", "download file"]),
            ],
            soft_checks=[
                ("file_endpoint_hints", ["attachment", "export", "read file", "local file inclusion"]),
            ],
        )
        return self._finalize("Path Traversal Agent", hard, soft, blockers)

    def _evaluate_template_injection(self, text: str) -> GatingDecision:
        hard, soft, blockers = self._base_signals(
            text=text,
            hard_checks=[
                ("template_rendering_vector", ["template injection", "ssti", "{{", "{%", "jinja", "twig"]),
            ],
            soft_checks=[
                ("engine_fingerprint_hints", ["jinja2", "handlebars", "mustache", "template engine"]),
            ],
        )
        return self._finalize("Template Injection Agent", hard, soft, blockers)

    def _base_signals(
        self,
        text: str,
        hard_checks: List[tuple[str, List[str]]],
        soft_checks: List[tuple[str, List[str]]],
    ) -> tuple[List[str], List[str], List[str]]:
        hard_gates = [name for name, keywords in hard_checks if self._contains_any(text, keywords)]
        soft_signals = [name for name, keywords in soft_checks if self._contains_any(text, keywords)]
        blockers: List[str] = []
        if not hard_gates:
            blockers.append("missing_hard_gate_signals")
        return hard_gates, soft_signals, blockers

    def _finalize(
        self,
        agent_name: str,
        hard_gates_met: List[str],
        soft_signals: List[str],
        blockers: List[str],
    ) -> GatingDecision:
        score = min(0.7, 0.45 * len(hard_gates_met))
        score += 0.1 * len(soft_signals)
        if "missing_hard_gate_signals" in blockers:
            score -= 0.15
        score = max(0.0, min(1.0, score))

        if score >= self.RUN_THRESHOLD and not blockers:
            decision = "run"
            reason = "Hard gates satisfied with sufficient confidence."
        elif score >= self.SKIP_THRESHOLD:
            decision = "defer"
            reason = "Partial evidence found; defer to lightweight validation."
        else:
            decision = "skip"
            reason = "Insufficient prerequisite signals in current evidence."

        return GatingDecision(
            agent_name=agent_name,
            decision=decision,
            confidence=score,
            hard_gates_met=hard_gates_met,
            soft_signals=soft_signals,
            blockers=blockers,
            reason=reason,
        )

    def _contains_any(self, text: str, keywords: List[str]) -> bool:
        return any(keyword in text for keyword in keywords)
