from itzraven.agents.base_agent import Finding
from itzraven.agents.gating import GatingEvaluator


def _finding(
    *,
    title: str,
    description: str = "",
    category: str = "",
    evidence: str = "",
    proof_of_concept: str = "",
    remediation: str = "",
    severity: str = "medium",
):
    return Finding(
        title=title,
        description=description,
        severity=severity,
        category=category,
        evidence=evidence,
        proof_of_concept=proof_of_concept,
        remediation=remediation,
        agent_name="test-agent",
        finding_id="f-1",
    )


def _decision_for(decisions, agent_name: str):
    return next(d for d in decisions if d["agent_name"] == agent_name)


def test_gating_evaluator_returns_all_core_agent_decisions():
    evaluator = GatingEvaluator()

    decisions = evaluator.evaluate([])

    assert len(decisions) == 8
    for decision in decisions:
        assert decision["decision"] in {"run", "defer", "skip"}
        assert "reason" in decision


def test_gating_evaluator_marks_xss_run_when_hard_signals_present():
    evaluator = GatingEvaluator()
    findings = [
        _finding(
            title="Reflected XSS in search",
            description="user input reflected in javascript context",
            category="xss",
            evidence="query parameter is reflected into page response",
        )
    ]

    decisions = evaluator.evaluate(findings)
    xss = _decision_for(decisions, "XSS Agent")

    assert xss["decision"] == "run"
    assert xss["confidence"] >= 0.7
    assert "missing_hard_gate_signals" not in xss["blockers"]


def test_gating_evaluator_marks_sqli_defer_for_partial_signals():
    evaluator = GatingEvaluator()
    findings = [
        _finding(
            title="Potential SQL error leak",
            description="sql error observed on malformed parameter",
            category="injection",
            evidence="parameter id= triggers db error",
        )
    ]

    decisions = evaluator.evaluate(findings)
    sqli = _decision_for(decisions, "SQLi Agent")

    assert sqli["decision"] in {"defer", "run"}
    assert sqli["confidence"] >= 0.45


def test_gating_evaluator_marks_skip_when_no_relevant_signals():
    evaluator = GatingEvaluator()
    findings = [
        _finding(
            title="Static asset listing",
            description="Only css/js static files discovered",
            category="info",
            evidence="no forms no parameters",
            severity="info",
        )
    ]

    decisions = evaluator.evaluate(findings)
    cmd = _decision_for(decisions, "Command Injection Agent")

    assert cmd["decision"] == "skip"
    assert "missing_hard_gate_signals" in cmd["blockers"]


def test_gating_threshold_policy_baseline_constants():
    evaluator = GatingEvaluator()

    assert evaluator.SKIP_THRESHOLD == 0.45
    assert evaluator.RUN_THRESHOLD == 0.70


def test_gating_threshold_boundary_one_hard_gate_results_in_defer():
    evaluator = GatingEvaluator()
    findings = [
        _finding(
            title="Reflected XSS candidate",
            description="reflected xss observed",
            category="xss",
            evidence="response includes reflected payload",
        )
    ]

    decisions = evaluator.evaluate(findings)
    xss = _decision_for(decisions, "XSS Agent")

    assert xss["confidence"] == 0.45
    assert xss["decision"] == "defer"


def test_gating_threshold_boundary_two_hard_gates_with_soft_signal_results_in_run():
    evaluator = GatingEvaluator()
    findings = [
        _finding(
            title="Reflected XSS in search",
            description="reflected xss with user input in javascript context",
            category="xss",
            evidence="query parameter reflected and form input present",
        )
    ]

    decisions = evaluator.evaluate(findings)
    xss = _decision_for(decisions, "XSS Agent")

    assert xss["confidence"] >= 0.8
    assert xss["decision"] == "run"
