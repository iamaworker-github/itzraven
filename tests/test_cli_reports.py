from types import SimpleNamespace

from itzraven.cli import _build_markdown_report


def _fake_result(metadata):
    return SimpleNamespace(
        target="https://example.com",
        duration=1.23,
        total_findings=0,
        findings_by_severity={"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        all_findings=[],
        metadata=metadata,
    )


def test_markdown_report_includes_remediation_summary_and_suggestions():
    result = _fake_result(
        {
            "remediation": {
                "processed": 3,
                "suggested": 2,
                "skipped": 1,
                "suggestions": [
                    {
                        "title": "SQL Injection",
                        "severity": "high",
                        "suggested_fix": "Use parameterized queries",
                        "patch_suggestion": "Replace f-string SQL with bound params",
                    }
                ],
            }
        }
    )

    report = _build_markdown_report(result)

    assert "## Remediation Suggestions" in report
    assert "- Processed: 3" in report
    assert "- Suggested: 2" in report
    assert "- Skipped: 1" in report
    assert "### Top Suggestions" in report
    assert "_Showing 1 of 1 remediation suggestions._" in report
    assert "**SQL Injection** (high)" in report
    assert "Suggested fix: Use parameterized queries" in report
    assert "Patch suggestion: Replace f-string SQL with bound params" in report


def test_markdown_report_limits_to_top_five_remediation_suggestions():
    suggestions = [
        {
            "title": f"Finding {idx}",
            "severity": "high" if idx % 2 else "medium",
            "suggested_fix": f"Fix {idx}",
            "patch_suggestion": f"Patch {idx}",
        }
        for idx in range(1, 7)
    ]
    result = _fake_result(
        {
            "remediation": {
                "processed": 6,
                "suggested": 6,
                "skipped": 0,
                "suggestions": suggestions,
            }
        }
    )

    report = _build_markdown_report(result)

    assert "_Showing 5 of 6 remediation suggestions._" in report
    for idx in range(1, 6):
        assert f"**Finding {idx}**" in report
        assert f"Suggested fix: Fix {idx}" in report
        assert f"Patch suggestion: Patch {idx}" in report

    assert "**Finding 6**" not in report
    assert "Suggested fix: Fix 6" not in report
    assert "Patch suggestion: Patch 6" not in report


def test_markdown_report_omits_remediation_section_when_absent():
    result = _fake_result({"poc_validation": {"processed": 1, "validated": 1, "failed": 0, "skipped": 0}})

    report = _build_markdown_report(result)

    assert "## PoC Validation" in report
    assert "## Remediation Suggestions" not in report


def test_markdown_report_includes_gating_shadow_decisions():
    result = _fake_result(
        {
            "gating_shadow_decisions": [
                {
                    "agent_name": "XSS Agent",
                    "decision": "run",
                    "confidence": 0.8,
                    "reason": "Hard gates satisfied with sufficient confidence.",
                    "blockers": [],
                },
                {
                    "agent_name": "SQLi Agent",
                    "decision": "skip",
                    "confidence": 0.2,
                    "reason": "Insufficient prerequisite signals in current evidence.",
                    "blockers": ["missing_hard_gate_signals"],
                },
            ]
        }
    )

    report = _build_markdown_report(result)

    assert "## Agent Gating Decisions (Shadow Mode)" in report
    assert "**XSS Agent**: RUN" in report
    assert "Confidence: 0.8" in report
    assert "**SQLi Agent**: SKIP" in report
    assert "Blockers: missing_hard_gate_signals" in report


def test_markdown_report_includes_gating_enforced_decisions_and_blocked_agents():
    result = _fake_result(
        {
            "gating_enforced_decisions": [
                {
                    "agent_name": "XSS Agent",
                    "decision": "run",
                    "confidence": 0.85,
                    "reason": "Strong reflected sink evidence present.",
                    "blockers": [],
                },
                {
                    "agent_name": "SQLi Agent",
                    "decision": "skip",
                    "confidence": 0.3,
                    "reason": "No dynamic injectable parameter evidence.",
                    "blockers": ["missing_hard_gate_signals"],
                },
            ],
            "gating_enforced_skips": [
                {
                    "agent_name": "SQL Injection Agent",
                    "reason": "Insufficient prerequisite signals in current evidence.",
                }
            ],
        }
    )

    report = _build_markdown_report(result)

    assert "## Agent Gating Decisions (Enforced Mode)" in report
    assert "**XSS Agent**: RUN" in report
    assert "**SQLi Agent**: SKIP" in report
    assert "### Enforced Gating Blocked Agents" in report
    assert "**SQL Injection Agent**" in report
    assert "Reason: Insufficient prerequisite signals in current evidence." in report
