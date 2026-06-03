from itzraven.agents.remediation_agent import RemediationAgent


def _agent() -> RemediationAgent:
    # These helpers are pure functions for this test scope; no runtime wiring needed.
    return RemediationAgent.__new__(RemediationAgent)


def test_extract_json_parses_direct_json_object():
    agent = _agent()
    payload = '{"suggested_fix":"Use prepared statements","confidence":0.9}'

    parsed = agent._extract_json(payload)

    assert isinstance(parsed, dict)
    assert parsed["suggested_fix"] == "Use prepared statements"
    assert parsed["confidence"] == 0.9


def test_extract_json_parses_fenced_json_block():
    agent = _agent()
    payload = """LLM preface
```json
{"suggested_fix":"Sanitize input","verification_steps":["Run scanner"]}
```
extra text
"""

    parsed = agent._extract_json(payload)

    assert isinstance(parsed, dict)
    assert parsed["suggested_fix"] == "Sanitize input"
    assert parsed["verification_steps"] == ["Run scanner"]


def test_extract_json_parses_generic_fenced_block_with_json():
    agent = _agent()
    payload = """notes
```
{"patch_suggestion":"Replace string concat with parameter binding"}
```
"""

    parsed = agent._extract_json(payload)

    assert isinstance(parsed, dict)
    assert parsed["patch_suggestion"] == "Replace string concat with parameter binding"


def test_extract_json_parses_first_valid_balanced_object_from_noisy_text():
    agent = _agent()
    payload = """noise {not valid}
context blah blah
{"suggested_fix":"Use allowlist validation","risk_notes":["Requires QA pass"]}
trailing noise
"""

    parsed = agent._extract_json(payload)

    assert isinstance(parsed, dict)
    assert parsed["suggested_fix"] == "Use allowlist validation"
    assert parsed["risk_notes"] == ["Requires QA pass"]


def test_extract_json_returns_none_on_malformed_content():
    agent = _agent()

    assert agent._extract_json("this is not json at all {{{") is None


def test_normalizer_applies_defaults_for_missing_keys():
    agent = _agent()

    normalized = agent._normalize_remediation_payload({})

    assert normalized["suggested_fix"] == ""
    assert normalized["patch_suggestion"] == ""
    assert normalized["verification_steps"] == []
    assert normalized["risk_notes"] == []
    assert normalized["confidence"] == 0.6


def test_normalizer_coerces_string_fields_to_lists():
    agent = _agent()
    payload = {
        "verification_steps": "Run unit tests",
        "risk_notes": "Review migration rollback plan",
    }

    normalized = agent._normalize_remediation_payload(payload)

    assert normalized["verification_steps"] == ["Run unit tests"]
    assert normalized["risk_notes"] == ["Review migration rollback plan"]
