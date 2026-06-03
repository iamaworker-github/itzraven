"""Benchmark: CVSS vector parsing correctness."""

VECTORS = [
    {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "expected_score": 9.8, "expected_severity": "critical"},
    {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "expected_score": 5.3, "expected_severity": "medium"},
    {"vector": "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:N", "expected_score": 3.0, "expected_severity": "low"},
    {"vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", "expected_score": 7.8, "expected_severity": "high"},
]


def _parse_cvss(vector: str) -> tuple:
    metrics = {}
    for part in vector.split("/"):
        if ":" in part:
            k, v = part.split(":", 1)
            metrics[k] = v
    base_score = 0.0
    if "AV" in metrics and "AC" in metrics:
        av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}.get(metrics.get("AV", "N"), 0.85)
        ac = {"L": 0.77, "H": 0.44}.get(metrics.get("AC", "L"), 0.77)
        pr = {"N": 0.85, "L": 0.62, "H": 0.27}.get(metrics.get("PR", "N"), 0.85)
        ui = {"N": 0.85, "R": 0.62}.get(metrics.get("UI", "N"), 0.85)
        scope = metrics.get("S", "U")
        c = {"H": 0.56, "L": 0.22, "N": 0}.get(metrics.get("C", "N"), 0)
        i_val = {"H": 0.56, "L": 0.22, "N": 0}.get(metrics.get("I", "N"), 0)
        a = {"H": 0.56, "L": 0.22, "N": 0}.get(metrics.get("A", "N"), 0)
        impact = 1 - (1 - c) * (1 - i_val) * (1 - a)
        if scope == "U":
            base_score = min(impact * av * ac * pr * ui, 10)
        else:
            base_score = min(1.08 * (impact * av * ac * pr * ui), 10)
        base_score = round(base_score, 1)
    sev = "critical" if base_score >= 9 else "high" if base_score >= 7 else "medium" if base_score >= 4 else "low"
    return base_score, sev


def run_test() -> dict:
    passed = 0
    failed = 0
    for tc in VECTORS:
        score, sev = _parse_cvss(tc["vector"])
        if abs(score - tc["expected_score"]) < 0.5 and sev == tc["expected_severity"]:
            passed += 1
        else:
            failed += 1
    return {"passed": passed, "failed": failed, "total": len(VECTORS), "score": round(passed / len(VECTORS) * 100, 1) if VECTORS else 0}
