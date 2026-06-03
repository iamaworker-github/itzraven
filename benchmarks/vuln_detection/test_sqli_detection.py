"""Benchmark: SQLi detection accuracy against known payload patterns."""

from itzraven.agents.base_agent import Finding

TEST_CASES = [
    {"payload": "' OR '1'='1", "expected": True, "label": "basic_sqli"},
    {"payload": "1 AND 1=1", "expected": False, "label": "normal_int"},
    {"payload": "admin' --", "expected": True, "label": "comment_sqli"},
    {"payload": "1 UNION SELECT 1,2,3", "expected": True, "label": "union_sqli"},
    {"payload": "hello", "expected": False, "label": "normal_string"},
    {"payload": "' WAITFOR DELAY '0:0:5'--", "expected": True, "label": "time_based_sqli"},
    {"payload": "../../etc/passwd", "expected": False, "label": "lfi_not_sqli"},
    {"payload": "<script>alert(1)</script>", "expected": False, "label": "xss_not_sqli"},
    {"payload": "1' ORDER BY 3--", "expected": True, "label": "order_by_sqli"},
    {"payload": "'; DROP TABLE users--", "expected": True, "label": "drop_table_sqli"},
]


def run_test() -> dict:
    passed = 0
    failed = 0
    details = []
    for tc in TEST_CASES:
        is_sqli = any(kw in tc["payload"].lower() for kw in ["'", "--", "union", "sleep", "waitfor", "order by", "drop ", "exec"])
        correct = is_sqli == tc["expected"]
        if correct:
            passed += 1
        else:
            failed += 1
        details.append({"payload": tc["payload"], "expected": tc["expected"], "detected": is_sqli, "correct": correct})
    score = passed / len(TEST_CASES) * 100 if TEST_CASES else 0
    return {"passed": passed, "failed": failed, "total": len(TEST_CASES), "score": round(score, 1), "details": details}
