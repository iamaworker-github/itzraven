"""Benchmark: XSS detection accuracy against known payload patterns."""

TEST_CASES = [
    {"payload": "<script>alert(1)</script>", "expected": True, "label": "basic_xss"},
    {"payload": "<img src=x onerror=alert(1)>", "expected": True, "label": "img_xss"},
    {"payload": "hello world", "expected": False, "label": "normal_text"},
    {"payload": "\" onmouseover=\"alert(1)", "expected": True, "label": "event_handler_xss"},
    {"payload": "' OR '1'='1", "expected": False, "label": "sqli_not_xss"},
    {"payload": "javascript:alert(1)", "expected": True, "label": "js_protocol_xss"},
    {"payload": "<svg onload=alert(1)>", "expected": True, "label": "svg_xss"},
    {"payload": "#", "expected": False, "label": "hash_fragment"},
    {"payload": "{{7*7}}", "expected": False, "label": "ssti_not_xss"},
    {"payload": "<ScRiPt>alert(1)</sCrIpT>", "expected": True, "label": "case_insensitive_xss"},
]


def run_test() -> dict:
    passed = 0
    failed = 0
    details = []
    import re
    xss_patterns = [
        r"<script[^>]*>.*</script>", r"on\w+\s*=", r"javascript:", r"<img[^>]+onerror", r"<svg[^>]+onload",
    ]
    for tc in TEST_CASES:
        detected = any(re.search(p, tc["payload"], re.IGNORECASE) for p in xss_patterns)
        correct = detected == tc["expected"]
        if correct:
            passed += 1
        else:
            failed += 1
        details.append({"payload": tc["payload"], "expected": tc["expected"], "detected": detected, "correct": correct})
    score = passed / len(TEST_CASES) * 100 if TEST_CASES else 0
    return {"passed": passed, "failed": failed, "total": len(TEST_CASES), "score": round(score, 1), "details": details}
