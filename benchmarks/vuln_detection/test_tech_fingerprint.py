"""Benchmark: Technology fingerprinting accuracy."""

TECH_SIGNATURES = {
    "php": [{"header": "X-Powered-By: PHP", "expected": True}, {"body": "<?php", "expected": True}, {"body": "Hello World", "expected": False}],
    "wordpress": [{"body": "/wp-content/", "expected": True}, {"body": "wp-json", "expected": True}, {"body": "Hello World", "expected": False}],
    "nodejs": [{"header": "X-Powered-By: Express", "expected": True}, {"body": "Node.js", "expected": False}],
    "nginx": [{"header": "Server: nginx/1.24", "expected": True}, {"header": "Server: Apache", "expected": False}],
}


def run_test() -> dict:
    passed = 0
    failed = 0
    total = 0
    for tech, cases in TECH_SIGNATURES.items():
        for case in cases:
            total += 1
            detected = False
            if "body" in case:
                detected = case["body"] in case.get("body", "")
            elif "header" in case:
                detected = True
            if detected == case["expected"]:
                passed += 1
            else:
                failed += 1
    score = passed / total * 100 if total else 0
    return {"passed": passed, "failed": failed, "total": total, "score": round(score, 1)}
