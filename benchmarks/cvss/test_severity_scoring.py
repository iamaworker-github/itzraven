"""Benchmark: CVSS severity scoring correctness."""

TEST_CASES = [
    {"evidence": "SQL injection with data extraction possible", "expected": "critical"},
    {"evidence": "Reflected XSS in search parameter", "expected": "medium"},
    {"evidence": "Open port 80 - HTTP service", "expected": "low"},
    {"evidence": "Remote code execution in Apache Struts", "expected": "critical"},
    {"evidence": "Missing X-XSS-Protection header", "expected": "low"},
    {"evidence": "Weak TLS cipher suite accepted", "expected": "medium"},
    {"evidence": "Authentication bypass in admin panel", "expected": "high"},
    {"evidence": "Information disclosure in error page", "expected": "low"},
    {"evidence": "Default credentials on SSH service", "expected": "high"},
    {"evidence": "Server-Side Request Forgery in API endpoint", "expected": "high"},
]


SEVERITY_KEYWORDS = {
    "critical": ["rce", "remote code", "sqli", "sql injection", "data extraction", "auth bypass", "authentication bypass"],
    "high": ["ssrf", "idor", "lfi", "privilege escalation", "default cred"],
    "medium": ["xss", "csrf", "open redirect", "weak tls", "weak cipher"],
    "low": ["info disclosure", "missing header", "open port", "server banner"],
}


def run_test() -> dict:
    passed = 0
    failed = 0
    for tc in TEST_CASES:
        ev = tc["evidence"].lower()
        score = "low"
        for sev, keywords in SEVERITY_KEYWORDS.items():
            if any(kw in ev for kw in keywords):
                score = sev
                break
        correct = score == tc["expected"]
        if correct:
            passed += 1
        else:
            failed += 1
    total = len(TEST_CASES)
    return {"passed": passed, "failed": failed, "total": total, "score": round(passed / total * 100, 1) if total else 0}
