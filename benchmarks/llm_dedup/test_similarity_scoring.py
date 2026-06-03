"""Benchmark: Finding deduplication similarity scoring."""

SIMILAR_PAIRS = [
    ("SQL Injection in login.php", "SQLi found in login page", True),
    ("XSS in search parameter", "Reflected XSS in search box", True),
    ("Open redirect in redirect.php", "No open redirect found", False),
    ("Server running Apache 2.4.56", "Apache 2.4.56 detected on port 80", True),
    ("Weak password policy", "Strong password policy detected", False),
]


def run_test() -> dict:
    passed = 0
    failed = 0
    details = []
    for a, b, expected_similar in SIMILAR_PAIRS:
        words_a = set(a.lower().split()[:5])
        words_b = set(b.lower().split()[:5])
        overlap = len(words_a & words_b) / max(len(words_a | words_b), 1)
        is_similar = overlap > 0.3
        correct = is_similar == expected_similar
        if correct:
            passed += 1
        else:
            failed += 1
        details.append({"a": a, "b": b, "expected_similar": expected_similar, "got_similar": is_similar, "correct": correct})
    score = passed / len(SIMILAR_PAIRS) * 100 if SIMILAR_PAIRS else 0
    return {"passed": passed, "failed": failed, "total": len(SIMILAR_PAIRS), "score": round(score, 1), "details": details}
