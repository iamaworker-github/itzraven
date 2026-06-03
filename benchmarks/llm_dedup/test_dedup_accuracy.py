"""Benchmark: Deduplication accuracy on mixed finding list."""

from itzraven.agents.base_agent import Finding

DUP_FINDINGS = [
    ("SQL Injection in login", "' OR '1'='1"),
    ("SQL Injection in login page", "' OR '1'='1"),
    ("XSS in search bar", "<script>"),
    ("Open port 80", "nmap"),
]


def run_test() -> dict:
    from itzraven.core.bloom_filter import FindingDeduplicator
    dedup = FindingDeduplicator()
    unique = []
    duplicates = 0
    for title, evidence in DUP_FINDINGS:
        if dedup.is_duplicate(title, "benchmark", evidence):
            duplicates += 1
        else:
            unique.append(title)
    expected_duplicates = 1  # first 2 are similar
    accuracy = 1.0 if duplicates == expected_duplicates else duplicates / max(expected_duplicates, 1) * 0.5
    return {"total_findings": len(DUP_FINDINGS), "unique": len(unique), "duplicates_found": duplicates, "expected_duplicates": expected_duplicates, "accuracy": round(accuracy, 2)}
