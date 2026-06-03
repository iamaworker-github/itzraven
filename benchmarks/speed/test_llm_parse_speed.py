"""Benchmark: LLM response parsing speed."""

import json
import time


RAW_RESPONSES = [
    '{"thought": "Test SQL injection", "action": "test_sqli", "params": {"url": "/test", "param": "id"}}',
    '{"thought": "Check XSS", "action": "test_xss", "params": {"url": "/search", "param": "q"}}',
    'Here is my analysis: {"thought": "Port scan", "action": "http_request", "params": {"method": "GET", "path": "/"}}',
    '```json\n{"thought": "Nuclei scan", "action": "nuclei_scan", "params": {"template_tags": ["cve"]}}\n```',
    'Invalid response with no JSON at all',
]


def run_test() -> dict:
    start = time.time()
    iterations = 500
    parsed_count = 0
    for _ in range(iterations):
        for raw in RAW_RESPONSES:
            try:
                text = raw.strip()
                if text.startswith("```"):
                    text = text.strip("`").removeprefix("json").strip()
                json.loads(text)
                parsed_count += 1
            except Exception:
                pass
    elapsed = time.time() - start
    return {"iterations": iterations * len(RAW_RESPONSES), "parsed": parsed_count, "elapsed_seconds": round(elapsed, 3), "parses_per_second": round(parsed_count / elapsed, 1) if elapsed else 0}
