#!/usr/bin/env python3
"""Run all Itzraven benchmark suites."""

import argparse
import json
import sys
import time
from pathlib import Path


def run_benchmark(suite: str) -> dict:
    results = {"suite": suite, "timestamp": time.time(), "tests": [], "passed": 0, "failed": 0, "skipped": 0}
    suite_dir = Path(__file__).parent / suite

    if not suite_dir.exists():
        results["skipped"] = 1
        results["tests"].append({"name": suite, "status": "skipped", "reason": "directory not found"})
        return results

    for test_file in sorted(suite_dir.glob("test_*.py")):
        test_name = test_file.stem
        test_result = {"name": test_name, "status": "passed"}
        try:
            import importlib.util
            spec = importlib.util.spec_from_file_location(test_name, test_file)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            if hasattr(mod, "run_test"):
                output = mod.run_test()
                if output and isinstance(output, dict):
                    test_result["details"] = output
            test_result["status"] = "passed"
            results["passed"] += 1
        except Exception as e:
            test_result["status"] = "failed"
            test_result["error"] = str(e)
            results["failed"] += 1
        results["tests"].append(test_result)

    return results


def main():
    parser = argparse.ArgumentParser(description="Run Itzraven benchmarks")
    parser.add_argument("--suite", choices=["vuln_detection", "speed", "llm_dedup", "cvss"], help="Run specific suite only")
    parser.add_argument("--compare", help="Compare against baseline JSON file")
    args = parser.parse_args()

    suites = [args.suite] if args.suite else ["vuln_detection", "speed", "llm_dedup", "cvss"]
    all_results = {}

    for suite in suites:
        print(f"\n=== Running {suite} benchmarks ===")
        results = run_benchmark(suite)
        all_results[suite] = results
        print(f"  Passed: {results['passed']}, Failed: {results['failed']}, Skipped: {results['skipped']}")

    output_path = Path(__file__).parent / f"benchmark_results_{int(time.time())}.json"
    with open(output_path, "w") as f:
        json.dump(all_results, f, indent=2)
    print(f"\nResults saved to {output_path}")

    if args.compare:
        baseline = json.loads(Path(args.compare).read_text())
        print(f"\nComparison with {args.compare}:")
        for suite in all_results:
            bl = baseline.get(suite, {})
            cur = all_results.get(suite, {})
            bl_passed = bl.get("passed", 0)
            cur_passed = cur.get("passed", 0)
            delta = cur_passed - bl_passed
            sign = "+" if delta >= 0 else ""
            print(f"  {suite}: {bl_passed} \u2192 {cur_passed} ({sign}{delta})")

    return 0 if all(r["failed"] == 0 for r in all_results.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
