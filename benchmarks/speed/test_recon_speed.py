"""Benchmark: Simulated recon agent speed."""

import time


def run_test() -> dict:
    start = time.time()
    total_ops = 1000
    # Simulate URL discovery + tech detection
    urls = [f"/path/{i}" for i in range(100)]
    techs = ["php", "apache", "mysql"]
    _ = [(u, t) for u in urls for t in techs]
    elapsed = time.time() - start
    ops_per_sec = total_ops / elapsed if elapsed > 0 else 0
    return {"operations": total_ops, "elapsed_seconds": round(elapsed, 3), "ops_per_second": round(ops_per_sec, 1)}
