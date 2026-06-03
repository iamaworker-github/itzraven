# Itzraven Benchmarks

Performance and accuracy benchmarks for Itzraven scanning agents.

## Benchmark Suites

| Suite | Description | Target |
|-------|-------------|--------|
| `vuln_detection` | Vulnerability detection accuracy against Juiceshop/DVWA | `benchmarks/vuln_detection/` |
| `speed` | Scan time per agent | `benchmarks/speed/` |
| `llm_dedup` | LLM deduplication accuracy | `benchmarks/llm_dedup/` |
| `cvss` | CVSS scoring correctness | `benchmarks/cvss/` |

## Running

```bash
# All benchmarks
python -m benchmarks.run_all

# Specific suite
python -m benchmarks.run_all --suite vuln_detection

# With comparison against baseline
python -m benchmarks.run_all --compare baseline.json
```
