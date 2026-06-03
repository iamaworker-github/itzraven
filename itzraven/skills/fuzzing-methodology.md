---
name: Fuzzing Methodology and Automation
category: fuzzing
description: Automated vulnerability discovery — AFL++, libFuzzer, Honggfuzz, kernel fuzzing (syzkaller), CI/CD integration
tags: [fuzzing, afl, libfuzzer, honggfuzz, syzkaller, vulnerability-research]
---

## Fuzzing Methodology

### Fuzzer Type Comparison
- BlackBox: no source code (RADAMSA, boofuzz) — protocol fuzzing
- GreyBox: lightweight instrumentation (AFL++, libFuzzer) — fastest
- Snapshot: VM snapshot + syscall rewrite (kfx, winafl) — kernel/binary
- WhiteBox: symbolic execution (S2E, Angr) — deep path exploration  
- Ensemble: combine multiple fuzzers for best coverage

### AFL++ Setup
```bash
afl-clang-fast -o target target.c -lm
afl-fuzz -i input/ -o output/ -- ./target @@
```

Key flags:
- `-M main`, `-S secondary` for parallel fuzzing
- `-m none` disable memory limit
- `-t 1000` timeout per test case (ms)
- `-x dictionary.dict` syntax tokens

### libFuzzer
```cpp
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // your code here
    return 0;
}
```

Build: `clang++ -fsanitize=fuzzer,address target.cpp -o target`

### Honggfuzz
```c
HF_ITER() macro for persistent mode
```

Build: `honggfuzz -i input/ -o output/ -- ./target ___FILE___`

### Seed Corpus Curation
- Start with smallest valid input
- Add edge cases: empty, max-size, malformed headers
- Use afl-cmin for corpus minimization
- Use afl-tmin for individual test case minimization
- Common Crawl integration for web fuzzing

### Parallel Fuzzing
```bash
afl-fuzz -M main -i input/ -o sync/ -- ./target
afl-fuzz -S worker1 -i input/ -o sync/ -- ./target
afl-fuzz -S worker2 -i input/ -o sync/ -- ./target
```

### Crash Triage
```bash
afl-collect -r output/ crashes/
afl-report output/ -o report.html
```

For each crash: minimize, deduplicate, triage exploitability

### Specialized Targets

#### Kernel Fuzzing (syzkaller)
- System call description files (.txt)
- KASAN/KCSAN enabled kernel
- VM-based testing (qemu, gce, android)
- Repro: `syz-repro -config manager.cfg`

#### Rust Fuzzing
- `cargo fuzz` with libfuzzer backend
- `miri` for undefined behavior detection
- `loom` for concurrency model checking

#### Embedded / Binary-Only
- LibAFL for custom fuzzer harness
- Retrowrite + QASAN for binary instrumentation
- Nautilus for grammar-based fuzzing
- Fuzzilli for JavaScript engine fuzzing

### CI/CD Integration
```yaml
- name: Fuzz
  run: |
    cargo install cargo-fuzz
    cargo fuzz run fuzz_target -- -runs=100000
```

Use ClusterFuzzLite for continuous fuzzing
