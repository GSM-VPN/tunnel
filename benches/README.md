# Benchmarks

Performance benchmarks belong here. Benchmark changes must report the input
size, packet mix, concurrency, and whether encryption or device I/O is part of
the measured path; benchmark results are not correctness or security evidence.

The Rust core targets live under `crates/tunnel-core/benches/` and can be run
together with:

```bash
cargo bench --package tunnel-core --benches
```

To capture the command output together with the commit, host, toolchain, and
comparison conditions, run:

```bash
./scripts/run-core-benchmarks.sh benchmark-results/core-benchmark.md
```

`BENCH_MTU`, `BENCH_BANDWIDTH`, `BENCH_CONCURRENT_SESSIONS`,
`BENCH_TRAFFIC_PATTERN`, and `BENCH_REPETITIONS` can describe the surrounding
test conditions without changing the deterministic benchmark inputs.

Keep network-namespace and device-I/O benchmarks separate from these
deterministic core-path targets so that host and network variance is visible.
