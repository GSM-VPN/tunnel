# Benchmarks

Performance benchmarks belong here. Benchmark changes must report the input
size, packet mix, concurrency, and whether encryption or device I/O is part of
the measured path; benchmark results are not correctness or security evidence.

The Rust core targets live under `crates/tunnel-core/benches/` and can be run
together with:

```bash
cargo bench --package tunnel-core --benches
```

Keep network-namespace and device-I/O benchmarks separate from these
deterministic core-path targets so that host and network variance is visible.
