# Performance measurement plan

No throughput claim is made until measurements are available. Record the
commit, OS/kernel, CPU, memory, MTU, packet size distribution, cipher mode,
number of sessions, and loss/latency conditions with every result.

Measure:

- encrypted upload and download throughput;
- p50/p95/p99 packet latency and CPU utilization;
- packet loss, reorder, and recovery time;
- handshake and reconnect rates;
- fairness across the target 216 concurrent sessions.

Use the existing unit tests for deterministic correctness, then add Linux
network-namespace and benchmark jobs before comparing against WireGuard.

The repository currently includes a reproducible codec-only benchmark:

```bash
cargo bench --package tunnel-core --bench codec
```

It measures 100,000 encode/decode round trips for a 512-byte payload and
prints elapsed nanoseconds and processed bytes. This is a codec regression
signal, not an end-to-end VPN throughput result; record the commit and host
details before comparing runs.
