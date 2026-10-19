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
