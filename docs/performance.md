# Performance measurement plan

The `512MB` target is a throughput objective, not a packet-size limit. No
throughput claim is made until measurements are available. Record the
commit, OS/kernel, CPU, memory, MTU, packet size distribution, cipher mode,
number of sessions, and loss/latency conditions with every result.

Measure:

- encrypted upload and download throughput;
- p50/p95/p99 packet latency and CPU utilization;
- packet loss, reorder, and recovery time;
- handshake and reconnect rates;
- fairness across the target 216 concurrent sessions.

Use the existing unit tests for deterministic correctness, then add Linux
network-namespace and benchmark jobs before comparing against WireGuard. The
Rust benchmark targets below cover reusable core-path signals; they do not
replace an end-to-end network measurement.

## Reproducible core-path benchmarks

Run all targets from the repository root:

```bash
cargo bench --package tunnel-core --benches
```

The targets use fixed inputs and print machine-readable key/value fields:

| Target | Scope | Fixed workload |
| --- | --- | --- |
| `codec` | encode/decode round trip | 100,000 packets with a 512-byte payload |
| `crypto` | ChaCha20-Poly1305 seal/open round trip | 100,000 packets at 64, 512, and 1,024-byte payloads |
| `session` | session registry and fair byte limiter | 216 sessions, repeated 10,000 times |

Each output includes elapsed nanoseconds. The crypto target reports encrypted
bytes, while the session target reports the number of admitted operations.
These are regression signals for the Rust core and must not be presented as
VPN throughput, packet-per-second capacity, or security evidence.

## Result record

Copy the command, commit, host, and network conditions into the result record
before comparing runs:

```text
date_utc:
commit:
os_kernel:
cpu_memory:
rustc_cargo:
target_profile: bench
server:
client:
mtu:
bandwidth:
concurrent_sessions:
traffic_pattern:
repetitions:
command: cargo bench --package tunnel-core --benches
output:
interpretation:
```

The core benchmarks can be run on any host, but the server/client/MTU/
bandwidth fields are required for a future end-to-end result. Do not fill them
with defaults or infer network performance from a codec, crypto, or in-memory
session result.
