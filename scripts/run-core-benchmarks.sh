#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_PATH="${1:-${ROOT_DIR}/benchmark-results/core-benchmark-$(date -u +%Y%m%dT%H%M%SZ).md}"

mkdir -p "$(dirname "$OUTPUT_PATH")"

command -v cargo >/dev/null 2>&1 || {
  echo "cargo is required to run the Rust Core benchmarks" >&2
  exit 1
}

commit="$(git -C "$ROOT_DIR" rev-parse HEAD)"
date_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
os_kernel="$(uname -srm)"
cpu_memory="$(sysctl -n hw.ncpu 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null || printf 'unknown') CPUs"
rustc_version="$(rustc --version 2>/dev/null || printf 'unavailable')"
cargo_version="$(cargo --version 2>/dev/null || printf 'unavailable')"
mtu="${BENCH_MTU:-not-applicable}"
bandwidth="${BENCH_BANDWIDTH:-not-applicable}"
concurrent_sessions="${BENCH_CONCURRENT_SESSIONS:-216}"
traffic_pattern="${BENCH_TRAFFIC_PATTERN:-fixed-core-inputs}"
repetitions="${BENCH_REPETITIONS:-defined-by-benchmark-target}"

temporary_output="$(mktemp)"
trap 'rm -f "$temporary_output"' EXIT

(
  cd "$ROOT_DIR"
  cargo bench --package tunnel-core --benches
) 2>&1 | tee "$temporary_output"

{
  printf '# Rust Core Benchmark Report\n\n'
  printf '```text\n'
  printf 'date_utc: %s\n' "$date_utc"
  printf 'commit: %s\n' "$commit"
  printf 'os_kernel: %s\n' "$os_kernel"
  printf 'cpu_memory: %s\n' "$cpu_memory"
  printf 'rustc: %s\n' "$rustc_version"
  printf 'cargo: %s\n' "$cargo_version"
  printf 'target_profile: bench\n'
  printf 'server: in-memory Rust Core benchmark\n'
  printf 'client: in-memory Rust Core benchmark\n'
  printf 'mtu: %s\n' "$mtu"
  printf 'bandwidth: %s\n' "$bandwidth"
  printf 'concurrent_sessions: %s\n' "$concurrent_sessions"
  printf 'traffic_pattern: %s\n' "$traffic_pattern"
  printf 'repetitions: %s\n' "$repetitions"
  printf 'command: cargo bench --package tunnel-core --benches\n'
  printf '```\n\n'
  printf '## Raw output\n\n```text\n'
  cat "$temporary_output"
  printf '```\n\n'
  printf '> This report covers deterministic Rust Core targets only. It is not evidence of end-to-end VPN throughput, packet-per-second capacity, DNS behavior, or external-network performance.\n'
} > "$OUTPUT_PATH"

printf 'benchmark_report=%s\n' "$OUTPUT_PATH"
