#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

cargo build -p tunnel-core --bin tunnel-core
TUNNEL_CORE_BINARY="$repo_root/target/debug/tunnel-core" \
  go test -tags=integration ./internal/controller \
  -run '^TestTunnelCoreBinaryManagementContract$' -count=1
