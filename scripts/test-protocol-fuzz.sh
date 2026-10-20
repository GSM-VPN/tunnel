#!/usr/bin/env bash

set -euo pipefail

fuzz_time="${FUZZ_TIME:-30s}"
go test ./internal/protocol -run '^$' \
  -fuzz FuzzUnmarshalRequestFrameNeverPanics -fuzztime "$fuzz_time"
go test ./internal/protocol -run '^$' \
  -fuzz FuzzUnmarshalResponseFrameNeverPanics -fuzztime "$fuzz_time"
