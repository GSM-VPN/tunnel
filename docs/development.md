# 개발 환경

## 요구사항

- Go 1.24 이상
- Rust stable toolchain
- Cargo
- Linux 개발 환경(네트워크 기능 검증 시)

## 저장소 구조

```text
.
├── internal/
│   ├── controller/       # Go 제어 계층
│   └── protocol/         # Go 프로토콜 타입 계층
├── crates/
│   └── tunnel-core/      # Rust 데이터 플레인 기반
├── docs/
├── Cargo.toml
└── go.mod
```

## 검증 명령

변경 후 아래 명령을 실행합니다.

```bash
go test ./...
go vet ./...
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets --all-features
```

Rust packet parsing includes property tests over arbitrary byte sequences, and
the Go management codec exposes fuzz targets for bounded local campaigns:

```bash
cargo test --workspace --all-targets --all-features
go test ./... -run '^$'
go test ./internal/protocol -fuzz=FuzzUnmarshalRequestFrameNeverPanics -fuzztime=30s
```

Fuzzing hardens parser boundaries but does not replace network integration
tests, cryptographic review, or an independent security assessment.

On Unix, the Core process can be started with:

```bash
TUNNEL_CORE_IPC_SOCKET=/tmp/gsm-tunnel-core.sock \
TUNNEL_CORE_MAX_PEERS=216 \
cargo run -p tunnel-core --bin tunnel-core
```

The Go Controller's `CoreController` starts the child through `StartCore`,
reports STARTING/RUNNING/STOPPING/STOPPED/UNHEALTHY states, and uses the
bounded `Supervisor` policy for crash restarts. Calling `Stop` cancels
supervision and waits for the child to be collected. The Core socket is
local-only; data packets do not pass through the Controller. On Linux the
management server verifies the connecting process UID against the socket
owner. `bind_with_policy(..., false)` exposes a read-only management socket
that rejects engine, peer, session, and configuration mutations with 403;
the default bind permits the Controller's mutating control plane.

프로토콜·암호화·네트워크 기능은 각 단계의 테스트 요구사항을 충족하기 전까지 실제 사용자 트래픽에 사용하지 않습니다.

