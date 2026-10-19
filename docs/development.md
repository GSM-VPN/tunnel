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

`CoreController` keeps a secret-free desired state for network configuration
and approved peers. On every Core start or restart, `CoreSynchronizer` waits
for the IPC socket and applies initialization, configuration, peer approvals,
and the running transition in that order. A synchronization failure is
treated as an unhealthy start, so the Controller does not report a partially
restored Core as running.

For operations, `CoreController.CollectMetrics` combines the Core health label
with the eleven secret-free counters returned by `GetStatistics`. It refuses
to query a stopped or unhealthy Core and uses consecutive request IDs for the
two IPC calls. The snapshot contains no keys, plaintext packets, DNS query
contents, or per-user identity data.

VPN Server 승인 연동은 [`vpn-server-integration.md`](./vpn-server-integration.md)의
경계를 따른다. Controller는 Gateway/VPN Server의 정규화된 승인 정보와
HMAC 서명만 받고, 로그인 API나 `GATEWAY_SHARED_SECRET` 원문을 Rust Core에
전달하지 않는다.

## Go Controller 운영 로그

Controller의 운영 로그는 `log/slog` 구조화 이벤트로 기록한다. 기본 logger는
`io.Discard`를 사용하므로 애플리케이션이 `SetLogger`로 명시적으로 주입한
경우에만 출력된다. 현재 이벤트는 다음 생명주기 정보만 포함한다.

- `core_start_requested`, `core_start_attempt`, `core_running`
- `core_start_failed`, `core_state_sync_failed`
- `core_stop_completed`, `core_state_changed`

이벤트 필드는 상태 이름, 시작 횟수, 성공 여부처럼 운영에 필요한 메타데이터로
제한한다. 명령행, 소켓 경로, Peer 정보, 키, 평문·암호문 패킷, 원문 오류 문자열은
Controller가 로그 필드로 전달하지 않는다. 로그 저장소를 연결할 때도 동일한
비밀정보 금지 정책을 유지해야 한다.

프로토콜·암호화·네트워크 기능은 각 단계의 테스트 요구사항을 충족하기 전까지 실제 사용자 트래픽에 사용하지 않습니다.

## 테스트 범위

Rust 단위 테스트는 프로토콜 codec, Noise 핸드셰이크, AEAD·Replay·키 세대,
세션 상태와 네트워크 정책을 메모리 경계에서 검증한다. codec과 내부 IP
패킷 validator에는 `proptest` 기반 임의 입력 비패닉 테스트가 포함되어
있으며, 테스트 대상은 오류를 반환하고 프로세스를 종료하지 않아야 한다.

```text
cargo test --workspace --all-targets --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
go test ./...
go vet ./...
```

Linux network namespace, 실제 DNS·nftables 적용, 외부 인터넷 유출,
Windows Wintun, 성능 벤치마크와 장애 주입은 별도 권한·환경이 필요한
통합 검증으로 단위 테스트에 포함하지 않는다.
