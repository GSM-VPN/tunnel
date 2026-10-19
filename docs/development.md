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

`PlainTunnel` and `EncryptedTunnel` accept an optional `Metrics` value through
`with_metrics`. Successful data-plane sends and receives update packet/byte
counters, while device, transport, codec, authentication, inner-packet, and
session-type failures increment `packet_errors`. The metrics object stores only
atomic counters and never retains the failed datagram or its plaintext. It also
keeps a bounded snapshot of tx/rx bytes and packets for up to 216 observed
session IDs; management session removal removes that per-session snapshot.

VPN Server 승인 연동은 [`vpn-server-integration.md`](./vpn-server-integration.md)의
경계를 따른다. Controller는 Gateway/VPN Server의 정규화된 승인 정보와
HMAC 서명만 받고, 로그인 API나 `GATEWAY_SHARED_SECRET` 원문을 Rust Core에
전달하지 않는다.

`ListSessions` is the peer-level connection status boundary. Each returned
13-byte record contains `session_id`, `peer_id`, and the lifecycle state code;
it does not include keys, packet contents, or user profile data. The Controller
can therefore render per-peer connection state without transporting the data
plane through Go.

The final state byte uses the stable `LifecycleState` mapping `0=Disconnected`,
`1=Connecting`, `2=Handshaking`, `3=Established`, `4=Rekeying`,
`5=Reconnecting`, `6=Closing`, and `7=Closed`. Session creation and listing
tests assert the record shape and the established-state value.

`DnsUpstreamSelector` preserves the validated upstream order for a resolver
adapter. A failed query advances to the next provider and wraps around after
the last one; a successful query keeps the current provider selected. The
selector stores no query names, response bodies, or user-specific history.

`PeerRateLimiter` owns an independent bounded window per peer. Exhausting one
peer's packet allowance does not consume another peer's allowance; the shared
server queue and end-to-end fairness under load still require OS/network
integration measurements.

Secret configuration follows a separate boundary: `GATEWAY_SHARED_SECRET` is
kept by the Gateway/VPN service-authentication layer, while
`SERVER_PRIVATE_KEY` is supplied to Rust Core through its environment and is
parsed directly into the protected `ServerIdentity`. Neither value is stored
in a settings file, sent through IPC, or included in status and metrics.

## 운영 권한과 DNS 정책

초기 DNS 정책은 `DnsPolicy`의 순서가 지정된 upstream 목록을 사용하고,
Linux 적용 계층에서는 `resolvectl`의 UDP/TCP 53 transport만 실행한다. DoT와
DoH는 설정 모델에 보존할 수 있지만 별도 resolver adapter가 준비되기 전에는
활성화하지 않는다. 적용 전 `DnsSnapshot`을 보관하고 연결 종료나 실패 시
원래 link·resolver 설정을 역순으로 복원한다.

운영 배포에서는 VPN Server/Go Controller와 Rust Core를 전용 서비스 계정으로
실행하고, TUN·routing·nftables처럼 `CAP_NET_ADMIN`이 필요한 작업은 좁은
권한의 privileged adapter 경계에서만 수행한다. Rust Core의 Unix socket은
소유자 전용 `0600`으로 유지하며, 라이브러리는 서비스 계정 생성이나 host
권한 변경을 자동 수행하지 않는다.

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

Rust의 장기 키와 승인 피어 타입도 `Debug`에서 원문을 노출하지 않는다. 피어
요약·승인 객체는 `peer_id`와 주소 같은 운영 필드만 보여 주고 사용자 ID와
공개키는 `[redacted]`로 표시한다. Go의 `PeerRegistration.String()`도 Peer ID만
반환한다.

## 로컬 검증과 측정

Linux 개발 환경에서는 저장소 루트에서 `./scripts/validate.sh`를 실행하면
Go 포맷·vet·테스트와 Rust 포맷·Clippy·전체 테스트를 같은 순서로 검증한다.
Rust codec 기준 측정은 `cargo bench --package tunnel-core --bench codec`로
실행하며, 결과에는 반복 횟수·처리 바이트·경과 시간이 포함된다. 이 수치는
운영 처리량을 의미하지 않으며 OS, 커널, CPU, Rust toolchain과 커밋을 함께
기록한 비교 실험에서만 사용한다.

프로토콜·암호화·네트워크 기능은 각 단계의 테스트 요구사항을 충족하기 전까지 실제 사용자 트래픽에 사용하지 않습니다.

## 오류 처리 규칙

오류는 발생 계층의 typed error로 반환하고, 상위 계층이 정책을 결정한다.

- 프로토콜 codec과 IPC framing 오류는 해당 datagram/connection만 폐기한다.
  원문 payload나 키 자료를 오류 문자열에 포함하지 않는다.
- UDP·TUN의 일시적인 I/O 오류는 호출자에게 운영 오류로 반환한다. 재시도는
  세션과 Controller의 bounded backoff 정책을 통해서만 수행하며 무한 재시도하지
  않는다.
- 인증 실패, replay 거부, 승인 철회, 키 갱신 실패는 보안 오류로 분류하고
  영향을 받은 세션을 닫는다. 이전 키나 승인 상태를 재사용하지 않는다.
- 설정 오류, 권한 오류, 리소스 한도 초과는 시작·관리 작업을 실패시키되 다른
  세션과 프로세스 전체를 불필요하게 종료하지 않는다.
- 운영 로그에는 오류의 안정적인 분류와 상태만 기록하고, raw packet, secret,
  private key, 사용자 식별 정보는 기록하지 않는다.

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
