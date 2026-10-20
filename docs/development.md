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
cargo audit
```

Rust packet parser에는 임의 byte sequence를 대상으로 하는 property test가
있고, Go management codec은 제한된 로컬 campaign을 위한 fuzz target을
제공한다. request와 response parser를 함께 실행하려면 다음을 사용한다.

```bash
cargo test --workspace --all-targets --all-features
go test ./... -run '^$'
FUZZ_TIME=30s ./scripts/test-protocol-fuzz.sh
```

예약·수동 `Fuzz` workflow도 같은 script를 실행한다. seed case는 truncated,
empty, valid-header, status-bearing frame을 포함하며 임의 byte를 제한된
decoder에 통과시켜 malformed input이 panic을 일으키지 않음을 확인한다.

Fuzzing은 parser 경계를 강화하지만 network integration test, 암호화 검토,
독립적인 보안 평가를 대체하지 않는다.

Device test는 책임에 따라 나눈다. `device.rs`는 모든 platform에서
결정론적인 `MemoryDevice` queue와 close semantics를 검사하고,
`linux_device.rs`는 Linux 전용 TUN 검증을 담아 Linux에서만 compile한다.
`/dev/net/tun` 생성, 실제 IP packet 교환, host interface cleanup 확인은
memory-device suite에 섞지 않고 권한 있는 Linux integration test로 남긴다.

Unix에서는 다음 명령으로 Core process를 시작할 수 있다.

```bash
TUNNEL_CORE_IPC_SOCKET=/tmp/gsm-tunnel-core.sock \
TUNNEL_CORE_MAX_PEERS=216 \
cargo run -p tunnel-core --bin tunnel-core
```

Go Controller의 `CoreController`는 `StartCore`로 child를 시작하고
STARTING/RUNNING/STOPPING/STOPPED/UNHEALTHY 상태를 노출하며, crash 재시작에는
제한된 `Supervisor` policy를 사용한다. `Stop`을 호출하면 supervision을
취소하고 child가 수거될 때까지 기다린다. Core socket은 로컬 전용이며
data packet은 Controller를 통과하지 않는다. 배포는 socket을 소유한 전용
service account로 Core와 Controller를 실행해야 한다. socket mode는 `0600`이고
Linux management server는 연결 process UID를 socket owner와 비교한다.
`bind_with_policy(..., false)`는 읽기 전용 management socket을 노출한다.
이 socket은 engine·peer·session·configuration 변경을 `403`으로 거부하고,
기본 bind는 Controller의 변경 제어 영역을 허용한다.

배포 관점의 증거와 환경 gate는
[`release-verification-matrix.md`](./release-verification-matrix.md)에 요약한다.
매트릭스의 `required` 항목은 로컬 unit·IPC integration 결과와 분리하며,
로컬 테스트 통과를 production readiness 판단으로 해석하지 않는다.

`CoreController`는 network configuration과 승인 peer만 포함하는 비밀 없는
desired state를 유지한다. Core가 시작되거나 재시작될 때마다
`CoreSynchronizer`가 IPC socket을 기다린 뒤 initialization, configuration,
Peer 승인, running 전환을 순서대로 적용한다. 동기화가 실패하면 unhealthy
시작으로 처리하므로 부분 복구된 Core를 running으로 보고하지 않는다.

개발 시점의 Controller/Core 계약을 실제 Rust binary로 검증하려면 Unix에서
`scripts/test-tunnel-core-integration.sh`를 실행한다. 테스트는 폐기 가능한
Core process를 시작하고 실제 Unix socket을 통해 initialization, network
policy, Peer registration, start, health를 확인한다. privileged TUN,
routing, NAT, Gateway, public network 범위는 주장하지 않으며 별도 환경
검증으로 남긴다.

운영 조회에서 `CoreController.CollectMetrics`는 Core health label과
`GetStatistics`가 반환한 11개 비밀 없는 counter를 합친다. stopped 또는
unhealthy Core에는 조회하지 않고 두 IPC 호출에 연속 request ID를 사용한다.
snapshot에는 key, 평문 packet, DNS query 원문, 사용자별 identity data가 없다.

`PlainTunnel`과 `EncryptedTunnel`은 `with_metrics`를 통해 선택적인 `Metrics`
값을 받는다. 성공한 data-plane 송수신은 packet/byte counter를 갱신하고,
device·transport·codec·authentication·inner-packet·session type 오류는
`packet_errors`를 증가시킨다. metrics object는 atomic counter만 저장하며
실패한 datagram이나 평문을 보관하지 않는다. 또한 관찰된 session ID를 최대
216개까지 tx/rx byte·packet의 제한된 snapshot으로 유지하고, management
session 제거 시 해당 per-session snapshot도 제거한다.

VPN Server 승인 연동은 [`vpn-server-integration.md`](./vpn-server-integration.md)의
경계를 따른다. Controller는 Gateway/VPN Server의 정규화된 승인 정보와
HMAC 서명만 받고, 로그인 API나 `GATEWAY_SHARED_SECRET` 원문을 Rust Core에
전달하지 않는다.

키 변경 운영 절차는 [`key-lifecycle.md`](./key-lifecycle.md)에 따른다.
Gateway shared secret 교체는 Controller 서비스 인증 재시작으로 처리하고,
Server private key 교체는 기존 Core 세션을 종료한 뒤 새 장기 신원으로 Core를
재시작한다. 두 변경을 하나의 무중단 rolling 절차로 합치지 않는다.

`ListSessions`는 Peer 수준 connection status 경계다. 반환되는 13바이트
record에는 `session_id`, `peer_id`, lifecycle state code가 들어가며 key,
packet 내용, 사용자 profile data는 포함하지 않는다. 따라서 Controller는
data plane을 Go로 옮기지 않고 Peer별 connection state를 표시할 수 있다.

최종 state byte는 안정적인 `LifecycleState` 매핑을 사용한다. `0=Disconnected`,
`1=Connecting`, `2=Handshaking`, `3=Established`, `4=Rekeying`,
`5=Reconnecting`, `6=Closing`, `7=Closed`다. Session 생성·목록 테스트는
record shape와 established state 값을 확인한다.

`DnsUpstreamSelector`는 resolver adapter를 위해 검증된 upstream 순서를
유지한다. query가 실패하면 다음 provider로 이동하고 마지막 뒤에는 처음으로
돌아가며, 성공하면 현재 provider를 유지한다. selector는 upstream별
성공·실패 counter와 측정 latency 합계를 제한적으로 노출하지만 query name,
response body, 사용자별 history는 저장하지 않는다.
현재 Core에는 DNS response cache가 없으므로 임의의 결과를 무기한 보관해
검열 회피에 사용할 수 없다. 검증된 policy cursor만 노출하며, 향후 TTL
cache를 추가하려면 만료를 제한하고 별도 privacy review를 거쳐야 한다.

`PeerRateLimiter`는 Peer마다 독립된 제한 window를 소유한다. 한 Peer의
packet allowance를 모두 사용해도 다른 Peer의 allowance를 소비하지 않는다.
공유 server queue와 부하 상태 end-to-end 공정성은 OS/network integration
측정이 필요하다. Management frame과 UDP datagram은 parsing 전에 크기를
제한하고 malformed datagram은 device에 도달하기 전에 폐기하므로 잘못된
입력의 parser/work budget가 고정된다.

Secret configuration은 별도 경계를 따른다. `GATEWAY_SHARED_SECRET`는
Gateway/VPN service-authentication layer가 보관하고, `SERVER_PRIVATE_KEY`는
환경을 통해 Rust Core에 공급되어 보호된 `ServerIdentity`로 직접 parse된다.
두 값 모두 settings file, IPC, status, metrics에 들어가지 않는다.
Controller는 초기화 시 기존 service 경계에서 Gateway secret을 받으며
secret의 두 번째 복사본을 탐색하거나 저장하지 않는다.

## 운영 권한과 DNS 정책

초기 DNS 정책은 `DnsPolicy`의 순서가 지정된 upstream 목록을 사용하고,
Linux 적용 계층에서는 `resolvectl`의 UDP/TCP 53 transport만 실행한다. DoT와
DoH는 설정 모델에 보존할 수 있지만 별도 resolver adapter가 준비되기 전에는
활성화하지 않는다. 적용 전 `DnsSnapshot`을 보관하고 연결 종료나 실패 시
원래 link·resolver 설정을 역순으로 복원한다. Core는 DNS 질의 원문이나
사용자별 DNS 기록을 영구 저장하지 않으며, 장애 분석에 필요한 운영 정보도
정책 주소와 선택 cursor 수준으로 제한한다.

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

| 계층 | 대표 오류 타입 | 기본 처리 |
| --- | --- | --- |
| 패킷·프로토콜 | `ProtocolError`, `InnerIpPacketError`, `ManagementError` | 현재 입력만 폐기하고 루프 유지 |
| 장치·전송 | `DeviceError`, `TransportError` | 일시 오류는 재시도 정책으로 전달하고 종료 오류는 세션 정리 |
| 세션·인증 | `SessionError`, `CryptoError`, `NoiseHandshakeError` | 영향을 받은 세션을 닫고 키·Replay 상태 재사용 금지 |
| Controller·관리 | `ErrCore*`, 승인·권한 오류 | 작업만 실패시키고 다른 세션과 프로세스는 유지 |

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
