# GSM VPN Tunnel

GSM VPN Tunnel은 GSM VPN을 위한 자체 터널링 엔진의 연구·개발 저장소다.
Go Controller가 운영 제어·IPC·상태·메트릭을 담당하고, Rust Tunnel Core가
프로토콜·암호화·UDP·TUN·세션 데이터 플레인을 담당한다.

> 현재 저장소는 연구·개발 단계다. 독립 보안 검토와 실제 배포 환경 검증 전에는
> 공용 사용자 대상 VPN으로 사용하지 않는다. 기존 WireGuard 경로와 rollback
> 절차를 유지한다.

## 현재 상태

현재 코드베이스에서 다음 범위가 구현·로컬 검증되어 있다.

- Go Controller와 Rust Tunnel Core의 관리 IPC
- 패킷 codec·검증·fuzzing
- Noise·AEAD·Replay·세션·키 세대 관리
- UDP transport와 Linux TUN pair 격리 테스트
- Core 프로세스 상태·재시작·기본 메트릭
- Rust Core benchmark 실행기와 기준선
- Linux systemd 기동 예시와 secret 주입용 설정 템플릿

다음은 아직 실제 환경 검증이 필요한 범위다.

- Gateway·VPN Server 운영 서비스와의 실제 인증·Peer 연동
- 권한 있는 Linux 환경의 forwarding·NAT·외부 인터넷 출구
- DNS·IPv6 leak 및 Kill Switch
- Windows Wintun·라우팅·DNS·UI 종단 간 동작
- 다중 클라이언트 외부망 성능·장애 복구
- 독립 보안 검토와 공용 배포 승인

상세 상태는 [`docs/current-status.md`](./docs/current-status.md), 남은 작업은
[`STEP.md`](./STEP.md), 검증 근거는
[`docs/release-verification-matrix.md`](./docs/release-verification-matrix.md)에
기록한다.

## 기술 구성

| 계층 | 책임 |
| --- | --- |
| Go Controller | Gateway/VPN Server 제어 경계, IPC client, 상태·메트릭·재시작 정책 |
| Rust Tunnel Core | 패킷 format, Noise·AEAD, Replay·세션, UDP·TUN 데이터 경로 |
| Unix Domain Socket | Controller와 Core 사이의 길이 프리픽스 관리 메시지 |
| Linux adapter | TUN·route·DNS·nftables 적용 계획과 권한 경계 |
| Windows adapter | Wintun·route·DNS·firewall 적용 계획 및 후속 검증 대상 |

## 빠른 시작

### 요구 사항

- Go toolchain
- Rust toolchain과 Cargo
- Linux TUN pair 테스트를 실행하려면 Linux kernel의 network namespace와
  `/dev/net/tun` 권한
- 외부망·NAT·DNS·Windows 검증에는 별도의 권한 있는 환경

### 저장소 검증

```bash
./scripts/validate.sh
```

개별 검증은 다음과 같다.

```bash
go test ./...
cargo test --workspace --all-targets --all-features
./scripts/test-tunnel-core-integration.sh
./scripts/test-linux-tun-pair.sh
```

권한이 없는 호스트에서 Linux TUN 테스트가 실행되지 않으면 실패 원인과
환경을 기록한다. 그 결과만으로 외부 인터넷 연결을 주장하지 않는다.

### 로컬 loopback 예제

권한이나 운영 secret 없이 codec과 UDP 양방향을 확인하려면 두 터미널에서
실행한다.

```bash
cargo run -p tunnel-core --example server -- --listen 127.0.0.1:51820
cargo run -p tunnel-core --example client -- --server 127.0.0.1:51820 --message hello
```

이 예제는 암호화된 VPN이나 운영망 연결이 아니며, 검증된 echo 왕복과 UDP
transport만 확인한다. 자세한 범위는 [`examples/README.md`](./examples/README.md)를
참조한다.

## Linux 실 적용 준비

현재 구현된 Rust Core와 관리 IPC를 Linux systemd에서 기동하려면 다음 문서를
따른다.

```bash
cargo build --release --package tunnel-core --bin tunnel-core
```

설치·서비스 계정·환경 변수·systemd·소켓 권한·중지 절차는
[`deploy/README.md`](./deploy/README.md)에 있다. 설정 템플릿은
[`deploy/gsm-tunnel.env.example`](./deploy/gsm-tunnel.env.example), 서비스
예시는 [`deploy/systemd/gsm-tunnel-core.service`](./deploy/systemd/gsm-tunnel-core.service)다.

템플릿에는 실제 secret이나 private key를 넣지 않는다. 현재 예시는 Core
프로세스와 관리 IPC만 기동하며, routing·NAT·DNS·firewall 규칙을 자동으로
변경하지 않는다.

## Benchmark

Rust Core의 결정론적 codec·crypto·session benchmark를 실행하고 조건과 원시
출력을 Markdown으로 기록한다.

```bash
./scripts/run-core-benchmarks.sh benchmark-results/core-benchmark.md
```

기준선과 측정 범위는 [`docs/performance-results.md`](./docs/performance-results.md)와
[`docs/performance.md`](./docs/performance.md)에 기록한다. 이 benchmark는
실제 VPN 처리량·외부망 지연·DNS·IPv6 성능을 대체하지 않는다.

## 저장소 구조

```text
internal/controller/       Go Controller와 Core lifecycle/IPC
internal/protocol/         Go 관리 메시지와 서비스 계약
crates/tunnel-core/        Rust protocol, crypto, transport, TUN, session
crates/tunnel-core/examples/  loopback·Linux TUN 예제
scripts/                   재현 가능한 검증·benchmark 실행기
deploy/                    Linux 설정 템플릿과 systemd 예시
docs/                      설계·보안·운영·성능·플랫폼 문서
```

## 문서 읽기 순서

1. [`SPEC.md`](./SPEC.md) — 요구사항과 시스템 방향
2. [`STEP.md`](./STEP.md) — 현재 미완료 항목과 실행 순서
3. [`docs/current-status.md`](./docs/current-status.md) — 현재 구현·검증·제한
4. [`docs/architecture.md`](./docs/architecture.md) — 계층과 프로세스 경계
5. [`docs/protocol-design.md`](./docs/protocol-design.md) — 패킷·상태·버전
6. [`docs/security-design.md`](./docs/security-design.md) — 보안 경계와 로그 정책
7. [`docs/release-verification-matrix.md`](./docs/release-verification-matrix.md) — 배포 gate
8. [`docs/platform-support.md`](./docs/platform-support.md) — 플랫폼 지원 범위
9. [`CONTRIBUTING.md`](./CONTRIBUTING.md) — 변경·검증·PR 절차

## 보안 안내

취약점은 공개 이슈에 상세 내용을 먼저 올리지 말고 저장소 관리자에게
비공개로 전달한다. 실제 secret, private key, 사용자 payload, 암호문을
로그·테스트·이슈·PR에 포함하지 않는다. 자세한 절차는
[`SECURITY.md`](./SECURITY.md)를 참조한다.

자체 프로토콜은 독립 보안 검토가 완료되기 전까지 연구·개발용으로만
취급한다.

## 기여

브랜치·이슈·커밋·PR·CI 절차는 [`CONTRIBUTING.md`](./CONTRIBUTING.md)를
따른다. 커밋 메시지는 저장소 규칙인 `type: Korean summary` 형식을 사용한다.
