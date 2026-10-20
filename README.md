# GSM VPN Tunnel

GSM VPN Tunnel은 GSM VPN의 자체 터널링 엔진을 구현하는 저장소입니다.

프로젝트의 설계 기준은 [`SPEC.md`](./SPEC.md), 단계별 구현 계획은 [`STEP.md`](./STEP.md)에서 관리합니다.

현재 구현 범위와 검증 상태는 [`docs/current-status.md`](./docs/current-status.md),
세부 검증 근거와 외부 환경 대기 항목은
[`docs/release-verification-matrix.md`](./docs/release-verification-matrix.md)에서
확인할 수 있습니다.

## 기술 구성

- Go: Controller, 운영 제어, IPC, 메트릭
- Rust: Protocol Core, 암호화, UDP, TUN, 세션, 데이터 플레인
- 초기 검증 환경: Linux

## 로컬 검증

```bash
./scripts/validate.sh
```

Rust Core benchmark를 실행하고 조건·원시 결과를 보고서로 남기려면 다음 명령을 사용합니다.

```bash
./scripts/run-core-benchmarks.sh benchmark-results/core-benchmark.md
```

현재 저장소는 Linux 기반의 연구·개발용 Core와 제어 계층을 제공합니다.
실제 네트워크 적용과 배포 권한 설정은 별도 통합 검증이 필요합니다.

## 주요 문서

- [`docs/architecture.md`](./docs/architecture.md) — Controller와 Rust Core 경계
- [`docs/protocol-design.md`](./docs/protocol-design.md) — 패킷·상태·버전 설계
- [`docs/security-design.md`](./docs/security-design.md) — 암호화·권한·로그 경계
- [`docs/performance.md`](./docs/performance.md) — benchmark 실행과 결과 기록
- [`docs/platform-support.md`](./docs/platform-support.md) — Linux·Windows·macOS 범위
- [`deploy/README.md`](./deploy/README.md) — Linux systemd 설치·설정·기동 절차
- [`CONTRIBUTING.md`](./CONTRIBUTING.md) — 브랜치·이슈·PR·검증 절차

## 보안 안내

자체 프로토콜은 독립적인 보안 검토가 완료되기 전까지 연구·개발용으로만 취급해야 합니다. 기존 WireGuard 구현은 자체 구현의 검증이 끝날 때까지 제거하지 않습니다.

