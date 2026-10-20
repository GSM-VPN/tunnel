# 현재 구현 상태

이 문서는 `tunnel` 저장소의 현재 구현·검증 범위를 요약한다. 제품 배포
승인 문서가 아니며, 최종 체크 항목은 [`STEP.md`](../STEP.md)에서 관리한다.

## 현재 제공 범위

| 영역 | 현재 상태 | 확인 방법 |
| --- | --- | --- |
| Go Controller | 구현됨 | `go test ./...`, Controller 테스트 |
| Rust Tunnel Core | 구현됨 | `cargo test --workspace --all-targets --all-features` |
| 패킷 codec·프로토콜 | 로컬 검증됨 | codec·parser 테스트와 fuzz workflow |
| Noise·AEAD·Replay·키 세대 | 로컬 검증됨 | crypto·noise·replay·key rotation 테스트 |
| Go–Rust IPC | 로컬 통합 검증됨 | `scripts/test-tunnel-core-integration.sh` |
| Linux TUN pair | 격리 테스트 검증됨 | `scripts/test-linux-tun-pair.sh` |
| Core 프로세스 재시작 | 로컬 통합 검증됨 | Controller/Core integration test |
| Core benchmark | 실행기와 기준선 제공 | `scripts/run-core-benchmarks.sh` |
| WireGuard rollback | 절차 문서화됨 | [`wireguard-rollback-policy.md`](./wireguard-rollback-policy.md) |

## 현재 제한 범위

다음 항목은 코드와 계획만으로 완료 처리하지 않는다.

- 실제 Gateway 로그인·VPN Server 운영 연동
- Linux 권한 환경의 IP forwarding·NAT·외부 인터넷 출구
- 실제 DNS·IPv6 leak 및 Kill Switch 검증
- Windows Wintun adapter·라우팅·DNS·UI 종단 간 동작
- 다중 클라이언트 외부망 성능과 장애 주입 결과
- 독립 보안 검토와 공용 사용자 대상 배포 승인

각 제한 항목의 실행 조건과 증거 형식은
[`release-verification-matrix.md`](./release-verification-matrix.md),
[`platform-support.md`](./platform-support.md),
[`recovery-test-plan.md`](./recovery-test-plan.md)에 기록한다.

## 재현 명령

저장소 내부 검증은 다음 순서로 실행한다.

```bash
./scripts/validate.sh
./scripts/test-tunnel-core-integration.sh
./scripts/test-linux-tun-pair.sh
./scripts/run-core-benchmarks.sh benchmark-results/core-benchmark.md
```

환경에 따라 권한이 필요한 테스트가 있으면 해당 스크립트의 요구사항과
실패 원인을 결과에 함께 기록한다. benchmark 결과는 Rust Core의 결정론적
경로 기준선이며 실제 VPN 처리량이나 외부망 성능을 의미하지 않는다.

## 문서 읽기 순서

1. [`SPEC.md`](../SPEC.md) — 제품·시스템 요구사항
2. [`STEP.md`](../STEP.md) — 미완료 작업과 실행 순서
3. [`architecture.md`](./architecture.md) — Controller/Core 경계
4. [`protocol-design.md`](./protocol-design.md) — 패킷과 상태 설계
5. [`security-design.md`](./security-design.md) — 보안 경계와 제한
6. [`release-verification-matrix.md`](./release-verification-matrix.md) — 검증 상태
7. [`performance.md`](./performance.md) — benchmark 실행·기록 규칙
8. [`platform-support.md`](./platform-support.md) — 플랫폼별 지원 범위

## 상태 변경 규칙

실제 실행 결과를 추가할 때는 commit, OS·kernel, CPU·memory, 명령, 입력
조건, 관찰 결과, 정리 결과를 함께 기록한다. 문서나 단위 테스트가 존재한다는
이유만으로 외부 통합·보안·배포 항목을 완료로 표시하지 않는다.
