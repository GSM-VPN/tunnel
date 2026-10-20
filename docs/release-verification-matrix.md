# 배포 검증 매트릭스

이 표는 구현된 코드 증거와 배포 환경에서 별도로 수행해야 하는 검증을
구분한다. `unit`과 `local-integration`은 저장소에서 재현할 수 있지만,
`privileged-integration`과 `independent-review`는 결과 기록 없이는 완료로
판정하지 않는다.

| 영역 | 상태 | 근거 또는 실행 방법 |
| --- | --- | --- |
| 프로토콜·암호화 단위 동작 | verified | `cargo test --workspace --all-targets --all-features`, `docs/security-design.md` |
| Go 관리 파서 Fuzzing | verified | `scripts/test-protocol-fuzz.sh`, `.github/workflows/fuzz.yml` |
| Controller ↔ Rust Core IPC | verified | `scripts/test-tunnel-core-integration.sh`, `docs/development.md` |
| Gateway 승인 결과 경계 | verified | `GatewayApprovalResult`, `docs/vpn-server-integration.md` |
| 세션·Core 재시작 정책 | verified | `internal/controller/*_test.go`, `docs/recovery-test-plan.md` |
| 운영 절차와 WireGuard rollback | documented | `docs/vpn-server-lifecycle.md`, `docs/vpn-server-integration.md` |
| Linux TUN·namespace·forwarding/NAT | required | 권한 있는 Linux 시나리오와 `docs/recovery-test-plan.md`의 결과 기록 필요 |
| DNS·IPv6 leak·Kill Switch | required | 실제 OS 네트워크 경로에서 독립 실행 필요 |
| Windows/Wintun·macOS adapter | required | 대상 OS와 adapter가 있는 환경에서 별도 검증 필요 |
| 암호화·프로토콜 독립 검토 | required | 외부 검토 보고서가 배포 gate |

`required` 항목을 단위 테스트나 문서 존재만으로 `verified`로 바꾸지 않는다.
실제 결과를 추가할 때는 커밋, 환경, 명령, 관찰 결과, 정리 결과를 함께
기록하고 관련 STEP 체크포인트를 그때 갱신한다. 자체 엔진 검증 전에는 기존
WireGuard 경로와 rollback 절차를 유지한다.
