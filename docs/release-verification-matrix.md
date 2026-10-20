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
| 운영 절차와 WireGuard rollback | policy-documented | `docs/wireguard-rollback-policy.md`, `docs/vpn-server-lifecycle.md`, `docs/vpn-server-integration.md` |
| Linux TUN·namespace·forwarding/NAT | required | 권한 있는 Linux 시나리오와 `docs/recovery-test-plan.md`의 결과 기록 필요 |
| DNS·IPv6 leak·Kill Switch | required | 실제 OS 네트워크 경로에서 독립 실행 필요 |
| Windows/Wintun·macOS adapter | required | 대상 OS와 adapter가 있는 환경에서 별도 검증 필요 |
| 암호화·프로토콜 독립 검토 | required | 외부 검토 보고서가 배포 gate |

`required` 항목을 단위 테스트나 문서 존재만으로 `verified`로 바꾸지 않는다.
실제 결과를 추가할 때는 커밋, 환경, 명령, 관찰 결과, 정리 결과를 함께
기록하고 관련 STEP 체크포인트를 그때 갱신한다. 자체 엔진 검증 전에는 기존
WireGuard 경로와 rollback 절차를 유지한다.

## `STEP.md` 최종 체크리스트와의 대응

다음 항목은 저장소 내부 테스트와 CI에서 반복 실행되는 근거가 있으므로
최종 체크리스트에 반영한다.

| 최종 기준 | 검증 근거 | 범위 제한 |
| --- | --- | --- |
| Linux TUN 간 양방향 IP 패킷 전달 | `scripts/test-linux-tun-pair.sh`, `linux-tun-pair` 예제 | namespace 내부 양방향 패킷 전달까지이며 외부 인터넷은 포함하지 않음 |
| UDP 기반 터널 전송 | `UdpTransport` 단위 테스트와 TUN pair CI | 실제 공용망 손실·지연 조건은 포함하지 않음 |
| 기본 패킷 검증과 오류 처리 | protocol decoder 테스트, fuzz workflow, malformed datagram 테스트 | 독립 보안 검토를 대체하지 않음 |
| 인증·암호화·Replay·세션 수명주기 | `noise`, `crypto`, `session`, `key_rotation` 테스트 | 배포 환경 보안 승인이나 외부 감사는 포함하지 않음 |
| Go Controller와 Rust Core IPC | `scripts/test-tunnel-core-integration.sh`와 Go Controller 테스트 | Gateway 로그인과 VPN Server 외부 HTTP 서비스는 포함하지 않음 |

최종 검증 요약의 로컬 항목은 다음 자동화 근거로 대응한다.

| 최종 검증 항목 | 자동화 근거 | 한계 |
| --- | --- | --- |
| 단위 테스트 | Go·Rust CI job | 외부 운영 환경은 포함하지 않음 |
| 통합 테스트 | Controller/Core binary contract, Linux TUN smoke·pair CI | 실제 VPN 서비스와 공용 인터넷은 포함하지 않음 |
| 네트워크 Namespace 테스트 | `linux-tun-pair` job의 root namespace 격리 실행 | forwarding/NAT/external internet은 포함하지 않음 |
| 보안 테스트 | protocol fuzzing 및 crypto/noise/session/peer 테스트 | 독립 보안 검토와 leak 테스트는 포함하지 않음 |

반대로 실제 VPN Server의 IP forwarding/NAT, DNS·IPv6 leak, Windows
Wintun, Kill Switch, 외부 인터넷 출구와 독립 보안 검토는 이 표의
`required` 상태를 유지한다. 해당 항목은 권한 있는 환경에서 재현 결과를
기록한 뒤에만 `STEP.md`에서 체크한다.
