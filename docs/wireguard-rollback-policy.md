# WireGuard 병행 운영과 롤백 정책

Tunnel Core를 도입하는 동안 기존 WireGuard 경로를 보존한다. 이 저장소의
Controller는 엔진 선택과 승인 게이트만 제공하며, 실제 프로세스 교체와
라우팅·방화벽 변경은 권한 있는 배포 어댑터가 수행한다.

## 전환 게이트

`auto` 설정은 Tunnel Core를 primary로 선택하지만 WireGuard fallback을
승인 대기 상태로 남긴다. `FallbackAllowed(true)`가 확인되기 전에는
WireGuard 프로세스를 시작하거나 사용자 트래픽의 route를 바꾸지 않는다.
승인 없이 실패를 감지했다는 이유만으로 fallback하는 동작은 허용하지 않는다.

다음 조건을 모두 만족하기 전에는 기존 WireGuard 경로를 제거하지 않는다.

- Tunnel Core의 프로토콜·세션·복구 검증이 대상 배포 환경에서 완료된다.
- 전환 전 WireGuard 설정과 현재 route/firewall 상태를 snapshot한다.
- VPN endpoint로 향하는 물리 NIC 예외 경로가 보존된다.
- Core 실패 시 route/firewall을 이전 상태로 원복하고 WireGuard를 재시작하는
  절차가 준비된다.
- 전환과 원복 결과에 대한 운영 증거가 저장된다.

## 롤백 증거

배포 어댑터는 각 전환 시도마다 다음 항목을 기록한다. 개인키, 세션키,
사용자 트래픽, 인증 토큰은 기록하지 않는다.

1. 릴리스 버전, 시도 시각, 대상 호스트 식별자
2. 설정 snapshot의 해시와 저장 위치
3. 적용한 route/firewall 변경의 명령 요약과 적용 순서
4. endpoint 예외 경로가 유지되었는지에 대한 확인 결과
5. 실패 원인 분류, 원복 시작·종료 시각, 원복 후 WireGuard 상태
6. 원복 후 관리 경로와 기존 VPN 경로의 연결 확인 결과

실제 route/firewall 적용과 WireGuard 재시작은 이 저장소의 단위 테스트로
완료 처리하지 않는다. 권한 있는 Linux/Windows 배포 환경에서 명령, 환경,
관찰 결과, 정리 결과를 함께 기록한 뒤에만 운영 검증으로 승격한다.

## 코드와 운영 책임

- `internal/controller/engine_selection.go`는 fallback 승인 여부만 결정한다.
- 배포 어댑터는 snapshot, route/firewall 원복, 프로세스 재시작을 담당한다.
- 운영 검증 전까지 `wireguard` 직접 선택과 승인 대기 fallback을 모두
  지원한다.
- 자동 fallback이나 WireGuard 제거를 추가하려면 독립적인 운영 검증과
  별도 보안 검토를 먼저 남긴다.

관련 구현 게이트는
[`vpn-server-lifecycle.md`](vpn-server-lifecycle.md)와
[`release-verification-matrix.md`](release-verification-matrix.md)에 연결한다.
