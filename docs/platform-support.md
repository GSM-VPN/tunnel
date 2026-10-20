# 플랫폼 지원 범위

이 문서는 현재 `tunnel` 저장소가 제공하는 플랫폼 계층과 아직 외부
adapter가 필요한 범위를 구분한다. 플랫폼 검토는 지원 완료를 의미하지
않으며, 실제 네트워크 변경은 권한 있는 대상 OS에서 별도로 검증해야 한다.

## 현재 구현 경계

| 플랫폼 | 현재 확인된 범위 | 제공하지 않는 범위 |
| --- | --- | --- |
| Linux | `/dev/net/tun` 기반 `LinuxTunDevice`, Linux route·DNS·nftables 계획, Unix IPC | 운영망 forwarding/NAT·외부 인터넷 출구 검증 |
| Windows | Wintun 계층 타입, `netsh`·`route`·방화벽 명령 계획, Rust workspace CI | 실제 Wintun adapter 생성·패킷 I/O·관리자 권한 네트워크 적용 |
| macOS | Unix 계열 관리 socket 경계와 공통 `MemoryDevice` 테스트, 플랫폼 비종속 Rust Core 코드 | macOS TUN adapter, route·DNS·방화벽 적용, 실제 VPN 연결 |

macOS에서 `#[cfg(unix)]` 관리 socket과 플랫폼 비종속 모듈을 빌드할 수
있다는 사실만으로 macOS VPN이 동작한다고 판단하지 않는다. 현재 `tunnel-core`
실행 파일은 Unix Domain Socket 관리 경계를 요구하며, 실제 packet device는
Linux와 Windows 전용 모듈로 분리되어 있다.

## 후속 macOS 구현 조건

macOS 지원을 시작할 때는 다음을 별도 구현 단위로 다룬다.

1. macOS TUN 또는 Network Extension 계층의 책임과 배포 권한을 확정한다.
2. endpoint 예외 경로, 기본 route, DNS, IPv6 정책을 macOS 명령 모델에 맞춰
   계획하고 rollback snapshot을 제공한다.
3. 권한 없는 개발 환경의 단위 테스트와 권한 있는 macOS 통합 테스트를
   분리한다.
4. 실제 adapter·DNS·leak 결과를 기록하기 전에는 macOS VPN 지원을 완료로
   표시하지 않는다.

따라서 현재 저장소의 macOS 상태는 “지원 범위 검토 완료, adapter 구현 대기”다.
