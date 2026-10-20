# VPN Server 연동 생명주기

이 문서는 Gateway, VPN Server, Go Controller, Rust Tunnel Core, 기존
WireGuard 경로 사이의 책임을 단계별로 고정한다. Gateway 로그인과 실제
VPN Server HTTP 호출은 이 저장소가 재구현하지 않으며, 외부 어댑터가 아래
계약에 맞는 정규화된 결과를 전달한다.

## 승인부터 연결까지

1. Gateway가 사용자를 인증하고 VPN Server 선택과 서비스 권한을 결정한다.
2. VPN Server 어댑터가 승인 정보와 HMAC 서명을 Controller에 전달한다.
3. Controller는 서명, server/device/user 식별자, 만료 시각, 공개키, 터널
   주소를 검증한다. shared secret은 Core IPC와 상태에 들어가지 않는다.
4. Controller는 검증된 공개 Peer와 허용 주소만 Core desired state에 등록한다.
5. 연결 요청은 승인된 Peer에 대해서만 세션을 생성한다.
6. Core는 승인된 서버 신원과 클라이언트 공개키로 핸드셰이크를 완료한 뒤
   세션 키와 데이터 경로를 만든다.

구현 경계는 `GatewayAuthenticator`, `GatewayApprovalResult`,
`PeerApproval.Validate`, `VPNServerAuthorization.ReceiveApproval`,
`CoreController.ApplyPeerApproval`,
`ManagementService` 순서로 대응한다. Gateway 로그인 자체의 성공 여부는
외부 어댑터가 책임지고, Controller는 서명된 승인 결과만 신뢰한다.

## 연결 종료와 권한 철회

일반 연결 종료는 해당 `session_id`만 종료한다. Peer 승인과 장기 공개키는
유지되므로 사용자는 같은 승인으로 다시 핸드셰이크할 수 있다.

권한 철회는 다음 순서로 처리한다.

1. VPN Server 어댑터가 철회 요청을 서명한다.
2. Controller가 서명을 검증하고 desired state에서 Peer를 제거한다.
3. 실행 중 Core에 `RemovePeer`를 전달해 해당 Peer의 승인과 세션을 제거한다.
4. 장기 키 폐기가 필요한 경우 `PurgeKey`를 사용해 키 경계와 세션을 함께
   폐기한다.
5. 이후 같은 Peer ID나 공개키로 세션을 만들려면 새 승인과 등록이 필요하다.

철회·만료·인증 실패는 자동 재연결하지 않는다. 다른 Peer의 세션과
프로세스 전체는 영향을 받지 않아야 하며, 로그에는 키와 평문 대신 상태와
안정적인 오류 분류만 남긴다.

## 상태와 메트릭

`ConnectionStatus`는 먼저 Peer 승인과 Core 실행 상태를 확인한 뒤 Core의
비밀 없는 `SessionStatus`를 조회하고 Peer ID 소유권을 재검증한다. 세션 ID를
아는 것만으로 다른 사용자의 상태나 메트릭을 조회할 수 없다.

Core 메트릭은 세션 수, 송수신 바이트/패킷, 인증 실패, Replay 거부,
재연결, 핸드셰이크 실패 같은 bounded counter만 노출한다. 키, 평문,
DNS 질의 원문, 개인키는 상태·IPC·로그에 포함하지 않는다.

## WireGuard 병행 운영

기존 WireGuard 설정 생성, 인터페이스 적용, route/firewall 전환, rollback은
기존 VPN Server 배포 어댑터의 책임이다. 이 저장소의 `EngineSelection`은
엔진 종류와 명시적 fallback 승인만 결정하며, 실제 프로세스 교체나 route
전환을 수행하지 않는다.

- `wireguard`: 기존 경로만 사용
- `tunnel-core`: 자체 엔진만 사용
- `auto`: Tunnel Core를 우선하고 WireGuard를 승인 대기 fallback으로 보존

자체 엔진의 코어 테스트가 통과한 것만으로 기존 WireGuard를 제거하거나
실제 사용자 트래픽을 전환하지 않는다. 배포 어댑터는 WireGuard 설정
snapshot, 적용 전 endpoint 예외 경로, 실패 시 원복 명령, 비정상 종료 후
복구 결과를 별도 증거로 기록해야 한다. 전환 게이트와 증거 형식은
[`wireguard-rollback-policy.md`](wireguard-rollback-policy.md)에 정의한다.

## 검증 범위

이 저장소에서 검증되는 범위는 HMAC·승인 검증, Peer 주소 격리, 승인된
세션 생성 경계, 철회·키 폐기, 상태 소유권 재검증, 엔진 선택 정책이다.
Gateway 로그인 유지, 실제 VPN Server HTTP 호출, WireGuard 설정 생성,
route 전환, 실제 인터넷 출구와 rollback은 권한 있는 배포 환경에서 별도
검증한다.
