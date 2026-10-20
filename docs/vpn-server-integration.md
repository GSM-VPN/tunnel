# VPN Server 연동 경계

전체 승인·세션·철회·WireGuard 병행 생명주기는
[`vpn-server-lifecycle.md`](./vpn-server-lifecycle.md)에 단계별로 정리한다.
이 문서는 각 경계의 자료형과 보안 제한을 보완한다.

## 책임 분리

Gateway와 VPN Server는 사용자 인증, 서비스 권한, 서버 선택, 승인 정보를
담당한다. Go Controller는 이 결과를 검증하고 Rust Tunnel Core에 공개된 Peer
승인 정보와 세션 제어만 전달한다. Gateway shared secret와 장기 개인키는
Core IPC payload나 Peer 상태에 들어가지 않는다.

현재 공개된 `GSM-VPN/vpn-server` 계약에서 확인한 입력은 다음과 같다.

- `GATEWAY_SHARED_SECRET` 기반 HMAC-SHA-256 서명
- 서명 입력은 `parts.join("|")`
- 결과는 base64url 인코딩
- Peer 등록 입력은 공개키, 허용 IP, `serverId`, `deviceId`
- Peer 상태는 공개키, 허용 IP, handshake 시각, 송수신 카운터를 포함

Controller는 이 결과를 `GatewayApprovalResult`로 받는다. 이 envelope는
서명 대상 parts, HMAC signature, 정규화된 `PeerApproval`, request ID를 한
경계로 묶고 `ReceiveApproval`에서 기존 HMAC·server·device·expiry·주소
검증을 수행한다. HTTP transport와 Gateway 로그인 흐름은 envelope를 만드는
어댑터의 책임이며 Core나 IPC 프로토콜에 노출하지 않는다.

공개 저장소의 HTTP 서버 구현이 완성되지 않은 상태이므로 이 저장소는
Gateway URL이나 엔드포인트를 추측해 직접 호출하지 않는다. 대신
`VPNServerAuthorization`이 정규화된 승인 결과를 받는 명시적 경계를 제공한다.
실제 Gateway/VPN Server 어댑터는 해당 API 계약이 확정된 뒤 이 경계에 연결한다.

배포 시 `ParseVPNServerConfig`는 기존 `GATEWAY_SHARED_SECRET`와 함께
`VPN_SERVER_ID`, `TUNNEL_CORE_BINARY`, `TUNNEL_CORE_IPC_SOCKET`,
`TUNNEL_CORE_MAX_PEERS`를 읽는다. Core 바이너리와 소켓은 명시적으로
지정해야 하며, Peer 상한은 216 이하로 검증한다. `Authenticator()`가
생성한 검증기 외에는 secret을 전달하지 않으므로 Core 환경과 IPC payload에는
secret이 포함되지 않는다.

## 승인 흐름

```text
Gateway/VPN Server
  │ 승인 정보 + HMAC signature
  ▼
VPNServerAuthorization
  ├─ HMAC timing-safe 검증
  ├─ server/device/user/expiry 검증
  ├─ 10.80.0.0/16·fd80:1234:5678::/64 주소 검증
  └─ 공개 Peer 정보로 변환
       ▼
CoreController desired state
       ├─ Core 실행 중: RegisterPeer IPC
       └─ Core 재시작: 상태 재동기화
```

승인 정보가 만료되거나 일반 연결 해지되면 Controller desired state에서
제거하고 실행 중 Core에는 `RemovePeer`를 호출한다. 키 파기는 별도
`PurgeKey` 관리 동작으로 제공하며, 동일하게 Rust Core의 승인과 해당 Peer의
모든 세션을 즉시 제거하고 `peer_key_purged` 감사 이벤트를 남긴다. 두 동작
모두 승인되지 않은 Peer의 새 세션을 즉시 거부하고, Core 재시작 시 복원하지
않는다. 새 공개키는 새 승인 절차를 거쳐야 한다.

서비스 상태 조회는 `VPNServerAuthorization::ConnectionStatus` 경계를 사용한다.
Controller는 먼저 Peer 승인과 Core 실행 상태를 확인하고, Core의 비밀 없는
`SessionStatus`를 조회한 뒤 응답의 Peer ID가 요청한 Peer와 일치하는지 다시
검증한다. 따라서 세션 ID를 알고 있더라도 다른 사용자의 연결 상태를 조회할
수 없다.

## 서명 경계

`GatewayAuthenticator`는 비어 있지 않은 secret만 허용하고 HMAC 결과를
constant-time 비교한다. secret 자체는 로그, 상태 snapshot, Peer payload,
IPC payload에 복사하지 않는다. 서명 실패는 승인 정보 검증 전에 반환한다.

`GATEWAY_SHARED_SECRET`의 공급은 기존 Gateway/VPN Server 서비스 인증 설정이
담당하며, Controller는 초기화 시 전달받은 값으로 검증기만 구성한다. 반면
`SERVER_PRIVATE_KEY`는 기존 `vpn-server`와 동일하게 32바이트 표준 Base64로
저장·공급하며 Rust Core 프로세스의 환경 변수 경계에서만 파싱된다. 파생된
서버 공개키도 32바이트 표준 Base64로 표현한다. 두 값 모두 설정 파일, IPC,
상태 조회, 메트릭으로 우회 공급하지 않는다.

## 현재 범위와 후속 연동

이 문서는 서비스 인증을 Tunnel Core에 재구현하지 않는다. Gateway 로그인,
VPN 서버 등록, HTTP endpoint 호출, WireGuard fallback 선택은 기존 서비스의
API 계약이 확정된 뒤 별도 어댑터에서 구현해야 한다. 그 전까지 Tunnel Core는
연구·개발용으로만 취급하며 기존 WireGuard 경로를 제거하지 않는다.

엔진 선택 경계는 `ParseEngineSelection`이 담당한다. `wireguard`와
`tunnel-core`는 단일 엔진 선택이며, `auto`는 Tunnel Core를 우선하고
WireGuard를 fallback 후보로만 보존한다. `auto`에서도 fallback은 명시적인
운영 승인 없이는 허용되지 않는다. 이 저장소는 엔진 프로세스 교체나 라우트
전환을 자동으로 수행하지 않으므로, 실제 전환은 기존 VPN Server 배포
어댑터와 rollback 절차에서 별도로 검증해야 한다.

## 완료 기준과 검증 범위

현재 코어·Controller 경계에서 다음 동작은 결정론적인 테스트로 검증된다.

| 기준 | 검증 근거 |
| --- | --- |
| 승인된 사용자만 연결 | `PeerApproval.Validate`, `CreateSession`, Rust Core 승인 검사 |
| 권한 철회 시 세션 정리 | `RemovePeer`/`PurgeKey`와 Core의 Peer 세션 제거 테스트 |
| 사용자별 VPN IP 격리 | 주소 풀의 중복·서버 주소 제외 테스트와 승인 주소 검증 |
| 다중 세션 상한 | `SessionTable`, Peer Registry, 216 세션 자원 제한 테스트 |

Gateway 로그인 유지, 실제 VPN Server HTTP 호출, Linux namespace를 통한
인터넷 출구·NAT 검증은 외부 서비스와 권한 있는 네트워크 환경이 필요하다.
따라서 이 문서의 코어 테스트 통과를 실제 배포 완료로 해석하지 않으며,
해당 통합 테스트가 끝나기 전에는 자체 엔진을 기존 WireGuard 경로와
대체하지 않는다.
