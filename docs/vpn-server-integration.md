# VPN Server 연동 경계

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

공개 저장소의 HTTP 서버 구현이 완성되지 않은 상태이므로 이 저장소는
Gateway URL이나 엔드포인트를 추측해 직접 호출하지 않는다. 대신
`VPNServerAuthorization`이 정규화된 승인 결과를 받는 명시적 경계를 제공한다.
실제 Gateway/VPN Server 어댑터는 해당 API 계약이 확정된 뒤 이 경계에 연결한다.

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

승인 정보가 만료되거나 철회되면 Controller desired state에서 제거하고,
실행 중 Core에는 `RemovePeer`를 호출한다. Rust Core는 철회된 Peer에 속한
세션도 함께 제거한다. 승인되지 않은 Peer의 세션 생성은 Controller와 Core
양쪽에서 거부한다.

## 서명 경계

`GatewayAuthenticator`는 비어 있지 않은 secret만 허용하고 HMAC 결과를
constant-time 비교한다. secret 자체는 로그, 상태 snapshot, Peer payload,
IPC payload에 복사하지 않는다. 서명 실패는 승인 정보 검증 전에 반환한다.

`GATEWAY_SHARED_SECRET`의 공급은 기존 Gateway/VPN Server 서비스 인증 설정이
담당하며, Controller는 초기화 시 전달받은 값으로 검증기만 구성한다. 반면
`SERVER_PRIVATE_KEY`는 Rust Core 프로세스의 `SERVER_PRIVATE_KEY` 환경 변수로
공급되어 Core identity 경계에서만 파싱된다. 두 값 모두 설정 파일, IPC,
상태 조회, 메트릭으로 우회 공급하지 않는다.

## 현재 범위와 후속 연동

이 문서는 서비스 인증을 Tunnel Core에 재구현하지 않는다. Gateway 로그인,
VPN 서버 등록, HTTP endpoint 호출, WireGuard fallback 선택은 기존 서비스의
API 계약이 확정된 뒤 별도 어댑터에서 구현해야 한다. 그 전까지 Tunnel Core는
연구·개발용으로만 취급하며 기존 WireGuard 경로를 제거하지 않는다.
