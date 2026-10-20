# 보안 경계

이 프로젝트는 연구·개발용 소프트웨어다. 독립적인 보안 검토 전에는 범용 VPN으로 배포하지 않는다.

## 현재 보호 기능

- ChaCha20-Poly1305가 암호화 payload와 header를 인증한다.
- 송신 cipher state와 수신 cipher state를 분리한다.
- 2,048개 packet replay window가 중복·오래된 sequence를 거부한다.
- 인증 실패는 replay-window slot을 소비하지 않는다.
- 인증에 성공한 payload만 장치에 전달한다.
- 암호화 tunnel은 설정한 시간·바이트·sequence 경계 전에 멈춰 key generation이 교체 한도를 넘지 않게 한다.
- 인증된 re-handshake가 암호화 tunnel의 rekey 경계를 통해 새로운 방향별 key를 설치할 수 있다. generation은 단조 증가해야 하며 이전 key, replay window, sequence counter, byte counter, 시간 예산을 함께 폐기한다.
- 교체 직후 이전 key generation의 packet을 거부한다. 현재 경계에는 이전 key를 잠시 허용하는 grace window가 없다.
- 서버 packet policy는 인증된 session의 source가 승인된 가상 IPv4/IPv6 주소와 같도록 요구할 수 있다. 이는 넓은 tunnel-range 검사와 별개이며 Peer 간 주소 claim을 거부한다.
- sequence counter는 checked arithmetic를 사용한다. overflow는 nonce 재사용 위험이 있는 포화 대신 종료 오류가 된다.
- Management message에는 opaque payload만 있고 key field는 없다.
- IPC는 network listener 대신 로컬 Unix Domain Socket을 사용한다.
- 새 identity는 `ServerIdentity::generate`가 OS CSPRNG에서 private material을 채워 생성한다. 안정적인 배포에서는 매번 재시작 때 새 key를 만들지 않고 공급된 `SERVER_PRIVATE_KEY`를 읽는다.

## 비밀 정보

`GATEWAY_SHARED_SECRET`는 control-plane credential이며 tunnel data key로 사용하지 않는다. `SERVER_PRIVATE_KEY`는
Rust identity 경계에만 속하며, 둘 다 log·metrics·management payload에 넣지 않는다.

`GATEWAY_SHARED_SECRET`는 Go Controller의 service-plane HMAC verifier만 사용한다. Core로 전달하지 않고, tunnel
packet 암호화나 Noise static key· server public key 파생의 입력으로 사용하지 않는다.

`ServerIdentity`는 Rust Core 안에서 `vpn-server`가 사용하는 canonical 32바이트 standard Base64 형식으로
`SERVER_PRIVATE_KEY`를 읽고 X25519 public key를 결정론적으로 파생한다. public key는 pinning을 위해 같은 Base64 형식으로
노출한다. debug 출력에서는 private key를 가리며 Noise responder는 이 identity 경계를 통해서만 key를 사용할 수 있다. Go
Controller는 `GATEWAY_SHARED_SECRET`를 자체 service-authentication 경계에 보관하고 Core IPC payload에 포함하지 않는다.
Core는 management socket을 bind하기 전에 `SERVER_PRIVATE_KEY`를 검증하며, 누락·잘못된 key면 시작하지 않는다.

Gateway service secret과 Core server identity의 변경·재시작 절차는 [`key-lifecycle.md`](key-lifecycle.md)에 분리해
기록한다. service secret 변경은 Controller 인증 경계만 재시작하고, server identity 변경은 session을 drain한 뒤 Core
process를 교체하며 client가 새 public key를 pin하고 검증한 뒤 재접속해야 한다.

Session cipher key는 `zeroize` 기반 저장소를 사용한다. 교체 전에 이전 generation을 지우고 cipher drop 시 active key도 지운다.
장기 server private key와 임시 key parsing buffer도 같은 정책을 사용한다.

기본 data-key rotation policy는 각 방향에서 1시간 또는 1GiB 전송 중 먼저 도달하는 조건이다. 경계에서는 인증된 새 generation이 설치될 때까지
session을 멈춘다. rekey 실패 시 session은 `CLOSING`으로 전환하며 무한 재시도나 이전 key 사용을 계속하지 않는다.

`PeerRateLimiter`는 handshake와 packet admission에 별도의 제한된 fixed window를 적용하고 추적하는 Peer ID 수도 제한한다. 한
Peer가 admission 작업을 모두 차지하지 못하게 하며 limiter state가 무한히 커지는 것을 막는다. 플랫폼 adapter는 비용이 큰 처리 전에 이를 호출해야
한다. Management frame과 UDP datagram도 최대 크기를 가지며 malformed datagram은 내부 packet 전달 전에 폐기한다. 이 경계는 잘못된
입력이 유발할 수 있는 작업량을 제한하지만 host UDP queue 크기와 지속 부하 측정은 배포 단계의 과제다.

`PeerRegistry`는 client public key와 할당 IPv4/IPv6 주소를 고유 승인 상태로 취급한다. 이전 승인이 철회되기 전에는 identity나 주소
재사용을 거부한다. Noise responder는 이 registry를 직접 사용할 수 있으며, 알 수 없거나 불일치하거나 만료된 승인은 handshake state를 할당하기
전에 거부한다. Noise message도 동일한 public key를 인증한다.

Management peer 철회는 일치하는 관리 session을 즉시 제거한다. service는 Peer당 active session을 최대 하나로 제한하고 전체 managed
session table도 기본 peer capacity 216으로 제한한다. 각 management request 시작 시 만료된 승인을 정리해 주소를 반환하고 연결된
session을 닫는다.

UDP loss와 재정렬은 암호화 경계를 약화하지 않는다. generation별 Replay Window가 중복·오래된 sequence를 거부하고, window 안에서 인증된
packet은 순서가 바뀌어 도착해도 처리할 수 있다. Core 재시작은 session key, counter, replay state를 복원하지 않으며 Peer는 새 인증
handshake를 완료해야 한다.

Unix management socket은 로컬 전용 제어 경계다. 배포 service account가 socket을 소유하고 파일 mode는 `0600`이며 Linux
client는 `SO_PEERCRED`가 socket owner와 같은 UID를 보고할 때만 허용한다. service account 생성과 host 권한 변경은 배포 책임이다.

자동화된 보안 증거는 성공·실패 Noise handshake, lifecycle 전이, replay-window 거부, malformed packet 처리, session 격리를
다룬다. Fuzzing campaign, DNS/IPv6 leak test, Kill Switch test, 장애 주입 복구, 부하 상태 resource exhaustion, 독립
검토는 여전히 release gate다.

## 알려진 공백

Automatic Noise IK handshake와 data-plane rekey 연동, namespace 연동, DNS/IPv6 leak test, 배포
service-account 강화, 독립 검토는 배포 전에 필요하다. 호출자 권한과 admission rate limiting은 각 로컬 management 경계에 구현되어 있지만
배포 환경 수준의 검증이 추가로 필요하다.
