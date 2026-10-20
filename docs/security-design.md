# 보안 설계

이 터널은 독립적인 보안 검토와 실제 네트워크 검증이 끝나기 전까지
연구·개발용 소프트웨어다. 설계는 서비스 인증, Peer 권한, 핸드셰이크
인증, data-plane 암호화를 분리한다.

## 신원과 권한

`SERVER_PRIVATE_KEY`는 Rust Core의 `ServerIdentity` 경계에서만 읽는다.
공개키는 결정론적으로 파생하며 private material은 debug 출력에서 가린다.
승인된 Peer에는 public key, 할당 주소, 사용자 식별자, 만료 시각만 담긴다.
Noise responder는 제한된 승인 registry를 확인한 뒤 핸드셰이크 상태를
할당하고, 동일한 키가 Noise 메시지 교환에서도 인증되는지 확인한다.

Gateway service secret은 data-plane key가 아니며 Core IPC로 전달하지 않는다.
Peer 철회와 만료는 관리 세션을 종료한다. 승인·세션 registry는 수용량을
제한하고 중복 identity와 주소를 거부한다.

client long-term public key 변경은 in-place mutation이 아니라 승인 교체다.
`PeerRegistry::replace`는 새 권한이 모든 검증을 통과할 때만 기존 승인을
제거한다. 유효하지 않거나 만료됐거나 충돌하는 교체는 기존 승인을 그대로
복구한다. 교체에 성공하면 이전 public key는 즉시 거부한다.

## 데이터 보호

Noise IK가 핸드셰이크 경계를 제공한다. 세션 데이터는 방향별
ChaCha20-Poly1305 cipher, 세션별 key generation, 2,048개 packet replay
window를 사용하며 검사된 sequence arithmetic를 적용한다. 인증 실패는
replay state를 전진시키지 않는다. key generation은 1시간, 1GiB 또는
sequence 경계 중 먼저 도달한 조건에서 교체한다. 교체 후 이전 세대 패킷은
거부한다.

Session key와 server private key는 `zeroize` 기반 저장소를 사용한다.
암호화 tunnel은 consuming close를 수행해 cipher와 counter를 버리기 전에
device와 UDP transport를 닫는다.

## 상호 운용성 검증

AEAD primitive은 [RFC 8439 Section 2.8.2](https://datatracker.ietf.org/doc/html/rfc8439#section-2.8.2)의
ChaCha20-Poly1305 예제를 회귀 테스트한다. key, 96-bit nonce, AAD, plaintext,
ciphertext, tag를 고정하고 암호화와 복호화를 모두 확인한다. 이는 외부
known vector와의 일치만 검증하며 독립적인 보안 검토는 아니다.

`SessionCipher`는 이 primitive 주위에 프로젝트 고유의 경계를 추가한다.
Nonce 입력은 session ID, key generation, direction, packet sequence에서
파생하고 encoded tunnel header는 AAD로 인증한다. session·direction·generation
변경 시 ciphertext가 달라지고 인증된 header 변경이 거부되는지 회귀
테스트한다. 이 테스트는 replay, key lifecycle, network namespace 또는
독립 검토를 대체하지 않는다.

## 운영 경계

관리는 Unix Domain Socket 위의 제한된 바이너리 프로토콜을 사용한다.
frame, request ID, version, operation code, payload length, response status,
호출자 권한을 dispatch 전에 검증한다. status와 metrics에는 key, 평문
packet, DNS query 원문을 넣지 않는다. socket mode는 `0600`이고 Linux peer
credential을 확인한다. 배포 시에는 별도 service account를 지정해야 한다.

Network namespace, 실제 DNS/NAT, Windows/macOS adapter, 외부 leak test,
성능 측정, 독립 보안 검토는 production 배포 전에 필요한 항목이다.
