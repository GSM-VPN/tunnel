# 프로토콜 설계

이 문서는 구현된 `gsm-tunnel` wire 계약을 기록한다. 버전이 고정된 데이터 플레인 프로토콜이며, 초기 범위에서는 버전 협상을 사용하지 않는다.

## 패킷 형식

모든 정수는 네트워크 바이트 순서(big endian)를 사용한다. 고정 헤더는 24바이트다.

| 오프셋 | 크기 | 필드 |
|---:|---:|---|
| 0 | 1 | version major |
| 1 | 1 | version minor |
| 2 | 1 | version patch |
| 3 | 1 | packet type |
| 4 | 2 | flags |
| 6 | 4 | session ID |
| 10 | 8 | sequence number |
| 18 | 2 | key generation |
| 20 | 2 | payload length |
| 22 | 2 | reserved, zero |

프로토콜 식별자는 `gsm-tunnel`, 버전은 `1.0.0`, 인코딩된 패킷 한도는 1,400바이트다. 지원하는 패킷 타입은 Handshake Initiation,
Handshake Response, Transport Data, Keepalive, Session Termination, Protocol Error, Rekey다.

Transport Data와 Keepalive는 인증 데이터 경로를 사용한다. 헤더는 AEAD 추가 인증 데이터이고 payload는 암호화되며 ChaCha20-Poly1305
태그는 끝에 붙는다. Nonce는 session ID, key generation, direction, sequence number로부터 파생한다. 암호화된 평문의 최대 크기는
패킷 한도에서 헤더와 태그를 뺀 값이다.

알 수 없는 버전·패킷 타입, 0인 session ID, 0이 아닌 reserved 필드, 크기 초과 frame, 선언 길이 불일치는 거부한다. 초기 구현에는 downgrade나
버전 협상 경로가 없으므로 정확히 지원 버전을 사용해야 한다.

## 제어 패킷 payload

고정 헤더는 데이터·제어 패킷이 공유한다. 핸드셰이크 initiation/response는 payload에 Noise IK 메시지 하나를 정확히 담는다. session ID는 0이
아니고, key generation은 0이며 sequence number는 0에서 시작한다. 핸드셰이크의 인증은 터널 AEAD가 아니라 Noise 메시지가 담당한다. 핸드셰이크
payload도 외부 패킷 한도 안에 있어야 한다.

Keepalive는 인증된 빈 평문을 담고 일반 방향성 sequence number를 소비한다. Session Termination은 인증된 빈 평문을 담는 영구 세션 이벤트이며,
종료 이유는 사용자나 키 자료를 wire에 넣지 않고 로컬 세션 상태가 제공한다.

Protocol Error는 향후 안정적인 오류 코드 표를 위해 예약된 제한된 인증 제어 메시지다. 표가 구현되기 전에는 지원하지 않는 제어 메시지를 거부하고 영향받은 세션을
종료하며, 알 수 없는 payload를 임의로 해석하지 않는다. 버전 협상은 없으므로 `1.0.0`만 허용하고 다른 버전은 downgrade를 막는 영구 프로토콜 오류로 처리한다.

내부 IPv4/IPv6 패킷은 암호화 전과 복호화 후 검증한다. 검증기는 전체 길이, IPv4 헤더 checksum, 주소 패밀리 정책, 암호화 payload MTU 한도를
확인한다.
