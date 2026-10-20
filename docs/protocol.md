# GSM Tunnel 프로토콜

프로토콜 식별자는 `gsm-tunnel`, 버전은 `1.0.0`이며 모든 정수는 네트워크 바이트 순서(big endian)를 사용한다. 고정 터널 헤더의 크기는 24바이트다.

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

초기 외부 패킷 한도는 1,400바이트다. 16바이트 ChaCha20-Poly1305 태그를 고려하면 평문 payload의 최대 크기는 1,360바이트다.

Transport Data와 Keepalive는 동일한 AEAD 경계를 사용한다. 헤더는 추가 인증 데이터이고 payload는 암호화되며 태그는 payload 끝에 있다.
Nonce는 세션, 키 세대, 방향, sequence number로부터 파생한다. 이 프로토콜은 아직 검토가 완료된 Noise 핸드셰이크 구현을 대체하지 않는다.

알 수 없는 버전·패킷 타입, 잘못된 session ID, 0이 아닌 reserved 필드, 크기 초과 패킷, 길이 불일치는 거부한다.

인증된 데이터 경로는 암호화 전과 복호화 후, 터널 장치에 쓰기 전에 내부 패킷을 검증한다. 검증기는 IPv4/IPv6 전체 길이 일치, IPv4 헤더 checksum, 암호화
payload MTU 한도, dual-stack 비활성 시 IPv6 거부를 적용한다. 유효하지 않은 내부 패킷은 sequence number를 할당하거나 평문을 장치에 쓰기 전에
폐기한다.
