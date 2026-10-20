# GSM Tunnel 아키텍처

GSM Tunnel은 제어 영역과 패킷 데이터 영역을 분리한다.

```text
Go Controller ── Unix Domain Socket ── Rust tunnel-core
                                      ├─ TunnelDevice / Linux TUN
                                      ├─ SessionCipher / replay window
                                      └─ UdpTransport
```

Rust Core는 패킷 검증, 암호화, Replay 방어, 장치 I/O, UDP 전송, 세션
상태, 관리 프레임 디코딩을 담당한다. Go Controller는 CoreController를 통한
프로세스 생명주기, 관리 요청, 제한된 재시작 정책, 운영 연동을 담당한다.
사용자 IP 패킷은 Go IPC를 통과하지 않는다.

현재 구현은 연구·개발용 Core다. Noise 핸드셰이크, VPN Server 연동,
라우팅/NAT 설정, 운영 환경의 권한 부여 서비스는 아직 이 저장소가
완료했다고 주장하지 않는다.

## 데이터 경로

송신 데이터는 `TunnelDevice`에서 읽고 ChaCha20-Poly1305로 인증·암호화한
뒤 24바이트 터널 헤더와 함께 인코딩해 UDP로 보낸다. 수신 데이터는
디코딩·인증·Replay 검사를 거쳐 복호화한 뒤에만 장치에 쓴다. 인증된
Keepalive 패킷은 장치에 쓰지 않고 소비한다.

## 생명주기

`SessionMachine`은 재연결 횟수를 제한하고 1~60초의 지수 백오프를 적용한다.
인증 실패와 권한 철회는 종료 경로로 들어가며 자동 재시도하지 않는다.
CoreController는 child process의 STARTING/RUNNING/STOPPING/STOPPED/UNHEALTHY
상태를 노출하고, 설정된 재시작 한도에 도달하면 재시도를 중단한다.

배포 증거와 로컬 검증·권한이 필요한 환경 검증의 경계는
[`release-verification-matrix.md`](./release-verification-matrix.md)에 기록한다.
