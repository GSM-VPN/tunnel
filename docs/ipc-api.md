# Go–Rust IPC API

초기 전송 수단은 Unix Domain Socket이다. 각 메시지는 4바이트 big endian
frame 길이와 big endian 바이너리 메시지로 구성된다. frame 최대 크기는
1MiB다.

Go Controller와 Rust Core는 별도 프로세스다. Controller는 이 로컬 socket을
통해 제어 영역 상태만 보내며 터널 데이터 패킷은 Rust에 남는다. Core는
자기 신원 경계에서 `SERVER_PRIVATE_KEY`를 읽고 Gateway service secret은
Core IPC 필드가 아니다. TUN과 route 적용은 권한이 필요한 플랫폼 어댑터가
담당하고 data plane 프로세스는 검증된 계획을 소비한다. TCP listener나
외부에서 route 가능한 IPC endpoint는 사용하지 않는다.

## Request

```text
u16 version | u64 request_id | u16 operation | u32 payload_length | payload
```

## Response

```text
u16 version | u64 request_id | u16 status | u16 error_code |
u32 payload_length | payload
```

Operation code 1~12는 `internal/protocol`과 Rust `management.rs`에서
안정적으로 유지한다. 순서는 initialize, start, stop, register/remove
peer, create/terminate session, get/list session, statistics, configuration,
health다.

Controller는 호출자에게 반환하기 전에 response version과 request ID를
검증한다. frame은 크기 제한을 따르며 잘못된 길이는 거부한다. 데이터
패킷은 이 채널을 사용하지 않는다.

Rust Core는 Unix 전용 `UnixManagementServer`를 제공한다. 연결 하나당
request 하나를 받아 lifecycle, session, health, statistics, configuration,
peer registration/removal을 처리한다. 잘못된 frame은 해당 연결만 닫으며
payload를 data plane으로 전달하지 않는다. 성공 응답은 `200`, 잘못된
payload는 `400`, 없는 peer/session은 `404`, 중복 또는 수용량 초과 peer
registration은 `409`, 사용할 수 없는 lifecycle 상태는 `503`을 사용한다.

`GetHealth`는 `ready` 또는 `running`일 때 status `200`을, `uninitialized`
또는 `stopped`일 때 `503`을 반환한다.

`CreateSession`, `GetSession`, `TerminateSession`은 12바이트 payload를
사용한다. big endian인 `session_id(u32)` 뒤에 `peer_id(u64)`가 온다.
Session 생성에는 실행 중인 Core와 만료되지 않은 승인 peer가 필요하다.
`ListSessions`는 session 하나당 13바이트 record를 반환하며 동일한 식별자
뒤에 1바이트 lifecycle state를 붙인다. `Stop`은 모든 session을 제거한다.

`UpdateConfiguration`은 고정된 IPv4 `/16`·IPv6 `/64` prefix, UDP port,
MTU, dual-stack flag, kill-switch flag를 담은 10바이트 payload를 사용한다.
Core가 실행 중이 아닐 때만 configuration 변경을 허용한다.

`GetStatistics`는 11개의 big endian `u64` 값으로 구성된 88바이트 payload를
반환한다. 순서는 active sessions, 송·수신 bytes, 송·수신 packets,
authentication failures, replay rejections, reconnects, handshake failures,
keepalive failures, packet errors다. Go Controller는 이를
`Client.GetMetrics`를 통해 `protocol.MetricsSnapshot`으로 노출한다.

Rust server는 Unix socket에 mode `0600`을 적용하고 각 connection의 read·write
작업을 5초로 제한한다. Linux에서는 request를 디코딩하기 전에
`SO_PEERCRED`로 연결 프로세스 UID와 socket owner UID를 비교한다. 읽기 전용
server policy는 health·statistics·session read를 허용하고 engine·peer·session
변경 및 configuration에는 `403`을 반환한다. 기본 policy는 Go Controller의
로컬 변경 제어 영역을 허용한다.

라이브러리는 socket mode와 peer UID 경계를 강제하지만 전용 OS service
account를 생성하거나 전환하지는 않는다. 배포 unit이 의도한 service user가
소유하도록 설정하고 socket 경로를 외부에서 쓰기 가능한 directory 밖에 둬야
한다.

Go Controller의 `CoreDesiredState`는 승인된 peer data와 network policy만
저장한다. `CoreSynchronizer`는 Core 재시작마다 `Initialize`,
`UpdateConfiguration`, `RegisterPeer`, `Start` 순서로 상태를 복원한다.
peer ID는 결정론적 복구를 위해 오름차순으로 적용한다. 동기화 오류가 나면
Core를 running 상태로 전환하지 않는다.

`CoreController.CollectMetrics`는 별도의 로컬 IPC connection에서
`GetHealth`와 `GetStatistics`를 호출해 운영 snapshot을 구성한다. health
label과 11개 counter는 집계된 비밀 없는 값이다. Core 가용성 또는 IPC
오류는 0 값으로 조용히 바꾸지 않고 호출자에게 반환한다.
