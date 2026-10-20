# 세션 상태 머신

`SessionMachine`은 다음 상태를 사용한다.

```text
DISCONNECTED → CONNECTING → HANDSHAKING → ESTABLISHED
       ↑             ↓             ↓             ↓
       └──── RECONNECTING ← failure ─────── REKEYING
                                      ↓
                                CLOSING → CLOSED
```

기본값은 핸드셰이크 timeout 5초, 제한된 핸드셰이크 시도 5회, keepalive
threshold 25초, idle timeout 120초, 1~60초 reconnect backoff와 재연결
10회다.

세션 timer는 established connection의 idle 시간을 세 동작으로 매핑한다.
25초 전에는 아무 작업도 하지 않고, 25초부터 120초 idle limit까지는 인증된
`Keepalive` packet을 보내며, limit에 도달하면 제한된 재연결로 전환한다.
keepalive 성공은 established 상태를 바꾸지 않는다. 명시적인 handshake
timeout도 다른 handshake 실패와 같은 제한된 재연결 경로를 따른다.

인증 실패, 권한 철회, server shutdown, 명시적 close는 reconnecting 중인
세션을 포함해 terminal 상태가 아닌 모든 상태에서 `CLOSING`으로 들어간다.
rekey 실패도 이전 data-key generation을 재사용하지 않고 `CLOSING`으로
들어간다. 어느 경로도 제한 없는 retry loop를 사용하지 않는다. 성공한
handshake는 handshake·reconnect 시도를 모두 초기화하고, handshake 한도에
도달하면 `CLOSING`으로 전환한다.

세션 테스트는 인증 실패, 권한 철회, rekey 실패, key purge 뒤의
`RetryRequested`가 유효하지 않음을 확인한다. Key purge는 별도 관리
operation이며 Peer 승인과 해당 Peer 소유의 모든 세션을 제거한다. Core
재시작 시 Peer를 복원하지 않고 새 client key에는 새 명시적 승인이 필요하다.

관리 `TerminateSession` operation은 connection 수준 close다. 선택한 session만
제거하고 authorization registry의 장기 Peer 승인은 유지한다. 따라서 같은
승인 Peer가 새 session ID로 다시 session을 만들 수 있다. `RemovePeer`는
별도 철회 operation이며 승인과 해당 Peer의 모든 session을 제거한다.

암호화 tunnel은 consuming close operation을 노출한다. tunnel을 버리기 전에
device와 UDP transport를 닫고 session cipher, sequence counter, byte counter도
함께 폐기한다.

암호화 data path는 인증된 handshake 결과를 위한 rekey 경계를 제공한다.
교체는 반드시 더 큰 key generation을 사용해야 하며 양방향 cipher를 함께
갱신한다. 이전 generation의 replay window, sequence counter, byte counter,
시간 예산은 폐기하므로 교체 후 이전 generation packet은 거부한다.
