# 장애 복구 통합 테스트 계획

이 문서는 권한 있는 Linux host에서 수행할 외부 통합 검증의 실행 조건과
증거 형식을 정의한다. macOS 또는 일반 개발 환경에서 Rust 단위 테스트만
통과한 것은 아래 항목의 완료가 아니다.

## 사전 조건

- `ip netns`, veth, `/dev/net/tun`을 지원하는 Linux kernel
- root 또는 동등한 `CAP_NET_ADMIN`·`CAP_NET_RAW` 권한
- production route나 credential이 없는 격리된 테스트 네트워크
- 동일 commit으로 빌드한 client/server process
- namespace, veth, route, firewall rule을 제거하는 cleanup trap

실행기는 kernel, `ip` version, commit, process command line, namespace
topology, MTU, loss/delay/reorder 설정, cleanup 결과를 출력해야 한다.
자신이 만든 자원을 모두 제거했음을 증명하지 못하면 테스트는 실패해야 한다.

## 시나리오 표

| 시나리오 | 주입 방법 | 기대 결과 | 증거 |
| --- | --- | --- | --- |
| Server restart | server process 중지 후 재시작 | client가 reconnecting으로 이동하고 새 핸드셰이크·새 세션 세대로 복구 | transition log, handshake count, key generation |
| Client 종료 | client process 종료 | server가 해당 session만 닫고 다른 session은 유지 | 전후 session snapshot |
| UDP loss | 결정론적 netem loss | 제한된 retry/backoff, stale packet 전달 없음 | netem 설정, reconnect metrics, packet counter |
| 지연·재정렬 | 결정론적 netem delay와 duplicate/reorder | 인증된 window 안의 재정렬 packet 허용, replay packet 거부 | sequence 결과와 replay counter |
| Interface 변경 | client endpoint/interface 교체 | 인증된 검증 후에만 endpoint 재바인딩 | route snapshot, endpoint table, handshake log |
| DNS 장애 | 테스트 resolver 차단 | DNS 실패를 제한하고 route cleanup 수행 | resolver 명령, 오류 분류, cleanup 출력 |

## 실행 순서

1. client, simulated network, server, simulated-internet namespace를 만들고 주소를 기록한다.
2. full-tunnel route보다 먼저 endpoint exception route를 적용한다.
3. server와 client를 테스트 전용 identity로 시작하고 최초 session·route snapshot을 수집한다.
4. 한 번에 하나의 장애만 주입한다. 개별 시나리오가 통과하기 전에는 장애를 조합하지 않는다.
5. 기대한 상태 전이, 제한된 retry count, 이전 key 재사용 없음, packet 전달 경계를 확인한다.
6. 모든 process를 중지하고 snapshot을 복구한 뒤 firewall rule, veth, namespace를 제거하고 자원이 남지 않았는지 확인한다.

## 결과 기록

```text
date_utc:
commit:
kernel:
iproute2:
topology:
mtu:
loss_delay_reorder:
scenario:
commands:
expected:
observed:
transition_log:
metrics:
cleanup:
status: pass | fail | blocked
```

필요한 권한이나 네트워크 기능이 없는 host에서는 `blocked`가 올바른
결과다. 이를 실제 network-integration 또는 recovery 체크 통과로 바꾸지
않는다.
