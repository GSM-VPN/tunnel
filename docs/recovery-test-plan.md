# 장애 복구 통합 테스트 계획

이 문서는 권한 있는 Linux 호스트에서 수행할 외부 통합 검증의 실행 조건과
증거 형식을 정의한다. macOS 또는 일반 개발 환경에서 Rust 단위 테스트를
통과한 것만으로 아래 항목을 완료 처리하지 않는다.

## 사전 조건

- Linux kernel with `ip netns`, veth, and `/dev/net/tun` support
- root or equivalent `CAP_NET_ADMIN` and `CAP_NET_RAW` privileges
- isolated test network with no production routes or credentials
- the same commit built for both client and server processes
- a cleanup trap that removes namespaces, veth pairs, routes, and firewall rules

The test runner must print the kernel, `ip` version, commit, process command
lines, namespace topology, MTU, loss/delay/reorder settings, and cleanup
result. It must fail if cleanup cannot prove that it removed the resources it
created.

## Scenario matrix

| Scenario | Injection | Expected result | Evidence |
| --- | --- | --- | --- |
| Server restart | stop and start the server process | client enters reconnecting, performs a fresh handshake, and resumes with a new session generation | transition log, handshake count, key generation |
| Client termination | terminate client process | server closes only that session and keeps other sessions established | session snapshots before/after |
| UDP loss | deterministic netem loss | bounded retry/backoff, no stale packet delivery | netem configuration, reconnect metrics, packet counters |
| Delay/reorder | deterministic netem delay and duplicate/reorder | authenticated in-window packets may arrive reordered; replayed packets are rejected | sequence outcomes and replay counters |
| Interface change | replace client endpoint/interface | endpoint is rebound only after authenticated validation | route snapshot, endpoint table, handshake log |
| DNS outage | block test resolver | DNS failure is bounded and route cleanup still runs | resolver commands, error class, cleanup output |

## Run order

1. Create the client, simulated network, server, and simulated-internet
   namespaces and record their addresses.
2. Apply the endpoint exception route before the full-tunnel route.
3. Start the server and client with test-only identities and capture the
   initial session and route snapshots.
4. Execute one failure injection at a time; do not combine failures until the
   isolated scenario passes.
5. Assert the expected state transitions, bounded retry count, absence of old
   key reuse, and packet delivery boundary.
6. Stop all processes, restore snapshots, remove firewall rules, delete veths
   and namespaces, and verify that no test resource remains.

## Result record

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

`blocked` is the correct result when the host lacks the required privileges or
network features. It must not be converted into a passing network-integration
or recovery checkbox.
