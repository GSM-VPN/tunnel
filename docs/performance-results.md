# Rust Core 성능 기준선

이 문서는 GSM Tunnel Rust Core의 결정론적 benchmark 기준선이다. 측정 대상은
codec, 암호화, 메모리 내 session table과 공정한 rate limiter이며, 실제 Linux
TUN·UDP·NAT·외부 네트워크를 포함한 VPN 처리량을 의미하지 않는다.

## 실행 조건

```text
date_utc: 2026-10-20T08:49:02Z
commit: 2a705a7228de90bd83de2a175e09d530e22ff3f3
os_kernel: Darwin 25.6.0 (RELEASE_ARM64_T6030)
cpu_memory: Apple Mac15,7; 12 logical CPUs; 36 GiB memory
rustc_cargo: rustc 1.99.0; cargo 1.99.0
target_profile: bench (optimized)
server: 해당 없음, 메모리 내 Core benchmark
client: 해당 없음, 메모리 내 Core benchmark
mtu: 해당 없음
bandwidth: 해당 없음
concurrent_sessions: session benchmark 216
traffic_pattern: 고정 payload와 고정된 반복 횟수
repetitions: codec·crypto 100,000회; session 10,000회
command: cargo bench --package tunnel-core --benches
```

## 원시 결과

| 대상 | 입력 및 반복 | 결과 |
| --- | --- | --- |
| codec roundtrip | 512-byte payload, 100,000회 | `bytes=53600000`, `elapsed_ns=26963666` |
| crypto roundtrip | 64-byte payload, 100,000회 | `encrypted_bytes=8000000`, `elapsed_ns=144560417` |
| crypto roundtrip | 512-byte payload, 100,000회 | `encrypted_bytes=52800000`, `elapsed_ns=394671333` |
| crypto roundtrip | 1,024-byte payload, 100,000회 | `encrypted_bytes=104000000`, `elapsed_ns=804445958` |
| session table fill/remove | 216개 session, 10,000회 | `removed_sum=234360000`, `elapsed_ns=66462125` |
| fair rate limiter | 216개 session, 1,024-byte payload, 10,000회 | `admitted=2160000`, `elapsed_ns=97318083` |

## 해석 범위

- 결과는 동일한 benchmark target의 변경 전후를 비교하기 위한 기준선이다.
- 이 측정에는 실제 server/client, Linux network namespace, TUN I/O, UDP 지연,
  패킷 손실, MTU, 라우팅, NAT, DNS가 포함되지 않는다.
- 따라서 위 수치를 VPN 처리량, 초당 패킷 처리량, 외부 인터넷 성능 또는 보안
  근거로 사용하지 않는다.
- 후속 최적화는 동일한 command와 조건으로 다시 측정하고, 정확성·보안 테스트와
  함께 비교한다.
