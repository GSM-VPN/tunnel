# 성능 측정 계획

`512MB` 목표는 처리량 목표이며 패킷 크기 제한이 아니다. 실제 측정값이 확보되기 전에는 처리량을 주장하지 않는다. 모든 결과에는 commit, OS/kernel, CPU,
메모리, MTU, 패킷 크기 분포, cipher mode, 세션 수, loss/latency 조건을 함께 기록한다.

측정 항목:

- 암호화된 업로드·다운로드 처리량
- p50/p95/p99 패킷 지연과 CPU 사용량
- 패킷 손실·재정렬·복구 시간
- 핸드셰이크·재연결 비율
- 목표 동시 세션 216개에서의 공정성

결정론적 정확성은 기존 단위 테스트로 검증한 뒤, WireGuard와 비교하기 전에 Linux network namespace와 benchmark job을 추가한다. 아래 Rust
benchmark target은 재사용 가능한 코어 경로 신호를 제공하지만 end-to-end 네트워크 측정을 대체하지 않는다.

## 재현 가능한 코어 경로 benchmark

저장소 루트에서 모든 target을 실행한다.

```bash
cargo bench --package tunnel-core --benches
```

target은 고정 입력을 사용하고 기계가 읽을 수 있는 key/value 필드를 출력한다.

| Target | 범위 | 고정 작업량 |
| --- | --- | --- |
| `codec` | encode/decode 왕복 | 512바이트 payload 패킷 100,000개 |
| `crypto` | ChaCha20-Poly1305 seal/open 왕복 | 64·512·1,024바이트 payload 각 100,000개 |
| `session` | 세션 registry와 공정 byte limiter | 216개 세션, 10,000회 반복 |

각 출력에는 경과 나노초가 포함된다. crypto target은 암호화 바이트 수를, session target은 허용된 operation 수를 출력한다. 이는 Rust Core의
회귀 신호이며 VPN 처리량·초당 패킷 수용량·보안 증거로 제시해서는 안 된다.

## 결과 기록 양식

실행 비교 전 command, commit, 호스트와 네트워크 조건을 결과 기록에 복사한다.

```text
date_utc:
commit:
os_kernel:
cpu_memory:
rustc_cargo:
target_profile: bench
server:
client:
mtu:
bandwidth:
concurrent_sessions:
traffic_pattern:
repetitions:
command: cargo bench --package tunnel-core --benches
output:
interpretation:
```

코어 benchmark는 어느 호스트에서나 실행할 수 있지만, 향후 end-to-end 결과에는 server/client/MTU/bandwidth 필드가 필요하다. 기본값을
채우거나 codec·crypto·메모리 내 세션 결과만으로 네트워크 성능을 추론하지 않는다.

현재 호스트에서 실행한 Rust Core 기준선은 [`performance-results.md`](./performance-results.md)에 기록한다.
