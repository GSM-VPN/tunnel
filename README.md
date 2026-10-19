# GSM VPN Tunnel

GSM VPN Tunnel은 GSM VPN의 자체 터널링 엔진을 구현하는 저장소입니다.

프로젝트의 설계 기준은 [`SPEC.md`](./SPEC.md), 단계별 구현 계획은 [`STEP.md`](./STEP.md)에서 관리합니다.

## 기술 구성

- Go: Controller, 운영 제어, IPC, 메트릭
- Rust: Protocol Core, 암호화, UDP, TUN, 세션, 데이터 플레인
- 초기 검증 환경: Linux

## 로컬 검증

```bash
go test ./...
go vet ./...
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets --all-features
```

현재 저장소는 Phase 0 초기 workspace 기반을 제공하며, 실제 네트워크 기능은 단계별로 추가합니다.

## 보안 안내

자체 프로토콜은 독립적인 보안 검토가 완료되기 전까지 연구·개발용으로만 취급해야 합니다. 기존 WireGuard 구현은 자체 구현의 검증이 끝날 때까지 제거하지 않습니다.

