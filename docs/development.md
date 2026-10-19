# 개발 환경

## 요구사항

- Go 1.24 이상
- Rust stable toolchain
- Cargo
- Linux 개발 환경(네트워크 기능 검증 시)

## 저장소 구조

```text
.
├── internal/
│   ├── controller/       # Go 제어 계층
│   └── protocol/         # Go 프로토콜 타입 계층
├── crates/
│   └── tunnel-core/      # Rust 데이터 플레인 기반
├── docs/
├── Cargo.toml
└── go.mod
```

## 검증 명령

변경 후 아래 명령을 실행합니다.

```bash
go test ./...
go vet ./...
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets --all-features
```

프로토콜·암호화·네트워크 기능은 각 단계의 테스트 요구사항을 충족하기 전까지 실제 사용자 트래픽에 사용하지 않습니다.

