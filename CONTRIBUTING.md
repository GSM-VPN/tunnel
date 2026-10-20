# Contributing

1. Read `SPEC.md` and `STEP.md` before changing behavior.
2. Choose a category branch such as `feature/<summary>`, `fix/<summary>`, or
   `docs/<summary>` from `develop`.
3. Open one issue per coherent work area, not per commit, and apply the matching
   label.
4. Keep commits focused and use `type: Korean summary` messages.
5. Run `gofmt`, `go test ./...`, `go vet ./...`, Rust fmt, clippy, and tests.
6. Open a PR using the repository template with `Closes #<issue>`.
7. Merge only after CI succeeds, then return to `develop` before branching
   again.

Do not put keys, plaintext packets, or sensitive user data in logs, tests,
issues, or pull requests. Keep WireGuard rollback available until this
experimental implementation has passed independent review.
## 문서 언어

프로젝트의 primary language는 한국어입니다. 문서 제목과 설명은 한국어로
작성하고, 코드 식별자·명령어·프로토콜 필드명·외부 표준명은 호환성을 위해
원문을 유지합니다. 자세한 기준은 [`docs/language-policy.md`](docs/language-policy.md)를
참조하세요.
