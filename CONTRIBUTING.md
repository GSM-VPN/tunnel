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

## Documentation language

Korean is the project's primary language. Write document titles and
descriptions in Korean, while keeping code identifiers, commands, protocol
field names, and external standard names in their original form for
compatibility. See [`docs/language-policy.md`](docs/language-policy.md) for the
full policy.
