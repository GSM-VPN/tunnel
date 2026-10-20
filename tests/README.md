# Integration tests

Cross-package and cross-process tests belong here. Keep deterministic tests
that use in-memory devices or loopback sockets separate from environment-only
tests such as Linux namespaces and real DNS/NAT validation.

The recovery scenarios and evidence format are defined in
[`docs/recovery-test-plan.md`](../docs/recovery-test-plan.md). Until a
privileged Linux runner executes the full plan, namespace integration, DNS/NAT,
and failure-injection checkboxes remain open.

The focused Linux TUN lifecycle smoke test is available at
`scripts/test-linux-tun.sh`. It creates an isolated network namespace, sends a
kernel-generated packet through `gsmtest0`, verifies device read/write, and
checks that closing the helper removes the non-persistent interface.
