# Integration tests

Cross-package and cross-process tests belong here. Keep deterministic tests
that use in-memory devices or loopback sockets separate from environment-only
tests such as Linux namespaces and real DNS/NAT validation.

The recovery scenarios and evidence format are defined in
[`docs/recovery-test-plan.md`](../docs/recovery-test-plan.md). Until a
privileged Linux runner executes that plan, namespace, real TUN, DNS/NAT, and
failure-injection checkboxes remain open.
