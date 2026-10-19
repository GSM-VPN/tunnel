# Security boundary

This project is research/development software and must not be deployed as a
general-purpose VPN before independent security review.

## Current protections

- ChaCha20-Poly1305 authenticates encrypted payloads and headers.
- Sender and receiver cipher state are separate.
- A 2,048-packet replay window rejects duplicates and stale sequences.
- Failed authentication does not consume a replay-window slot.
- Payloads are delivered to a device only after successful authentication.
- The encrypted tunnel stops before the configured age, byte, or sequence
  boundary so a key generation is never continued past its rotation limit.
- Sequence counters use checked arithmetic; overflow is a terminal error rather
  than a nonce-reuse-prone saturation.
- Management messages contain opaque payloads and no key fields.
- IPC uses a local Unix Domain Socket rather than a network listener.

## Secrets

`GATEWAY_SHARED_SECRET` is a control-plane credential and must not be used as
a tunnel data key. `SERVER_PRIVATE_KEY` belongs at the Rust identity boundary;
neither value belongs in logs, metrics, or management payloads.

## Known gaps

Noise IK handshake integration with the data-plane rekey flow, long-term
identity verification, caller authorization, rate limiting, namespace
integration, DNS/IPv6 leak testing, and independent review remain required
before deployment.
