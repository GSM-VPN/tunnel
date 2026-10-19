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

`ServerIdentity` loads `SERVER_PRIVATE_KEY` as exactly 32 bytes of hex inside
Rust Core and derives the X25519 public key deterministically. Its debug output
redacts the private key, and the Noise responder can consume the key only
through this identity boundary. The Go Controller must keep
`GATEWAY_SHARED_SECRET` in its own service-authentication boundary and never
include it in Core IPC payloads.
The Core validates `SERVER_PRIVATE_KEY` before binding its management socket;
a missing or malformed key prevents startup.

`PeerRateLimiter` applies separate bounded fixed-window limits for handshake
and packet admission, with a maximum number of tracked peer IDs. This keeps a
single peer from consuming all admission work and prevents unbounded limiter
state growth; platform adapters must invoke it before expensive processing.

## Known gaps

Noise IK handshake integration with the data-plane rekey flow, long-term
identity verification, caller authorization, rate limiting, namespace
integration, DNS/IPv6 leak testing, and independent review remain required
before deployment.
