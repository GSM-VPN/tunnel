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
- An authenticated re-handshake can install newer directional keys through
  the encrypted tunnel rekey boundary. The generation must increase
  monotonically, and the old key, replay window, sequence counter, byte
  counter, and age budget are discarded together.
- Packets from an older key generation are rejected immediately after the
  switch; the current boundary intentionally provides no old-key grace
  window.
- The server-side packet policy can require an authenticated session's source
  to equal its approved virtual IPv4/IPv6 address; this is separate from the
  broader tunnel-range check and rejects cross-peer address claims.
- Sequence counters use checked arithmetic; overflow is a terminal error rather
  than a nonce-reuse-prone saturation.
- Management messages contain opaque payloads and no key fields.
- IPC uses a local Unix Domain Socket rather than a network listener.
- New identities are generated with `ServerIdentity::generate`, which fills
  private material from the operating system's CSPRNG. Stable deployments
  load the provisioned `SERVER_PRIVATE_KEY` instead of generating a new key at
  every restart.

## Secrets

`GATEWAY_SHARED_SECRET` is a control-plane credential and must not be used as
a tunnel data key. `SERVER_PRIVATE_KEY` belongs at the Rust identity boundary;
neither value belongs in logs, metrics, or management payloads.

`GATEWAY_SHARED_SECRET` is used only by the Go Controller's service-plane HMAC
verifier. It is not passed to Core, used for tunnel packet encryption, or used
as input to Noise static-key or server-public-key derivation.

`ServerIdentity` loads `SERVER_PRIVATE_KEY` as the canonical 32-byte standard
Base64 format used by `vpn-server` inside Rust Core and derives the X25519 public
key deterministically. The public key is exposed in the same Base64
representation for pinning. Its debug output redacts the private key, and the
Noise responder can consume the key only through this identity boundary. The Go Controller must keep
`GATEWAY_SHARED_SECRET` in its own service-authentication boundary and never
include it in Core IPC payloads.
The Core validates `SERVER_PRIVATE_KEY` before binding its management socket;
a missing or malformed key prevents startup.

The separate change and restart procedures for the Gateway service secret and
the Core server identity are documented in [`key-lifecycle.md`](key-lifecycle.md).
The service secret change restarts only the Controller authentication boundary;
the server identity change drains sessions, replaces the Core process, and
requires clients to pin and verify the new public key before reconnecting.

Session cipher keys use `zeroize`-backed storage: the previous generation is
cleared before replacement, and the active key is cleared when the cipher is
dropped. The long-term server private key and the temporary key-parsing buffer
use the same storage policy.

The default data-key rotation policy is one hour or 1 GiB transmitted in each
direction, whichever is reached first. A session stops at the boundary until
an authenticated newer generation is installed. A failed rekey transitions the
session to `CLOSING`; it does not retry indefinitely or continue using the
previous generation.

`PeerRateLimiter` applies separate bounded fixed-window limits for handshake
and packet admission, with a maximum number of tracked peer IDs. This keeps a
single peer from consuming all admission work and prevents unbounded limiter
state growth; platform adapters must invoke it before expensive processing.
Management frames and UDP datagrams also have fixed maximum sizes, and malformed
datagrams are discarded before inner-packet delivery. These boundaries cap the
work attributable to an invalid input; host UDP queue sizing and sustained-load
measurements remain deployment work.

`PeerRegistry` treats client public keys and assigned IPv4/IPv6 addresses as
unique approval state. Reusing identity material or an address is rejected
until the previous approval is revoked.
Noise responder creation can consume this registry directly: unknown,
mismatched, or expired approvals are rejected before allocating handshake
state, and the Noise message still authenticates the same public key.

Management peer revocation removes matching managed sessions immediately. The
service also permits at most one active session per peer and bounds the total
managed session table by the configured peer capacity (216 by default).
Expired approvals are purged at the start of each management request, releasing
their addresses and closing any associated sessions before the request runs.

UDP loss and reordering do not weaken the cryptographic boundary: the
per-generation Replay Window rejects duplicates and stale sequences, while
authenticated packets that arrive within the window may be processed out of
order. A Core restart never restores session keys, counters, or replay state;
the peer must complete a new authenticated handshake.

The Unix management socket is a local-only control boundary. The deployment
service account owns the socket, the file mode is restricted to `0600`, and
Linux clients are accepted only when `SO_PEERCRED` reports the same UID as the
socket owner. Service-account creation and host permission changes remain
deployment responsibilities.

Automated security evidence covers successful and failed Noise handshakes,
lifecycle transitions, replay-window rejection, malformed packet handling,
and cross-session isolation. Fuzzing campaigns, DNS/IPv6 leak tests, Kill
Switch tests, fault-injected recovery, resource-exhaustion tests under load,
and independent review remain release gates.

## Known gaps

Automatic Noise IK handshake integration with the data-plane rekey flow,
namespace integration, DNS/IPv6 leak testing, deployment service-account
hardening, and independent review remain required before deployment. Caller
authorization and admission rate limiting are implemented at their local
management boundaries, but still require deployment-level verification.
