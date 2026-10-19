# Security design

The tunnel is research/development software until independent security review
and real network validation are complete. The design separates service
authentication, peer authorization, handshake authentication, and data-plane
encryption.

## Identity and authorization

`SERVER_PRIVATE_KEY` is loaded only by Rust Core's `ServerIdentity` boundary;
its public key is derived deterministically and private material is redacted
from debug output. Approved peers contain a public key, assigned addresses,
user identifier, and expiry. The Noise responder checks the bounded approval
registry before allocating handshake state and authenticates the same key in
the Noise message exchange.

The Gateway service secret is not a data-plane key and is not sent through
Core IPC. Peer revocation and expiry close managed sessions. Approval and
session registries have bounded capacity and reject duplicate identities and
addresses.

## Data protection

Noise IK provides the handshake boundary. Session data uses separate
directional ChaCha20-Poly1305 ciphers, per-session key generations, a
2,048-packet replay window, and checked sequence arithmetic. Failed
authentication does not advance replay state. A key generation rotates at one
hour, one GiB, or the sequence boundary, whichever comes first; old-generation
packets are rejected after the switch.

Session keys and the server private key use `zeroize`-backed storage. The
encrypted tunnel has a consuming close operation that closes its device and
UDP transport before the cipher and counters are dropped.

## Operational boundary

Management uses a bounded binary protocol over a Unix Domain Socket. Frames,
request IDs, versions, operation codes, payload lengths, response statuses,
and caller permissions are validated before dispatch. Status and metrics omit
keys, plaintext packets, and DNS query contents. The socket is mode `0600` and
Linux peer credentials are checked; deployment still must assign a dedicated
service account.

Network namespaces, real DNS/NAT, Windows/macOS adapters, external leak tests,
performance measurements, and independent security review remain required
before production deployment.
