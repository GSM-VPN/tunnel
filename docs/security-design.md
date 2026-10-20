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

Changing a client's long-term public key is an approval replacement, not an
in-place mutation. `PeerRegistry::replace` removes the old approval only when
the new authorization passes all validation checks; invalid, expired, or
conflicting replacements restore the old approval unchanged. A successful
replacement immediately rejects the old public key.

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

## Interoperability verification

The AEAD primitive is regression-tested against the ChaCha20-Poly1305 example
from [RFC 8439 Section 2.8.2](https://datatracker.ietf.org/doc/html/rfc8439#section-2.8.2).
The test fixes the key, 96-bit nonce, AAD, plaintext, ciphertext, and tag, and
checks both encryption and decryption. This validates the library primitive
against an external known vector; it is not an independent security review.

`SessionCipher` adds the project-specific boundary around that primitive. Its
nonce input is derived from session ID, key generation, direction, and packet
sequence, while the encoded tunnel header is authenticated as AAD. Regression
tests assert that changing session, direction, or generation changes the
ciphertext and that changing an authenticated header field is rejected.
These tests do not replace replay, key-lifecycle, network-namespace, or
independent review requirements.

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
