# GSM Tunnel architecture

GSM Tunnel separates the control plane from the packet data plane.

```text
Go Controller ── Unix Domain Socket ── Rust tunnel-core
                                      ├─ TunnelDevice / Linux TUN
                                      ├─ SessionCipher / replay window
                                      └─ UdpTransport
```

The Rust core owns packet validation, encryption, replay protection, device
I/O, UDP transport, session state, and management-frame decoding. The Go
controller owns process lifecycle through CoreController, management requests,
bounded restart policy, and operational integration. User IP packets never
pass through Go IPC.

The current implementation is a research/development core. A Noise handshake,
VPN-server integration, routing/NAT setup, and production authorization
service are intentionally not claimed by this repository yet.

## Data path

Outbound data is read from a `TunnelDevice`, authenticated and encrypted with
ChaCha20-Poly1305, encoded with the 24-byte tunnel header, and sent over UDP.
Inbound data is decoded, authenticated, replay-checked, decrypted, and only
then written to the device. Authenticated Keepalive packets are consumed
without writing to the device.

## Lifecycle

`SessionMachine` bounds reconnect attempts and applies 1–60 second exponential
backoff. Authentication failure and permission revocation enter the closing
path and do not retry automatically. CoreController exposes the child
STARTING/RUNNING/STOPPING/STOPPED/UNHEALTHY state and stops retrying after the
configured restart limit.

Release evidence and the boundary between local verification and privileged
environment checks are tracked in
[`release-verification-matrix.md`](./release-verification-matrix.md).
