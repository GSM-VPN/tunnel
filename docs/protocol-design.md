# Protocol design

This document records the implemented `gsm-tunnel` wire contract. It is a
fixed-version data-plane protocol; version negotiation is intentionally outside
the initial scope.

## Packet format

All integers use network byte order (big endian). The fixed header is 24 bytes:

| Offset | Size | Field |
|---:|---:|---|
| 0 | 1 | version major |
| 1 | 1 | version minor |
| 2 | 1 | version patch |
| 3 | 1 | packet type |
| 4 | 2 | flags |
| 6 | 4 | session ID |
| 10 | 8 | sequence number |
| 18 | 2 | key generation |
| 20 | 2 | payload length |
| 22 | 2 | reserved, zero |

The protocol identifier is `gsm-tunnel`, version `1.0.0`, and the encoded
packet limit is 1,400 bytes. The supported packet types are Handshake
Initiation, Handshake Response, Transport Data, Keepalive, Session Termination,
Protocol Error, and Rekey.

Transport Data and Keepalive use the authenticated data path. The header is
AEAD additional authenticated data; the payload is encrypted and the
ChaCha20-Poly1305 tag is at the end. Nonces are derived from session ID, key
generation, direction, and sequence number. The maximum encrypted plaintext is
the packet limit minus the header and tag.

Unknown versions and packet types, zero session IDs, non-zero reserved fields,
oversized frames, and declared-length mismatches are rejected. There is no
downgrade or version negotiation path in the initial implementation: a peer
must use the exact supported version.

Inner IPv4/IPv6 packets are validated before encryption and after decryption.
The validator checks total length, IPv4 header checksum, address family policy,
and the encrypted payload MTU budget.
