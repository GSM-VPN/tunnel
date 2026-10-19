# GSM Tunnel protocol

The protocol identifier is `gsm-tunnel`, version `1.0.0`, and all integers use
network byte order (big endian). The fixed tunnel header is 24 bytes:

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

The initial external packet limit is 1,400 bytes. With the 16-byte
ChaCha20-Poly1305 tag, the maximum plaintext payload is 1,360 bytes.

Transport Data and Keepalive use the same AEAD boundary. The header is
additional authenticated data; the payload is encrypted and the tag is at the
end of the payload. Nonces are derived from session, key generation, direction,
and sequence number. The protocol is not a replacement for a reviewed Noise
handshake implementation yet.

Unknown versions, packet types, invalid session IDs, non-zero reserved fields,
oversized packets, and length mismatches are rejected.

The authenticated data path validates an inner packet before encryption and
again after decryption, before writing it to the tunnel device. The validator
requires an exact IPv4/IPv6 total length, checks IPv4 header checksums, applies
the encrypted payload MTU budget, and rejects IPv6 when dual-stack mode is
disabled. Invalid inner packets are discarded without allocating a sequence
number or writing plaintext to a device.
