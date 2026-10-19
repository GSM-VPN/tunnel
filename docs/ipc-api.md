# Go–Rust IPC API

The initial transport is a Unix Domain Socket. Each message is a four-byte
big-endian frame length followed by a big-endian binary message. The maximum
frame is 1 MiB.

## Request

```text
u16 version | u64 request_id | u16 operation | u32 payload_length | payload
```

## Response

```text
u16 version | u64 request_id | u16 status | u16 error_code |
u32 payload_length | payload
```

Operation codes 1–12 are stable in `internal/protocol` and Rust
`management.rs`: initialize, start, stop, register/remove peer, create/terminate
session, get/list session, statistics, configuration, and health.

The controller validates the response version and request ID before returning
it to callers. Frames are bounded and malformed lengths are rejected. Data
packets never use this channel.

The Rust Core provides a Unix-only `UnixManagementServer` that accepts one
request per connection and dispatches lifecycle, session, health, statistics,
configuration, peer registration, and peer removal operations. A malformed
frame closes only that connection; the server does not pass its payload to the
data plane. Successful responses use status `200`; malformed payloads use
`400`, missing peers or sessions use `404`, duplicate or capacity-limited peer
registrations use `409`, and an unavailable lifecycle state uses `503`.

`GetHealth` returns `ready` or `running` with status `200`, and
`uninitialized` or `stopped` with status `503`.

`CreateSession`, `GetSession`, and `TerminateSession` use a 12-byte payload:
`session_id(u32)` followed by `peer_id(u64)`, all big-endian. Session creation
requires a running Core and an unexpired approved peer. `ListSessions` returns
one 13-byte record per session, adding a one-byte lifecycle state after the
same identifiers. `Stop` clears all sessions.

`UpdateConfiguration` uses a 10-byte payload containing the fixed IPv4 `/16`
and IPv6 `/64` prefixes, UDP port, MTU, dual-stack flag, and kill-switch flag.
Configuration changes are accepted only while the Core is not running.

The Rust server applies mode `0600` to the Unix socket and bounds each
connection's read and write operations to five seconds. Socket ownership,
caller credentials, and operation-specific authorization must still be
enforced by the eventual daemon wrapper before production use.
