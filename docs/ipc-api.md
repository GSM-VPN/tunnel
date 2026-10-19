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
request per connection and dispatches health, statistics, peer registration,
and peer removal operations. A malformed frame closes only that connection;
the server does not pass its payload to the data plane. Successful responses
use status `200`; malformed payloads use `400`, missing peers use `404`, and
duplicate or capacity-limited peer registrations use `409`.

Socket ownership, caller credentials, and operation-specific authorization
must be enforced by the eventual daemon wrapper before production use.
