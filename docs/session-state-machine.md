# 세션 상태 머신

`SessionMachine` uses these states:

```text
DISCONNECTED → CONNECTING → HANDSHAKING → ESTABLISHED
       ↑             ↓             ↓             ↓
       └──── RECONNECTING ← failure ─────── REKEYING
                                      ↓
                                CLOSING → CLOSED
```

Defaults are a five-second handshake timeout, five bounded handshake attempts,
25-second keepalive threshold, 120-second idle timeout, and reconnect backoff
from one to 60 seconds with ten reconnect attempts.

The session timer maps an established connection's idle duration to one of
three actions: no work before 25 seconds, an authenticated `Keepalive` packet
from 25 seconds until the 120-second idle limit, or bounded reconnection at
the idle limit. A successful keepalive does not change the established state;
an explicit handshake timeout follows the same bounded reconnect path as
other handshake failures.

Authentication failure, permission revocation, server shutdown, and an
explicit close enter `CLOSING` from every non-terminal state, including a
session that is still reconnecting. A failed rekey also enters `CLOSING`
instead of reusing the previous data-key generation. None of these paths
enter an unbounded retry loop. Successful handshakes reset both handshake and
reconnect attempts; reaching the handshake limit enters `CLOSING`.

The session tests assert that `RetryRequested` is invalid after authentication
failure, permission revocation, rekey failure, and key purge. Key purge is a
separate management operation: it removes the peer approval, closes every
session owned by that peer, and does not restore the peer during a Core
restart. A new client key requires a new explicit approval.

The management `TerminateSession` operation is a connection-level close: it
removes only the selected session and leaves the peer's long-term approval in
the authorization registry. The same authorized peer can therefore create a
new session with a new session ID. `RemovePeer` is a separate revocation
operation; it removes the approval and all sessions belonging to that peer.

The encrypted tunnel exposes a consuming close operation. It closes the
device and UDP transport before the tunnel is dropped, which also discards
its session ciphers, sequence counter, and byte counter.

The encrypted data path exposes a rekey boundary for authenticated
handshake results. A replacement must use a strictly newer key generation and
updates both directional ciphers together. The old generation's replay
window, sequence counter, byte counter, and age budget are discarded, so
packets from the previous generation are rejected after the switch.
