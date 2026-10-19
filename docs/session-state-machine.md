# Session state machine

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

The encrypted tunnel exposes a consuming close operation. It closes the
device and UDP transport before the tunnel is dropped, which also discards
its session ciphers, sequence counter, and byte counter.

The encrypted data path exposes a rekey boundary for authenticated
handshake results. A replacement must use a strictly newer key generation and
updates both directional ciphers together. The old generation's replay
window, sequence counter, byte counter, and age budget are discarded, so
packets from the previous generation are rejected after the switch.
