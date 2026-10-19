# Session state machine

`SessionMachine` uses these states:

```text
DISCONNECTED → CONNECTING → HANDSHAKING → ESTABLISHED
       ↑             ↓             ↓             ↓
       └──── RECONNECTING ← failure ─────── REKEYING
                                      ↓
                                CLOSING → CLOSED
```

Defaults are a five-second handshake timeout, five handshake attempts,
25-second keepalive threshold, 120-second idle timeout, and reconnect backoff
from one to 60 seconds with ten reconnect attempts.

The session timer maps an established connection's idle duration to one of
three actions: no work before 25 seconds, an authenticated `Keepalive` packet
from 25 seconds until the 120-second idle limit, or bounded reconnection at
the idle limit. A successful keepalive does not change the established state;
an explicit handshake timeout follows the same bounded reconnect path as
other handshake failures.

Authentication failure, permission revocation, and server shutdown enter
`CLOSING`; they do not enter an unbounded retry loop. Explicit close is valid
from active states. Successful handshakes reset reconnect attempts.
