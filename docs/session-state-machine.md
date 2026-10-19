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

Authentication failure, permission revocation, and server shutdown enter
`CLOSING`; they do not enter an unbounded retry loop. Explicit close is valid
from active states. Successful handshakes reset reconnect attempts.
