# Security policy

Please do not use this repository's experimental tunnel as a production VPN.
The protocol and deployment model require independent security review.

For a suspected vulnerability, avoid public issue details until maintainers
have had a chance to assess impact. Include the affected commit, reproduction
steps, and whether keys or user traffic could be exposed. Never include real
secrets, private keys, or captured user payloads.

The repository currently validates packet lengths, AEAD authentication, replay
windows, session transitions, IPC framing, and bounded process retries. These
tests do not constitute a security audit.
