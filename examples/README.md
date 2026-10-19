# Examples

Runnable demonstrations belong here. Examples may depend on public library
APIs, but must not require privileged TUN devices, production credentials, or
external network access to build and run in CI.

The loopback protocol demo uses two short-lived processes:

```bash
cargo run -p tunnel-core --example server -- --listen 127.0.0.1:51820
cargo run -p tunnel-core --example client -- --server 127.0.0.1:51820 --message hello
```

It validates the fixed packet encoder/decoder and UDP transport only. It is
not encrypted and must not be used as a VPN or on an untrusted network.
