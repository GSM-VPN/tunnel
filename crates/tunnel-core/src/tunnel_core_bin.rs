//! Rust Tunnel Core process entrypoint.

#[cfg(unix)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _server_identity = tunnel_core::ServerIdentity::from_env().map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid SERVER_PRIVATE_KEY: {error:?}"),
        )
    })?;
    let socket_path = std::env::var("TUNNEL_CORE_IPC_SOCKET")
        .unwrap_or_else(|_| "/tmp/gsm-tunnel-core.sock".to_owned());
    let max_peers = std::env::var("TUNNEL_CORE_MAX_PEERS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(216);
    let service = tunnel_core::ManagementService::new(max_peers, tunnel_core::Metrics::default());
    let mut server = tunnel_core::UnixManagementServer::bind(socket_path, service)?;
    loop {
        server.serve_once()?;
    }
}

#[cfg(not(unix))]
fn main() {
    eprintln!("tunnel-core currently requires a Unix Domain Socket platform");
    std::process::exit(1);
}
