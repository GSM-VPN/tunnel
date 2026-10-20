#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

#[cfg(target_os = "linux")]
use std::{
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::Path,
    thread,
    time::Duration,
};

#[cfg(target_os = "linux")]
use tunnel_core::{
    DeviceError, LinuxTunDevice, PlainTunnel, SessionId, TransportError, TunnelDevice, TunnelError,
    UdpTransport,
};

#[cfg(target_os = "linux")]
fn main() -> Result<(), String> {
    let client_device = LinuxTunDevice::create(Some("gsmclient0"), 1_500)
        .map_err(|error| format!("client TUN creation failed: {error}"))?;
    client_device
        .set_nonblocking(true)
        .map_err(|error| format!("client TUN configuration failed: {error}"))?;
    let server_device = LinuxTunDevice::create(Some("gsmserver0"), 1_500)
        .map_err(|error| format!("server TUN creation failed: {error}"))?;
    server_device
        .set_nonblocking(true)
        .map_err(|error| format!("server TUN configuration failed: {error}"))?;

    let client_transport = UdpTransport::bind(loopback(41_000), 1_500)
        .map_err(|error| format!("client UDP bind failed: {error:?}"))?;
    let server_transport = UdpTransport::bind(loopback(41_001), 1_500)
        .map_err(|error| format!("server UDP bind failed: {error:?}"))?;
    let mut client_transport = client_transport;
    let mut server_transport = server_transport;
    client_transport.set_remote(
        server_transport
            .local_addr()
            .ok_or("server UDP address missing")?,
    );
    server_transport.set_remote(
        client_transport
            .local_addr()
            .ok_or("client UDP address missing")?,
    );
    client_transport
        .set_read_timeout(Some(Duration::from_millis(1)))
        .map_err(|error| format!("client UDP timeout failed: {error:?}"))?;
    server_transport
        .set_read_timeout(Some(Duration::from_millis(1)))
        .map_err(|error| format!("server UDP timeout failed: {error:?}"))?;

    let session =
        SessionId::new(41).map_err(|error| format!("session creation failed: {error:?}"))?;
    let mut client = PlainTunnel::new(client_device, client_transport, session);
    let mut server = PlainTunnel::new(server_device, server_transport, session);
    println!("ready client=gsmclient0 server=gsmserver0");

    let stop_file = std::env::var_os("GSM_TUN_STOP_FILE").ok_or("GSM_TUN_STOP_FILE is required")?;
    let mut sent = 0;
    let mut received = 0;
    for _ in 0..20_000 {
        sent += usize::from(pump_send(&mut client)?);
        sent += usize::from(pump_send(&mut server)?);
        received += usize::from(pump_receive(&mut client)?);
        received += usize::from(pump_receive(&mut server)?);
        if Path::new(&stop_file).exists() {
            break;
        }
        thread::sleep(Duration::from_millis(1));
    }
    drop(client);
    drop(server);
    println!("closed sent={sent} received={received}");
    Ok(())
}

#[cfg(target_os = "linux")]
fn loopback(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
}

#[cfg(target_os = "linux")]
fn pump_send<D: TunnelDevice>(tunnel: &mut PlainTunnel<D>) -> Result<bool, String> {
    match tunnel.send_next() {
        Ok(_) => Ok(true),
        Err(error) if is_transient(&error) => Ok(false),
        Err(error) => Err(format!("tunnel send failed: {error:?}")),
    }
}

#[cfg(target_os = "linux")]
fn pump_receive<D: TunnelDevice>(tunnel: &mut PlainTunnel<D>) -> Result<bool, String> {
    match tunnel.receive_next() {
        Ok(_) => Ok(true),
        Err(error) if is_transient(&error) => Ok(false),
        Err(error) => Err(format!("tunnel receive failed: {error:?}")),
    }
}

#[cfg(target_os = "linux")]
fn is_transient(error: &TunnelError) -> bool {
    matches!(
        error,
        TunnelError::Device(DeviceError::Io(io::ErrorKind::WouldBlock))
            | TunnelError::Transport(TransportError::Io(
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut,
            ))
    )
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("linux-tun-pair requires Linux");
}
