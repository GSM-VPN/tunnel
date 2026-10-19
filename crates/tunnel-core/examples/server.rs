use std::{
    env,
    net::{SocketAddr, UdpSocket},
    process,
    time::Duration,
};

use tunnel_core::{PacketType, TunnelPacket};

fn main() {
    if let Err(error) = run() {
        eprintln!("server error: {error}");
        process::exit(2);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let listen = parse_args()?;
    let socket = UdpSocket::bind(listen)?;
    socket.set_read_timeout(Some(Duration::from_secs(5)))?;
    println!("server started listen={}", socket.local_addr()?);
    let mut buffer = [0; 1_400];
    let (length, peer) = socket.recv_from(&mut buffer)?;
    let packet = TunnelPacket::decode(&buffer[..length])?;
    if packet.header.packet_type != PacketType::TransportData {
        return Err("example accepts TransportData only".into());
    }
    println!(
        "server received_bytes={length} peer={peer} payload_bytes={}",
        packet.payload.len()
    );
    println!("server stopped");
    Ok(())
}

fn parse_args() -> Result<SocketAddr, String> {
    let mut listen = None;
    let mut args = env::args().skip(1);
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--listen" => listen = Some(args.next().ok_or("--listen requires an address")?),
            "--help" => return Err("usage: server --listen HOST:PORT".into()),
            _ => return Err(format!("unknown argument: {argument}")),
        }
    }
    listen
        .ok_or("--listen is required")?
        .parse()
        .map_err(|_| "invalid listen address".into())
}
