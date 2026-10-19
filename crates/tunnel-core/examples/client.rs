use std::{env, net::SocketAddr, net::UdpSocket, process};

use tunnel_core::{
    KeyGeneration, PROTOCOL_VERSION, PacketType, SequenceNumber, SessionId, TunnelHeader,
    TunnelPacket,
};

fn main() {
    if let Err(error) = run() {
        eprintln!("client error: {error}");
        process::exit(2);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let (server, message) = parse_args()?;
    let socket = UdpSocket::bind("127.0.0.1:0")?;
    let session_id = SessionId::new(1)?;
    let packet = TunnelPacket::new(
        TunnelHeader {
            version: PROTOCOL_VERSION,
            packet_type: PacketType::TransportData,
            flags: 0,
            session_id,
            sequence_number: SequenceNumber(0),
            key_generation: KeyGeneration(0),
        },
        message.into_bytes(),
    )?;
    let encoded = packet.encode()?;
    println!(
        "client started local={} server={server}",
        socket.local_addr()?
    );
    socket.send_to(&encoded, server)?;
    println!("client sent_bytes={}", encoded.len());
    println!("client stopped");
    Ok(())
}

fn parse_args() -> Result<(SocketAddr, String), String> {
    let mut server = None;
    let mut message = None;
    let mut args = env::args().skip(1);
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--server" => server = Some(args.next().ok_or("--server requires an address")?),
            "--message" => message = Some(args.next().ok_or("--message requires text")?),
            "--help" => return Err("usage: client --server HOST:PORT --message TEXT".into()),
            _ => return Err(format!("unknown argument: {argument}")),
        }
    }
    let server = server
        .ok_or("--server is required")?
        .parse()
        .map_err(|_| "invalid server address")?;
    Ok((server, message.ok_or("--message is required")?))
}
