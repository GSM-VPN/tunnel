use std::hint::black_box;
use std::time::Instant;

use tunnel_core::{
    KeyGeneration, PacketType, ProtocolVersion, SequenceNumber, SessionId, TunnelHeader,
    TunnelPacket,
};

const ITERATIONS: usize = 100_000;

fn main() {
    let packet = TunnelPacket::new(
        TunnelHeader {
            version: ProtocolVersion::new(1, 0, 0),
            packet_type: PacketType::TransportData,
            flags: 0,
            session_id: SessionId::new(42).expect("non-zero session ID"),
            sequence_number: SequenceNumber(1),
            key_generation: KeyGeneration(0),
        },
        vec![0xabu8; 512],
    )
    .expect("benchmark packet fits");

    let started = Instant::now();
    let mut encoded_bytes = 0usize;
    for _ in 0..ITERATIONS {
        let encoded = black_box(packet.encode().expect("packet encodes"));
        encoded_bytes += encoded.len();
        black_box(TunnelPacket::decode(&encoded).expect("packet decodes"));
    }

    let elapsed = started.elapsed();
    println!(
        "codec_roundtrip iterations={ITERATIONS} bytes={encoded_bytes} elapsed_ns={}",
        elapsed.as_nanos()
    );
}
