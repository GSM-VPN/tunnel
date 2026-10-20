use std::hint::black_box;
use std::time::Instant;

use tunnel_core::{
    KeyGeneration, PacketType, ProtocolVersion, SequenceNumber, SessionCipher, SessionId,
    TunnelHeader,
};

const ITERATIONS: usize = 100_000;
const PAYLOAD_SIZES: &[usize] = &[64, 512, 1_024];

fn main() {
    for &payload_size in PAYLOAD_SIZES {
        measure_round_trip(payload_size);
    }
}

fn measure_round_trip(payload_size: usize) {
    let session_id = SessionId::new(42).expect("non-zero session ID");
    let sender = SessionCipher::new([7; 32], session_id, KeyGeneration(0), 0);
    let mut receiver = SessionCipher::new([7; 32], session_id, KeyGeneration(0), 0);
    let payload = vec![0xabu8; payload_size];
    let started = Instant::now();
    let mut encrypted_bytes = 0usize;

    for sequence in 1..=ITERATIONS as u64 {
        let packet = sender
            .seal(
                TunnelHeader {
                    version: ProtocolVersion::new(1, 0, 0),
                    packet_type: PacketType::TransportData,
                    flags: 0,
                    session_id,
                    sequence_number: SequenceNumber(sequence),
                    key_generation: KeyGeneration(0),
                },
                black_box(&payload),
            )
            .expect("payload fits in a tunnel packet");
        encrypted_bytes += packet.payload.len();
        black_box(receiver.open(&packet).expect("ciphertext authenticates"));
    }

    let elapsed = started.elapsed();
    println!(
        "crypto_roundtrip payload_bytes={payload_size} iterations={ITERATIONS} \
         encrypted_bytes={encrypted_bytes} elapsed_ns={}",
        elapsed.as_nanos()
    );
}
