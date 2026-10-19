use tunnel_core::{
    KeyGeneration, PacketType, ProtocolVersion, SequenceNumber, SessionId, TunnelHeader,
    TunnelPacket,
};

#[test]
fn public_protocol_api_round_trips_a_transport_packet() {
    let header = TunnelHeader {
        version: ProtocolVersion::new(1, 0, 0),
        packet_type: PacketType::TransportData,
        flags: 0,
        session_id: SessionId::new(42).expect("session ID is non-zero"),
        sequence_number: SequenceNumber(7),
        key_generation: KeyGeneration(3),
    };
    let packet = TunnelPacket::new(header, b"integration payload".to_vec())
        .expect("packet fits the protocol budget");

    let encoded = packet.encode().expect("packet encodes");
    let decoded = TunnelPacket::decode(&encoded).expect("packet decodes");

    assert_eq!(decoded, packet);
}
