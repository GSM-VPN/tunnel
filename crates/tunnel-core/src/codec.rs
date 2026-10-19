use crate::protocol::{
    HEADER_SIZE, KeyGeneration, MAX_PACKET_SIZE, MAX_PAYLOAD_SIZE, PROTOCOL_VERSION, PacketType,
    ProtocolError, ProtocolVersion, SequenceNumber, SessionId,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TunnelHeader {
    pub version: ProtocolVersion,
    pub packet_type: PacketType,
    pub flags: u16,
    pub session_id: SessionId,
    pub sequence_number: SequenceNumber,
    pub key_generation: KeyGeneration,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TunnelPacket {
    pub header: TunnelHeader,
    pub payload: Vec<u8>,
}

impl TunnelPacket {
    /// Creates a packet after enforcing the maximum encoded packet size.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::PacketTooLarge`] when the payload cannot fit
    /// in the initial tunnel packet size.
    pub fn new(header: TunnelHeader, payload: Vec<u8>) -> Result<Self, ProtocolError> {
        if payload.len() > MAX_PAYLOAD_SIZE {
            return Err(ProtocolError::PacketTooLarge {
                actual: HEADER_SIZE + payload.len(),
                maximum: MAX_PACKET_SIZE,
            });
        }
        Ok(Self { header, payload })
    }

    /// Encodes the packet using the fixed big-endian wire format.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::PacketTooLarge`] when the packet exceeds the
    /// configured maximum size.
    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        let packet = Self::new(self.header, self.payload.clone())?;
        let mut bytes = Vec::with_capacity(HEADER_SIZE + packet.payload.len());
        bytes.extend_from_slice(&[
            packet.header.version.major,
            packet.header.version.minor,
            packet.header.version.patch,
            packet.header.packet_type as u8,
        ]);
        bytes.extend_from_slice(&packet.header.flags.to_be_bytes());
        bytes.extend_from_slice(&packet.header.session_id.0.to_be_bytes());
        bytes.extend_from_slice(&packet.header.sequence_number.0.to_be_bytes());
        bytes.extend_from_slice(&packet.header.key_generation.0.to_be_bytes());
        let Ok(payload_length) = u16::try_from(packet.payload.len()) else {
            return Err(ProtocolError::PacketTooLarge {
                actual: HEADER_SIZE + packet.payload.len(),
                maximum: MAX_PACKET_SIZE,
            });
        };
        bytes.extend_from_slice(&payload_length.to_be_bytes());
        bytes.extend_from_slice(&0_u16.to_be_bytes());
        bytes.extend_from_slice(&packet.payload);
        Ok(bytes)
    }

    /// Decodes one fixed-format packet from a complete datagram.
    ///
    /// # Errors
    ///
    /// Returns a [`ProtocolError`] when the datagram is truncated, oversized,
    /// has an unsupported version or packet type, or contains invalid lengths.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() < HEADER_SIZE {
            return Err(ProtocolError::PacketTooShort {
                actual: bytes.len(),
                minimum: HEADER_SIZE,
            });
        }
        if bytes.len() > MAX_PACKET_SIZE {
            return Err(ProtocolError::PacketTooLarge {
                actual: bytes.len(),
                maximum: MAX_PACKET_SIZE,
            });
        }

        let version = ProtocolVersion::new(bytes[0], bytes[1], bytes[2]);
        if version != PROTOCOL_VERSION {
            return Err(ProtocolError::InvalidVersion(version));
        }

        let packet_type = PacketType::try_from(bytes[3])?;
        let flags = u16::from_be_bytes([bytes[4], bytes[5]]);
        let session_id =
            SessionId::new(u32::from_be_bytes([bytes[6], bytes[7], bytes[8], bytes[9]]))?;
        let sequence_number = SequenceNumber(u64::from_be_bytes([
            bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15], bytes[16], bytes[17],
        ]));
        let key_generation = KeyGeneration(u16::from_be_bytes([bytes[18], bytes[19]]));
        let payload_length = usize::from(u16::from_be_bytes([bytes[20], bytes[21]]));
        let reserved = u16::from_be_bytes([bytes[22], bytes[23]]);
        if reserved != 0 {
            return Err(ProtocolError::NonZeroReserved(reserved));
        }
        let actual_payload_length = bytes.len() - HEADER_SIZE;
        if payload_length != actual_payload_length {
            return Err(ProtocolError::PayloadLengthMismatch {
                declared: payload_length,
                actual: actual_payload_length,
            });
        }

        Self::new(
            TunnelHeader {
                version,
                packet_type,
                flags,
                session_id,
                sequence_number,
                key_generation,
            },
            bytes[HEADER_SIZE..].to_vec(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet(payload: Vec<u8>) -> TunnelPacket {
        TunnelPacket::new(
            TunnelHeader {
                version: PROTOCOL_VERSION,
                packet_type: PacketType::TransportData,
                flags: 0x0102,
                session_id: SessionId::new(42).expect("non-zero session ID"),
                sequence_number: SequenceNumber(7),
                key_generation: KeyGeneration(3),
            },
            payload,
        )
        .expect("payload fits")
    }

    #[test]
    fn round_trips_a_packet() {
        let original = packet(vec![1, 2, 3, 4]);
        let encoded = original.encode().expect("packet encodes");
        assert_eq!(encoded.len(), HEADER_SIZE + 4);
        assert_eq!(
            TunnelPacket::decode(&encoded).expect("packet decodes"),
            original
        );
    }

    #[test]
    fn accepts_empty_payload() {
        let encoded = packet(Vec::new()).encode().expect("packet encodes");
        assert_eq!(
            TunnelPacket::decode(&encoded)
                .expect("packet decodes")
                .payload,
            Vec::new()
        );
    }

    #[test]
    fn accepts_maximum_payload() {
        let encoded = packet(vec![0; MAX_PAYLOAD_SIZE])
            .encode()
            .expect("packet encodes");
        assert_eq!(encoded.len(), MAX_PACKET_SIZE);
        assert_eq!(
            TunnelPacket::decode(&encoded)
                .expect("packet decodes")
                .payload
                .len(),
            MAX_PAYLOAD_SIZE
        );
    }

    #[test]
    fn rejects_truncated_packet() {
        let error = TunnelPacket::decode(&[0; HEADER_SIZE - 1]).expect_err("packet must fail");
        assert!(matches!(error, ProtocolError::PacketTooShort { .. }));
    }

    #[test]
    fn rejects_wrong_version() {
        let mut encoded = packet(Vec::new()).encode().expect("packet encodes");
        encoded[0] = 2;
        assert!(matches!(
            TunnelPacket::decode(&encoded),
            Err(ProtocolError::InvalidVersion(_))
        ));
    }

    #[test]
    fn rejects_unknown_packet_type() {
        let mut encoded = packet(Vec::new()).encode().expect("packet encodes");
        encoded[3] = 0xff;
        assert!(matches!(
            TunnelPacket::decode(&encoded),
            Err(ProtocolError::UnknownPacketType(0xff))
        ));
    }

    #[test]
    fn rejects_zero_session_id() {
        let mut encoded = packet(Vec::new()).encode().expect("packet encodes");
        encoded[9] = 0;
        encoded[6..10].fill(0);
        assert!(matches!(
            TunnelPacket::decode(&encoded),
            Err(ProtocolError::InvalidSessionId)
        ));
    }

    #[test]
    fn rejects_payload_length_mismatch() {
        let mut encoded = packet(vec![1]).encode().expect("packet encodes");
        encoded[21] = 2;
        assert!(matches!(
            TunnelPacket::decode(&encoded),
            Err(ProtocolError::PayloadLengthMismatch { .. })
        ));
    }

    #[test]
    fn rejects_non_zero_reserved_field() {
        let mut encoded = packet(Vec::new()).encode().expect("packet encodes");
        encoded[23] = 1;
        assert!(matches!(
            TunnelPacket::decode(&encoded),
            Err(ProtocolError::NonZeroReserved(1))
        ));
    }

    #[test]
    fn arbitrary_bytes_never_panic() {
        for length in 0..=MAX_PACKET_SIZE + 16 {
            let bytes = vec![0xa5; length];
            let _ = TunnelPacket::decode(&bytes);
        }
    }
}
