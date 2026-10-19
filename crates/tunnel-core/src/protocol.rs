use core::fmt;

/// Protocol identifier defined by the project specification.
pub const PROTOCOL_NAME: &str = "gsm-tunnel";

/// Initial protocol version defined by the project specification.
pub const PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::new(1, 0, 0);

/// Fixed header size from the wire format in bytes.
pub const HEADER_SIZE: usize = 24;

/// Initial tunnel MTU and maximum encoded packet size.
pub const MAX_PACKET_SIZE: usize = 1_400;

/// Maximum payload that fits in an initial tunnel packet.
pub const MAX_PAYLOAD_SIZE: usize = MAX_PACKET_SIZE - HEADER_SIZE;

/// ChaCha20-Poly1305 authentication tag size in bytes.
pub const AEAD_TAG_SIZE: usize = 16;

/// Maximum plaintext that fits after the tunnel header and AEAD tag.
pub const MAX_ENCRYPTED_PAYLOAD_SIZE: usize = MAX_PAYLOAD_SIZE - AEAD_TAG_SIZE;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtocolVersion {
    pub major: u8,
    pub minor: u8,
    pub patch: u8,
}

impl ProtocolVersion {
    #[must_use]
    pub const fn new(major: u8, minor: u8, patch: u8) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum PacketType {
    HandshakeInitiation = 0x01,
    HandshakeResponse = 0x02,
    TransportData = 0x03,
    Keepalive = 0x04,
    SessionTermination = 0x05,
    ProtocolError = 0x06,
    Rekey = 0x07,
}

impl TryFrom<u8> for PacketType {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::HandshakeInitiation),
            0x02 => Ok(Self::HandshakeResponse),
            0x03 => Ok(Self::TransportData),
            0x04 => Ok(Self::Keepalive),
            0x05 => Ok(Self::SessionTermination),
            0x06 => Ok(Self::ProtocolError),
            0x07 => Ok(Self::Rekey),
            value => Err(ProtocolError::UnknownPacketType(value)),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionId(pub u32);

impl SessionId {
    /// Creates a session ID after rejecting the reserved zero value.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::InvalidSessionId`] when `value` is zero.
    pub const fn new(value: u32) -> Result<Self, ProtocolError> {
        if value == 0 {
            Err(ProtocolError::InvalidSessionId)
        } else {
            Ok(Self(value))
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SequenceNumber(pub u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyGeneration(pub u16);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionState {
    Initializing,
    Handshaking,
    Established,
    Rekeying,
    Closing,
    Closed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProtocolError {
    PacketTooShort { actual: usize, minimum: usize },
    PacketTooLarge { actual: usize, maximum: usize },
    InvalidVersion(ProtocolVersion),
    UnknownPacketType(u8),
    InvalidSessionId,
    PayloadLengthMismatch { declared: usize, actual: usize },
    NonZeroReserved(u16),
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PacketTooShort { actual, minimum } => {
                write!(
                    formatter,
                    "packet is too short: {actual} bytes, minimum {minimum}"
                )
            }
            Self::PacketTooLarge { actual, maximum } => {
                write!(
                    formatter,
                    "packet is too large: {actual} bytes, maximum {maximum}"
                )
            }
            Self::InvalidVersion(version) => write!(
                formatter,
                "unsupported protocol version {}.{}.{}",
                version.major, version.minor, version.patch
            ),
            Self::UnknownPacketType(value) => {
                write!(formatter, "unknown packet type: {value:#04x}")
            }
            Self::InvalidSessionId => formatter.write_str("session ID must not be zero"),
            Self::PayloadLengthMismatch { declared, actual } => write!(
                formatter,
                "payload length mismatch: declared {declared}, actual {actual}"
            ),
            Self::NonZeroReserved(value) => {
                write!(formatter, "reserved field is not zero: {value}")
            }
        }
    }
}

impl std::error::Error for ProtocolError {}
