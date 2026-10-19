//! Foundational types and codecs for the GSM Tunnel data plane.

mod codec;
mod crypto;
mod device;
mod engine;
mod protocol;
mod transport;

#[cfg(target_os = "linux")]
mod linux_device;

pub use codec::{TunnelHeader, TunnelPacket};
pub use crypto::{CryptoError, ReplayWindow, SessionCipher};
pub use device::{DeviceError, MemoryDevice, TunnelDevice};
pub use engine::{PlainTunnel, TunnelError};
#[cfg(target_os = "linux")]
pub use linux_device::LinuxTunDevice;
pub use protocol::{
    KeyGeneration, MAX_PACKET_SIZE, MAX_PAYLOAD_SIZE, PROTOCOL_NAME, PROTOCOL_VERSION, PacketType,
    ProtocolError, ProtocolVersion, SequenceNumber, SessionId, SessionState,
};
pub use transport::{TransportError, UdpTransport};
