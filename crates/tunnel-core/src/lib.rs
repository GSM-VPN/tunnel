//! Foundational types and codecs for the GSM Tunnel data plane.

mod codec;
mod device;
mod protocol;

#[cfg(target_os = "linux")]
mod linux_device;

pub use codec::{TunnelHeader, TunnelPacket};
pub use device::{DeviceError, MemoryDevice, TunnelDevice};
#[cfg(target_os = "linux")]
pub use linux_device::LinuxTunDevice;
pub use protocol::{
    KeyGeneration, MAX_PACKET_SIZE, MAX_PAYLOAD_SIZE, PROTOCOL_NAME, PROTOCOL_VERSION, PacketType,
    ProtocolError, ProtocolVersion, SequenceNumber, SessionId, SessionState,
};
