//! Foundational types and codecs for the GSM Tunnel data plane.

mod codec;
mod crypto;
mod device;
mod encrypted_engine;
mod engine;
mod protocol;
mod session;
mod session_table;
mod transport;

#[cfg(target_os = "linux")]
mod linux_device;

mod key_rotation;
mod management;
mod metrics;

pub use codec::{TunnelHeader, TunnelPacket};
pub use crypto::{CryptoError, ReplayWindow, SessionCipher};
pub use device::{DeviceError, MemoryDevice, TunnelDevice};
pub use encrypted_engine::{EncryptedTunnel, EncryptedTunnelError};
pub use engine::{PlainTunnel, TunnelError};
pub use key_rotation::{KeyRotationPolicy, RotationReason};
#[cfg(target_os = "linux")]
pub use linux_device::LinuxTunDevice;
pub use management::{
    MAX_MANAGEMENT_FRAME_SIZE, ManagementError, ManagementRequest, ManagementResponse,
    OPERATION_CREATE_SESSION, OPERATION_GET_HEALTH, OPERATION_GET_SESSION,
    OPERATION_GET_STATISTICS, OPERATION_INITIALIZE, OPERATION_LIST_SESSIONS,
    OPERATION_REGISTER_PEER, OPERATION_REMOVE_PEER, OPERATION_START, OPERATION_STOP,
    OPERATION_TERMINATE_SESSION, OPERATION_UPDATE_CONFIGURATION,
};
pub use metrics::{Metrics, MetricsSnapshot};
pub use protocol::{
    AEAD_TAG_SIZE, KeyGeneration, MAX_ENCRYPTED_PAYLOAD_SIZE, MAX_PACKET_SIZE, MAX_PAYLOAD_SIZE,
    PROTOCOL_NAME, PROTOCOL_VERSION, PacketType, ProtocolError, ProtocolVersion, SequenceNumber,
    SessionId, SessionState,
};
pub use session::{
    LifecycleState, SessionError, SessionEvent, SessionMachine, SessionPolicy, Transition,
};
pub use session_table::{SessionTable, SessionTableError};
pub use transport::{TransportError, UdpTransport};
