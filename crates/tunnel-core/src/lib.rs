//! Foundational types and codecs for the GSM Tunnel data plane.

mod address_pool;
mod codec;
mod crypto;
mod device;
mod dns;
mod encrypted_engine;
mod engine;
mod protocol;
mod rate_limit;
mod session;
mod session_endpoint;
mod session_table;
mod transport;

#[cfg(target_os = "linux")]
mod linux_device;

mod identity;
mod ip_packet;
mod key_rotation;
mod management;
#[cfg(unix)]
mod management_server;
mod metrics;
mod network;
mod noise;
mod peer;

pub use address_pool::{AddressPoolError, ClientAddressPool, ClientAddresses};
pub use codec::{TunnelHeader, TunnelPacket};
pub use crypto::{CryptoError, ReplayWindow, SessionCipher};
pub use device::{DeviceError, MemoryDevice, TunnelDevice};
pub use dns::{
    DnsCommand, DnsConfigError, DnsPolicy, DnsSnapshot, DnsTransport, DnsUpstream,
    DnsUpstreamSelector, LinuxDnsPlan,
};
pub use encrypted_engine::{EncryptedTunnel, EncryptedTunnelError};
pub use engine::{PlainTunnel, TunnelError};
pub use identity::{IdentityConfigError, ServerIdentity};
pub use ip_packet::{
    InnerIpPacketError, InnerIpPacketInfo, InnerIpVersion, ipv4_header_checksum,
    is_tunnel_ipv4_address, validate_inner_ip_packet,
};
pub use key_rotation::{KeyRotationPolicy, RotationReason};
#[cfg(target_os = "linux")]
pub use linux_device::LinuxTunDevice;
pub use management::{EngineState, ManagedSession};
pub use management::{
    MAX_MANAGEMENT_FRAME_SIZE, ManagementError, ManagementRequest, ManagementResponse,
    ManagementService, OPERATION_CREATE_SESSION, OPERATION_GET_HEALTH, OPERATION_GET_SESSION,
    OPERATION_GET_STATISTICS, OPERATION_INITIALIZE, OPERATION_LIST_SESSIONS,
    OPERATION_REGISTER_PEER, OPERATION_REMOVE_PEER, OPERATION_START, OPERATION_STOP,
    OPERATION_TERMINATE_SESSION, OPERATION_UPDATE_CONFIGURATION, PeerRegistrationPayload,
    STATUS_BAD_REQUEST, STATUS_CONFLICT, STATUS_FORBIDDEN, STATUS_NOT_FOUND,
    STATUS_NOT_IMPLEMENTED, STATUS_OK, STATUS_UNAVAILABLE, decode_peer_registration,
    decode_peer_removal, encode_peer_registration, encode_peer_removal,
};
#[cfg(unix)]
pub use management_server::UnixManagementServer;
pub use metrics::{Metrics, MetricsSnapshot, SessionMetricsSnapshot};
pub use network::{
    LinuxClientNetworkPlan, LinuxClientRoutePlan, LinuxKillSwitchPlan, LinuxNetworkPlan,
    LinuxRouteSnapshot, LinuxRouteState, MtuBudget, NetworkCommand, NetworkConfigError,
    TunnelNetworkConfig,
};
pub use noise::{NOISE_IK_PARAMS, NoiseHandshake, NoiseHandshakeError, NoiseTransport};
pub use peer::{PeerAuthorization, PeerRegistry, PeerRegistryError, PeerSummary};
pub use protocol::{
    AEAD_TAG_SIZE, KeyGeneration, MAX_ENCRYPTED_PAYLOAD_SIZE, MAX_PACKET_SIZE, MAX_PAYLOAD_SIZE,
    PROTOCOL_NAME, PROTOCOL_VERSION, PacketType, ProtocolError, ProtocolVersion, SequenceNumber,
    SessionId, SessionState,
};
pub use rate_limit::{PeerRateLimiter, RateLimitKind, RateLimitPolicy};
pub use session::{
    IdleAction, LifecycleState, SessionError, SessionEvent, SessionMachine, SessionPolicy,
    Transition,
};
pub use session_endpoint::{SessionEndpointError, SessionEndpointTable};
pub use session_table::{SessionTable, SessionTableError};
pub use transport::{TransportError, UdpTransport};
