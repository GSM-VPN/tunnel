//! Versioned control-plane IPC frames shared with the Go controller.

use std::{
    collections::HashMap,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::{
    LifecycleState, Metrics, PeerAuthorization, PeerRegistry, PeerRegistryError,
    TunnelNetworkConfig,
};

const FRAME_PREFIX: usize = 4;
const REQUEST_HEADER: usize = 2 + 8 + 2 + 4;
const RESPONSE_HEADER: usize = 2 + 8 + 2 + 2 + 4;
const PEER_PAYLOAD_FIXED_SIZE: usize = 8 + 32 + 1 + 4 + 16 + 8 + 2;
const MAX_PEER_USER_ID_LENGTH: usize = 256;
const PEER_FLAG_IPV4: u8 = 1 << 0;
const PEER_FLAG_IPV6: u8 = 1 << 1;
pub const MAX_MANAGEMENT_FRAME_SIZE: usize = 1 << 20;
pub const OPERATION_INITIALIZE: u16 = 1;
pub const OPERATION_START: u16 = 2;
pub const OPERATION_STOP: u16 = 3;
pub const OPERATION_REGISTER_PEER: u16 = 4;
pub const OPERATION_REMOVE_PEER: u16 = 5;
pub const OPERATION_CREATE_SESSION: u16 = 6;
pub const OPERATION_TERMINATE_SESSION: u16 = 7;
pub const OPERATION_GET_SESSION: u16 = 8;
pub const OPERATION_LIST_SESSIONS: u16 = 9;
pub const OPERATION_GET_STATISTICS: u16 = 10;
pub const OPERATION_UPDATE_CONFIGURATION: u16 = 11;
pub const OPERATION_GET_HEALTH: u16 = 12;
pub const STATUS_OK: u16 = 200;
pub const STATUS_BAD_REQUEST: u16 = 400;
pub const STATUS_NOT_FOUND: u16 = 404;
pub const STATUS_CONFLICT: u16 = 409;
pub const STATUS_FORBIDDEN: u16 = 403;
pub const STATUS_NOT_IMPLEMENTED: u16 = 501;
pub const STATUS_UNAVAILABLE: u16 = 503;

const SESSION_PAYLOAD_SIZE: usize = 12;
const CONFIG_PAYLOAD_SIZE: usize = 10;

fn is_known_operation(operation: u16) -> bool {
    (OPERATION_INITIALIZE..=OPERATION_GET_HEALTH).contains(&operation)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagementRequest {
    pub version: u16,
    pub request_id: u64,
    pub operation: u16,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagementResponse {
    pub version: u16,
    pub request_id: u64,
    pub status: u16,
    pub error_code: u16,
    pub payload: Vec<u8>,
}

/// Rust Core control-plane state owned by the management server.
pub struct ManagementService {
    peers: PeerRegistry,
    max_sessions: usize,
    metrics: Metrics,
    state: EngineState,
    config: TunnelNetworkConfig,
    sessions: HashMap<u32, ManagedSession>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EngineState {
    Uninitialized,
    Ready,
    Running,
    Stopped,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ManagedSession {
    pub session_id: u32,
    pub peer_id: u64,
    pub state: LifecycleState,
}

impl ManagementService {
    /// Creates a service with a bounded approved-peer registry.
    #[must_use]
    pub fn new(max_peers: usize, metrics: Metrics) -> Self {
        Self {
            peers: PeerRegistry::new(max_peers),
            max_sessions: max_peers,
            metrics,
            state: EngineState::Uninitialized,
            config: TunnelNetworkConfig::default(),
            sessions: HashMap::new(),
        }
    }

    #[must_use]
    pub const fn state(&self) -> EngineState {
        self.state
    }

    /// Dispatches one decoded control-plane request.
    #[must_use]
    pub fn handle(&mut self, request: &ManagementRequest, now: SystemTime) -> ManagementResponse {
        self.handle_with_permissions(request, now, true)
    }

    /// Dispatches a request after applying the server's mutation permission.
    #[must_use]
    pub fn handle_with_permissions(
        &mut self,
        request: &ManagementRequest,
        now: SystemTime,
        allow_mutations: bool,
    ) -> ManagementResponse {
        self.expire_approvals(now);
        if !allow_mutations && operation_mutates_state(request.operation) {
            return ManagementResponse {
                version: request.version,
                request_id: request.request_id,
                status: STATUS_FORBIDDEN,
                error_code: 4,
                payload: Vec::new(),
            };
        }
        let (status, error_code, payload) = match request.operation {
            OPERATION_INITIALIZE => self.initialize(&request.payload),
            OPERATION_START => self.start(&request.payload),
            OPERATION_STOP => self.stop(&request.payload),
            OPERATION_REGISTER_PEER => match decode_peer_registration(&request.payload) {
                Ok(peer) => match self.register_peer(peer, now) {
                    Ok(()) => (STATUS_OK, 0, Vec::new()),
                    Err(error) => (status_for_peer_error(&error), 1, Vec::new()),
                },
                Err(_) => (STATUS_BAD_REQUEST, 1, Vec::new()),
            },
            OPERATION_REMOVE_PEER => match decode_peer_removal(&request.payload) {
                Ok(peer_id) => match self.remove_peer(peer_id) {
                    Ok(()) => (STATUS_OK, 0, Vec::new()),
                    Err(status) => (status, 2, Vec::new()),
                },
                Err(_) => (STATUS_BAD_REQUEST, 2, Vec::new()),
            },
            OPERATION_GET_HEALTH => self.health(),
            OPERATION_GET_STATISTICS => (STATUS_OK, 0, encode_metrics(&self.metrics)),
            OPERATION_CREATE_SESSION => self.create_session(&request.payload, now),
            OPERATION_TERMINATE_SESSION => self.terminate_session(&request.payload),
            OPERATION_GET_SESSION => self.get_session(&request.payload),
            OPERATION_LIST_SESSIONS => (STATUS_OK, 0, encode_sessions(&self.sessions)),
            OPERATION_UPDATE_CONFIGURATION => self.update_configuration(&request.payload),
            _ => (STATUS_NOT_IMPLEMENTED, 3, Vec::new()),
        };
        ManagementResponse {
            version: request.version,
            request_id: request.request_id,
            status,
            error_code,
            payload,
        }
    }

    fn register_peer(
        &mut self,
        peer: PeerRegistrationPayload,
        now: SystemTime,
    ) -> Result<(), PeerRegistryError> {
        let expires_at = UNIX_EPOCH
            .checked_add(Duration::from_secs(peer.expires_at_unix))
            .ok_or(PeerRegistryError::InvalidExpiry)?;
        self.peers.register(
            PeerAuthorization {
                peer_id: peer.peer_id,
                user_id: peer.user_id,
                public_key: peer.public_key,
                ipv4: peer.ipv4.map(std::net::Ipv4Addr::from),
                ipv6: peer.ipv6.map(std::net::Ipv6Addr::from),
                expires_at,
            },
            now,
        )
    }

    fn expire_approvals(&mut self, now: SystemTime) {
        let expired = self.peers.purge_expired(now);
        for peer_id in expired {
            let session_ids: Vec<_> = self
                .sessions
                .values()
                .filter(|session| session.peer_id == peer_id)
                .map(|session| session.session_id)
                .collect();
            for session_id in session_ids {
                self.sessions.remove(&session_id);
                self.metrics.session_closed();
            }
        }
    }

    fn initialize(&mut self, payload: &[u8]) -> (u16, u16, Vec<u8>) {
        if !payload.is_empty() {
            return (STATUS_BAD_REQUEST, 4, Vec::new());
        }
        match self.state {
            EngineState::Uninitialized | EngineState::Stopped => {
                self.state = EngineState::Ready;
                (STATUS_OK, 0, Vec::new())
            }
            EngineState::Ready | EngineState::Running => (STATUS_CONFLICT, 4, Vec::new()),
        }
    }

    fn start(&mut self, payload: &[u8]) -> (u16, u16, Vec<u8>) {
        if !payload.is_empty() {
            return (STATUS_BAD_REQUEST, 4, Vec::new());
        }
        match self.state {
            EngineState::Ready => {
                self.state = EngineState::Running;
                (STATUS_OK, 0, Vec::new())
            }
            EngineState::Uninitialized | EngineState::Stopped => {
                (STATUS_UNAVAILABLE, 5, Vec::new())
            }
            EngineState::Running => (STATUS_CONFLICT, 4, Vec::new()),
        }
    }

    fn stop(&mut self, payload: &[u8]) -> (u16, u16, Vec<u8>) {
        if !payload.is_empty() {
            return (STATUS_BAD_REQUEST, 4, Vec::new());
        }
        match self.state {
            EngineState::Running | EngineState::Ready => {
                let closed = self.sessions.len();
                self.sessions.clear();
                for _ in 0..closed {
                    self.metrics.session_closed();
                }
                self.state = EngineState::Stopped;
                (STATUS_OK, 0, Vec::new())
            }
            EngineState::Stopped | EngineState::Uninitialized => (STATUS_CONFLICT, 4, Vec::new()),
        }
    }

    fn create_session(&mut self, payload: &[u8], now: SystemTime) -> (u16, u16, Vec<u8>) {
        let Ok((session_id, peer_id)) = decode_session_payload(payload) else {
            return (STATUS_BAD_REQUEST, 6, Vec::new());
        };
        if self.state != EngineState::Running {
            return (STATUS_UNAVAILABLE, 5, Vec::new());
        }
        let peer_is_authorized = self
            .peers
            .active_summaries(now)
            .iter()
            .any(|peer| peer.peer_id == peer_id);
        if !peer_is_authorized {
            return (STATUS_NOT_FOUND, 2, Vec::new());
        }
        if self.sessions.len() >= self.max_sessions
            || self
                .sessions
                .values()
                .any(|session| session.peer_id == peer_id)
        {
            return (STATUS_CONFLICT, 4, Vec::new());
        }
        if self.sessions.contains_key(&session_id) {
            return (STATUS_CONFLICT, 4, Vec::new());
        }
        self.sessions.insert(
            session_id,
            ManagedSession {
                session_id,
                peer_id,
                state: LifecycleState::Established,
            },
        );
        self.metrics.session_started();
        (STATUS_OK, 0, encode_session(&self.sessions[&session_id]))
    }

    fn terminate_session(&mut self, payload: &[u8]) -> (u16, u16, Vec<u8>) {
        let Ok((session_id, _)) = decode_session_payload(payload) else {
            return (STATUS_BAD_REQUEST, 6, Vec::new());
        };
        if self.sessions.remove(&session_id).is_none() {
            return (STATUS_NOT_FOUND, 2, Vec::new());
        }
        self.metrics.session_closed();
        (STATUS_OK, 0, Vec::new())
    }

    fn remove_peer(&mut self, peer_id: u64) -> Result<(), u16> {
        self.peers.revoke(peer_id).map_err(|_| STATUS_NOT_FOUND)?;
        let session_ids: Vec<_> = self
            .sessions
            .values()
            .filter(|session| session.peer_id == peer_id)
            .map(|session| session.session_id)
            .collect();
        for session_id in session_ids {
            self.sessions.remove(&session_id);
            self.metrics.session_closed();
        }
        Ok(())
    }

    fn get_session(&self, payload: &[u8]) -> (u16, u16, Vec<u8>) {
        let Ok((session_id, _)) = decode_session_payload(payload) else {
            return (STATUS_BAD_REQUEST, 6, Vec::new());
        };
        self.sessions
            .get(&session_id)
            .map_or((STATUS_NOT_FOUND, 2, Vec::new()), |session| {
                (STATUS_OK, 0, encode_session(session))
            })
    }

    fn update_configuration(&mut self, payload: &[u8]) -> (u16, u16, Vec<u8>) {
        match decode_configuration(payload) {
            Ok(config) => match config.validate() {
                Ok(_) if self.state != EngineState::Running => {
                    self.config = config;
                    (STATUS_OK, 0, Vec::new())
                }
                Ok(_) => (STATUS_CONFLICT, 4, Vec::new()),
                Err(_) => (STATUS_BAD_REQUEST, 6, Vec::new()),
            },
            Err(()) => (STATUS_BAD_REQUEST, 6, Vec::new()),
        }
    }

    fn health(&self) -> (u16, u16, Vec<u8>) {
        let (status, label) = match self.state {
            EngineState::Running => (STATUS_OK, "running"),
            EngineState::Ready => (STATUS_OK, "ready"),
            EngineState::Stopped => (STATUS_UNAVAILABLE, "stopped"),
            EngineState::Uninitialized => (STATUS_UNAVAILABLE, "uninitialized"),
        };
        (status, 0, label.as_bytes().to_vec())
    }
}

fn operation_mutates_state(operation: u16) -> bool {
    !matches!(
        operation,
        OPERATION_GET_HEALTH
            | OPERATION_GET_STATISTICS
            | OPERATION_GET_SESSION
            | OPERATION_LIST_SESSIONS
    )
}

fn decode_session_payload(payload: &[u8]) -> Result<(u32, u64), ()> {
    if payload.len() != SESSION_PAYLOAD_SIZE {
        return Err(());
    }
    Ok((
        u32::from_be_bytes(payload[0..4].try_into().map_err(|_| ())?),
        u64::from_be_bytes(payload[4..12].try_into().map_err(|_| ())?),
    ))
}

fn encode_session(session: &ManagedSession) -> Vec<u8> {
    let mut payload = Vec::with_capacity(SESSION_PAYLOAD_SIZE + 1);
    payload.extend_from_slice(&session.session_id.to_be_bytes());
    payload.extend_from_slice(&session.peer_id.to_be_bytes());
    payload.push(session_state_code(session.state));
    payload
}

fn encode_sessions(sessions: &HashMap<u32, ManagedSession>) -> Vec<u8> {
    let mut ordered: Vec<_> = sessions.values().collect();
    ordered.sort_by_key(|session| session.session_id);
    ordered.into_iter().flat_map(encode_session).collect()
}

fn session_state_code(state: LifecycleState) -> u8 {
    match state {
        LifecycleState::Disconnected => 0,
        LifecycleState::Connecting => 1,
        LifecycleState::Handshaking => 2,
        LifecycleState::Established => 3,
        LifecycleState::Rekeying => 4,
        LifecycleState::Reconnecting => 5,
        LifecycleState::Closing => 6,
        LifecycleState::Closed => 7,
    }
}

fn decode_configuration(payload: &[u8]) -> Result<TunnelNetworkConfig, ()> {
    if payload.len() != CONFIG_PAYLOAD_SIZE {
        return Err(());
    }
    let ipv4_prefix = payload[0];
    let ipv6_prefix = payload[1];
    let udp_port = u16::from_be_bytes(payload[2..4].try_into().map_err(|_| ())?);
    let mtu = u16::from_be_bytes(payload[4..6].try_into().map_err(|_| ())?);
    let dual_stack = payload[6] != 0;
    let kill_switch = payload[7] != 0;
    if ipv4_prefix != 16 || ipv6_prefix != 64 || payload[9] != 0 {
        return Err(());
    }
    Ok(TunnelNetworkConfig {
        udp_port,
        mtu: usize::from(mtu),
        dual_stack,
        nat66: payload[8] != 0,
        kill_switch,
        ..TunnelNetworkConfig::default()
    })
}

fn status_for_peer_error(error: &PeerRegistryError) -> u16 {
    match error {
        PeerRegistryError::DuplicatePeer
        | PeerRegistryError::DuplicatePublicKey
        | PeerRegistryError::DuplicateAddress
        | PeerRegistryError::Capacity => STATUS_CONFLICT,
        PeerRegistryError::UnknownPeer => STATUS_NOT_FOUND,
        PeerRegistryError::EmptyUserId
        | PeerRegistryError::InvalidAddress
        | PeerRegistryError::InvalidExpiry => STATUS_BAD_REQUEST,
    }
}

fn encode_metrics(metrics: &Metrics) -> Vec<u8> {
    let snapshot = metrics.snapshot();
    [
        snapshot.active_sessions,
        snapshot.tx_bytes,
        snapshot.rx_bytes,
        snapshot.tx_packets,
        snapshot.rx_packets,
        snapshot.authentication_failures,
        snapshot.replay_rejections,
        snapshot.reconnects,
        snapshot.handshake_failures,
        snapshot.keepalive_failures,
        snapshot.packet_errors,
    ]
    .into_iter()
    .flat_map(u64::to_be_bytes)
    .collect()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManagementError {
    FrameTooLarge,
    Truncated,
    LengthMismatch,
    ZeroVersion,
    UnknownOperation,
    InvalidPeerPayload,
    PeerUserIdTooLong,
}

/// Wire payload for the `RegisterPeer` management operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerRegistrationPayload {
    pub peer_id: u64,
    pub public_key: [u8; 32],
    pub ipv4: Option<[u8; 4]>,
    pub ipv6: Option<[u8; 16]>,
    pub expires_at_unix: u64,
    pub user_id: String,
}

/// Encodes the stable Go/Rust `RegisterPeer` payload.
///
/// # Errors
///
/// Returns an error when the user ID, address set, or expiry is invalid.
pub fn encode_peer_registration(
    peer: &PeerRegistrationPayload,
) -> Result<Vec<u8>, ManagementError> {
    if peer.user_id.is_empty() || peer.user_id.len() > MAX_PEER_USER_ID_LENGTH {
        return Err(ManagementError::PeerUserIdTooLong);
    }
    if peer.ipv4.is_none() && peer.ipv6.is_none() || peer.expires_at_unix == 0 {
        return Err(ManagementError::InvalidPeerPayload);
    }
    let mut payload = vec![0; PEER_PAYLOAD_FIXED_SIZE + peer.user_id.len()];
    payload[0..8].copy_from_slice(&peer.peer_id.to_be_bytes());
    payload[8..40].copy_from_slice(&peer.public_key);
    let mut flags = 0;
    if let Some(ipv4) = peer.ipv4 {
        flags |= PEER_FLAG_IPV4;
        payload[41..45].copy_from_slice(&ipv4);
    }
    if let Some(ipv6) = peer.ipv6 {
        flags |= PEER_FLAG_IPV6;
        payload[45..61].copy_from_slice(&ipv6);
    }
    payload[40] = flags;
    payload[61..69].copy_from_slice(&peer.expires_at_unix.to_be_bytes());
    let user_id_len =
        u16::try_from(peer.user_id.len()).map_err(|_| ManagementError::PeerUserIdTooLong)?;
    payload[69..71].copy_from_slice(&user_id_len.to_be_bytes());
    payload[71..].copy_from_slice(peer.user_id.as_bytes());
    Ok(payload)
}

/// Decodes and validates the stable Go/Rust `RegisterPeer` payload.
///
/// # Errors
///
/// Returns an error when the payload has invalid lengths, flags, encoding, or
/// expiry data.
pub fn decode_peer_registration(
    payload: &[u8],
) -> Result<PeerRegistrationPayload, ManagementError> {
    if payload.len() < PEER_PAYLOAD_FIXED_SIZE {
        return Err(ManagementError::InvalidPeerPayload);
    }
    let user_id_len = usize::from(u16::from_be_bytes(
        payload[69..71]
            .try_into()
            .map_err(|_| ManagementError::InvalidPeerPayload)?,
    ));
    if user_id_len == 0
        || user_id_len > MAX_PEER_USER_ID_LENGTH
        || payload.len() != PEER_PAYLOAD_FIXED_SIZE + user_id_len
    {
        return Err(ManagementError::InvalidPeerPayload);
    }
    let flags = payload[40];
    if flags & !(PEER_FLAG_IPV4 | PEER_FLAG_IPV6) != 0 || flags == 0 {
        return Err(ManagementError::InvalidPeerPayload);
    }
    let user_id = String::from_utf8(payload[71..].to_vec())
        .map_err(|_| ManagementError::InvalidPeerPayload)?;
    let mut public_key = [0; 32];
    public_key.copy_from_slice(&payload[8..40]);
    let ipv4 = (flags & PEER_FLAG_IPV4 != 0).then(|| {
        let mut value = [0; 4];
        value.copy_from_slice(&payload[41..45]);
        value
    });
    let ipv6 = (flags & PEER_FLAG_IPV6 != 0).then(|| {
        let mut value = [0; 16];
        value.copy_from_slice(&payload[45..61]);
        value
    });
    let expires_at_unix = u64::from_be_bytes(
        payload[61..69]
            .try_into()
            .map_err(|_| ManagementError::InvalidPeerPayload)?,
    );
    if expires_at_unix == 0 {
        return Err(ManagementError::InvalidPeerPayload);
    }
    Ok(PeerRegistrationPayload {
        peer_id: u64::from_be_bytes(
            payload[0..8]
                .try_into()
                .map_err(|_| ManagementError::InvalidPeerPayload)?,
        ),
        public_key,
        ipv4,
        ipv6,
        expires_at_unix,
        user_id,
    })
}

/// Encodes the eight-byte `RemovePeer` payload.
#[must_use]
pub fn encode_peer_removal(peer_id: u64) -> Vec<u8> {
    peer_id.to_be_bytes().to_vec()
}

/// Decodes the eight-byte `RemovePeer` payload.
///
/// # Errors
///
/// Returns an error when the payload is not exactly eight bytes.
pub fn decode_peer_removal(payload: &[u8]) -> Result<u64, ManagementError> {
    payload
        .try_into()
        .map(u64::from_be_bytes)
        .map_err(|_| ManagementError::InvalidPeerPayload)
}

impl ManagementRequest {
    /// Encodes a request using the Go controller's big-endian wire format.
    ///
    /// # Errors
    ///
    /// Returns an error when the version is zero or the frame exceeds the
    /// configured management message limit.
    pub fn encode(&self) -> Result<Vec<u8>, ManagementError> {
        if self.version == 0 {
            return Err(ManagementError::ZeroVersion);
        }
        if !is_known_operation(self.operation) {
            return Err(ManagementError::UnknownOperation);
        }
        let payload_len =
            u32::try_from(self.payload.len()).map_err(|_| ManagementError::FrameTooLarge)?;
        encode_frame(REQUEST_HEADER, self.payload.len(), |frame| {
            frame[4..6].copy_from_slice(&self.version.to_be_bytes());
            frame[6..14].copy_from_slice(&self.request_id.to_be_bytes());
            frame[14..16].copy_from_slice(&self.operation.to_be_bytes());
            frame[16..20].copy_from_slice(&payload_len.to_be_bytes());
            frame[20..].copy_from_slice(&self.payload);
        })
    }

    /// Decodes one complete length-prefixed request frame.
    ///
    /// # Errors
    ///
    /// Returns an error when the frame is truncated, oversized, or internally
    /// inconsistent.
    pub fn decode(frame: &[u8]) -> Result<Self, ManagementError> {
        validate_frame(frame, REQUEST_HEADER)?;
        let payload_len = read_u32(frame, 16)? as usize;
        if payload_len != frame.len() - FRAME_PREFIX - REQUEST_HEADER {
            return Err(ManagementError::LengthMismatch);
        }
        let request = Self {
            version: read_u16(frame, 4)?,
            request_id: read_u64(frame, 6)?,
            operation: read_u16(frame, 14)?,
            payload: frame.get(20..).ok_or(ManagementError::Truncated)?.to_vec(),
        };
        if request.version == 0 {
            return Err(ManagementError::ZeroVersion);
        }
        if !is_known_operation(request.operation) {
            return Err(ManagementError::UnknownOperation);
        }
        Ok(request)
    }
}

impl ManagementResponse {
    /// Encodes a response using the Go controller's big-endian wire format.
    ///
    /// # Errors
    ///
    /// Returns an error when the version is zero or the frame exceeds the
    /// configured management message limit.
    pub fn encode(&self) -> Result<Vec<u8>, ManagementError> {
        if self.version == 0 {
            return Err(ManagementError::ZeroVersion);
        }
        let payload_len =
            u32::try_from(self.payload.len()).map_err(|_| ManagementError::FrameTooLarge)?;
        encode_frame(RESPONSE_HEADER, self.payload.len(), |frame| {
            frame[4..6].copy_from_slice(&self.version.to_be_bytes());
            frame[6..14].copy_from_slice(&self.request_id.to_be_bytes());
            frame[14..16].copy_from_slice(&self.status.to_be_bytes());
            frame[16..18].copy_from_slice(&self.error_code.to_be_bytes());
            frame[18..22].copy_from_slice(&payload_len.to_be_bytes());
            frame[22..].copy_from_slice(&self.payload);
        })
    }

    /// Decodes one complete length-prefixed response frame.
    ///
    /// # Errors
    ///
    /// Returns an error when the frame is truncated, oversized, or internally
    /// inconsistent.
    pub fn decode(frame: &[u8]) -> Result<Self, ManagementError> {
        validate_frame(frame, RESPONSE_HEADER)?;
        let payload_len = read_u32(frame, 18)? as usize;
        if payload_len != frame.len() - FRAME_PREFIX - RESPONSE_HEADER {
            return Err(ManagementError::LengthMismatch);
        }
        let response = Self {
            version: read_u16(frame, 4)?,
            request_id: read_u64(frame, 6)?,
            status: read_u16(frame, 14)?,
            error_code: read_u16(frame, 16)?,
            payload: frame.get(22..).ok_or(ManagementError::Truncated)?.to_vec(),
        };
        if response.version == 0 {
            return Err(ManagementError::ZeroVersion);
        }
        Ok(response)
    }
}

fn encode_frame<F>(
    header_size: usize,
    payload_len: usize,
    write: F,
) -> Result<Vec<u8>, ManagementError>
where
    F: FnOnce(&mut [u8]),
{
    let frame_len = header_size
        .checked_add(payload_len)
        .ok_or(ManagementError::FrameTooLarge)?;
    if frame_len > MAX_MANAGEMENT_FRAME_SIZE {
        return Err(ManagementError::FrameTooLarge);
    }
    let mut frame = vec![0; FRAME_PREFIX + frame_len];
    let frame_len = u32::try_from(frame_len).map_err(|_| ManagementError::FrameTooLarge)?;
    frame[..FRAME_PREFIX].copy_from_slice(&frame_len.to_be_bytes());
    write(&mut frame);
    Ok(frame)
}

fn validate_frame(frame: &[u8], header_size: usize) -> Result<(), ManagementError> {
    if frame.len() < FRAME_PREFIX + header_size {
        return Err(ManagementError::Truncated);
    }
    let declared = read_u32(frame, 0)? as usize;
    if declared > MAX_MANAGEMENT_FRAME_SIZE {
        return Err(ManagementError::FrameTooLarge);
    }
    if declared != frame.len() - FRAME_PREFIX {
        return Err(ManagementError::LengthMismatch);
    }
    Ok(())
}

fn read_u16(frame: &[u8], start: usize) -> Result<u16, ManagementError> {
    let bytes = frame
        .get(start..start + 2)
        .ok_or(ManagementError::Truncated)?;
    Ok(u16::from_be_bytes(
        bytes.try_into().map_err(|_| ManagementError::Truncated)?,
    ))
}

fn read_u32(frame: &[u8], start: usize) -> Result<u32, ManagementError> {
    let bytes = frame
        .get(start..start + 4)
        .ok_or(ManagementError::Truncated)?;
    Ok(u32::from_be_bytes(
        bytes.try_into().map_err(|_| ManagementError::Truncated)?,
    ))
}

fn read_u64(frame: &[u8], start: usize) -> Result<u64, ManagementError> {
    let bytes = frame
        .get(start..start + 8)
        .ok_or(ManagementError::Truncated)?;
    Ok(u64::from_be_bytes(
        bytes.try_into().map_err(|_| ManagementError::Truncated)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_only_permission_rejects_mutations_but_allows_health() {
        let mut service = ManagementService::new(4, Metrics::default());
        let initialize = ManagementRequest {
            version: 1,
            request_id: 1,
            operation: OPERATION_INITIALIZE,
            payload: Vec::new(),
        };
        assert_eq!(
            service
                .handle_with_permissions(&initialize, UNIX_EPOCH, false)
                .status,
            STATUS_FORBIDDEN
        );
        let health = ManagementRequest {
            version: 1,
            request_id: 2,
            operation: OPERATION_GET_HEALTH,
            payload: Vec::new(),
        };
        assert_eq!(
            service
                .handle_with_permissions(&health, UNIX_EPOCH, false)
                .status,
            STATUS_UNAVAILABLE
        );
    }

    #[test]
    fn request_matches_go_layout() {
        let request = ManagementRequest {
            version: 1,
            request_id: 42,
            operation: 2,
            payload: b"config".to_vec(),
        };
        let encoded = request.encode().unwrap();
        assert_eq!(&encoded[..4], &[0, 0, 0, 22]);
        assert_eq!(ManagementRequest::decode(&encoded).unwrap(), request);
    }

    #[test]
    fn response_round_trips_and_rejects_truncation() {
        let response = ManagementResponse {
            version: 1,
            request_id: 42,
            status: 200,
            error_code: 0,
            payload: b"ok".to_vec(),
        };
        let encoded = response.encode().unwrap();
        assert_eq!(ManagementResponse::decode(&encoded).unwrap(), response);
        assert_eq!(
            ManagementResponse::decode(&encoded[..encoded.len() - 1]),
            Err(ManagementError::LengthMismatch)
        );
    }

    #[test]
    fn rejects_zero_version_and_oversize_payload() {
        let zero = ManagementRequest {
            version: 0,
            request_id: 1,
            operation: 1,
            payload: Vec::new(),
        };
        assert_eq!(zero.encode(), Err(ManagementError::ZeroVersion));
        let large = ManagementRequest {
            version: 1,
            request_id: 1,
            operation: 1,
            payload: vec![0; MAX_MANAGEMENT_FRAME_SIZE],
        };
        assert_eq!(large.encode(), Err(ManagementError::FrameTooLarge));
        let unknown = ManagementRequest {
            version: 1,
            request_id: 1,
            operation: 99,
            payload: Vec::new(),
        };
        assert_eq!(unknown.encode(), Err(ManagementError::UnknownOperation));

        let encoded = ManagementRequest {
            version: 1,
            request_id: 1,
            operation: OPERATION_GET_HEALTH,
            payload: Vec::new(),
        }
        .encode()
        .unwrap();
        let mut zero_version = encoded;
        zero_version[4..6].copy_from_slice(&0_u16.to_be_bytes());
        assert_eq!(
            ManagementRequest::decode(&zero_version),
            Err(ManagementError::ZeroVersion)
        );
    }

    #[test]
    fn peer_payload_matches_fixed_cross_language_layout() {
        let peer = PeerRegistrationPayload {
            peer_id: 7,
            public_key: [3; 32],
            ipv4: Some([10, 80, 0, 2]),
            ipv6: None,
            expires_at_unix: 1_700_000_000,
            user_id: "user-7".to_owned(),
        };
        let encoded = encode_peer_registration(&peer).unwrap();
        assert_eq!(encoded.len(), PEER_PAYLOAD_FIXED_SIZE + 6);
        assert_eq!(encoded[0..8], 7_u64.to_be_bytes());
        assert_eq!(encoded[40], PEER_FLAG_IPV4);
        assert_eq!(decode_peer_registration(&encoded).unwrap(), peer);
        assert_eq!(decode_peer_removal(&encode_peer_removal(7)).unwrap(), 7);
    }

    #[test]
    fn rejects_invalid_peer_payloads() {
        let peer = PeerRegistrationPayload {
            peer_id: 1,
            public_key: [0; 32],
            ipv4: None,
            ipv6: None,
            expires_at_unix: 1,
            user_id: "user".to_owned(),
        };
        assert_eq!(
            encode_peer_registration(&peer),
            Err(ManagementError::InvalidPeerPayload)
        );
        assert_eq!(
            decode_peer_removal(&[1, 2]),
            Err(ManagementError::InvalidPeerPayload)
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn manages_engine_state_and_authorized_sessions() {
        let mut service = ManagementService::new(2, Metrics::default());
        let request = |operation, payload| ManagementRequest {
            version: 1,
            request_id: 1,
            operation,
            payload,
        };
        assert_eq!(service.state(), EngineState::Uninitialized);
        assert_eq!(
            service
                .handle(&request(OPERATION_START, Vec::new()), UNIX_EPOCH)
                .status,
            STATUS_UNAVAILABLE
        );
        assert_eq!(
            service
                .handle(&request(OPERATION_INITIALIZE, Vec::new()), UNIX_EPOCH)
                .status,
            STATUS_OK
        );
        assert_eq!(
            service
                .handle(&request(OPERATION_START, Vec::new()), UNIX_EPOCH)
                .status,
            STATUS_OK
        );

        let peer = PeerRegistrationPayload {
            peer_id: 7,
            public_key: [3; 32],
            ipv4: Some([10, 80, 0, 2]),
            ipv6: None,
            expires_at_unix: 120,
            user_id: "user-7".to_owned(),
        };
        assert_eq!(
            service
                .handle(
                    &request(
                        OPERATION_REGISTER_PEER,
                        encode_peer_registration(&peer).unwrap()
                    ),
                    UNIX_EPOCH
                )
                .status,
            STATUS_OK
        );
        let mut session_payload = Vec::new();
        session_payload.extend_from_slice(&9_u32.to_be_bytes());
        session_payload.extend_from_slice(&7_u64.to_be_bytes());
        let created = service.handle(
            &request(OPERATION_CREATE_SESSION, session_payload.clone()),
            UNIX_EPOCH,
        );
        assert_eq!(created.status, STATUS_OK);
        assert_eq!(created.payload.len(), SESSION_PAYLOAD_SIZE + 1);
        let mut duplicate_session = Vec::new();
        duplicate_session.extend_from_slice(&10_u32.to_be_bytes());
        duplicate_session.extend_from_slice(&7_u64.to_be_bytes());
        assert_eq!(
            service
                .handle(
                    &request(OPERATION_CREATE_SESSION, duplicate_session),
                    UNIX_EPOCH
                )
                .status,
            STATUS_CONFLICT
        );
        assert_eq!(
            service
                .handle(
                    &request(OPERATION_GET_SESSION, session_payload.clone()),
                    UNIX_EPOCH
                )
                .status,
            STATUS_OK
        );
        assert_eq!(
            service
                .handle(
                    &request(OPERATION_TERMINATE_SESSION, session_payload),
                    UNIX_EPOCH
                )
                .status,
            STATUS_OK
        );
        assert_eq!(
            service
                .handle(
                    &request(OPERATION_GET_SESSION, vec![0; SESSION_PAYLOAD_SIZE]),
                    UNIX_EPOCH
                )
                .status,
            STATUS_NOT_FOUND
        );
        let mut revocable_session = Vec::new();
        revocable_session.extend_from_slice(&11_u32.to_be_bytes());
        revocable_session.extend_from_slice(&7_u64.to_be_bytes());
        assert_eq!(
            service
                .handle(
                    &request(OPERATION_CREATE_SESSION, revocable_session.clone()),
                    UNIX_EPOCH,
                )
                .status,
            STATUS_OK
        );
        assert_eq!(
            service
                .handle(
                    &request(OPERATION_REMOVE_PEER, encode_peer_removal(7)),
                    UNIX_EPOCH,
                )
                .status,
            STATUS_OK
        );
        assert_eq!(
            service
                .handle(
                    &request(OPERATION_GET_SESSION, revocable_session),
                    UNIX_EPOCH,
                )
                .status,
            STATUS_NOT_FOUND
        );
    }

    #[test]
    fn prevents_live_configuration_changes_and_clears_sessions_on_stop() {
        let mut service = ManagementService::new(1, Metrics::default());
        let request = |operation, payload| ManagementRequest {
            version: 1,
            request_id: 1,
            operation,
            payload,
        };
        assert_eq!(
            service
                .handle(&request(OPERATION_INITIALIZE, Vec::new()), UNIX_EPOCH)
                .status,
            STATUS_OK
        );
        let mut config = vec![16, 64, 0xCA, 0x6C, 0x05, 0x78, 1, 0, 0, 0];
        assert_eq!(
            service
                .handle(
                    &request(OPERATION_UPDATE_CONFIGURATION, std::mem::take(&mut config)),
                    UNIX_EPOCH
                )
                .status,
            STATUS_OK
        );
        assert_eq!(
            service
                .handle(&request(OPERATION_START, Vec::new()), UNIX_EPOCH)
                .status,
            STATUS_OK
        );
        assert_eq!(
            service
                .handle(
                    &request(
                        OPERATION_UPDATE_CONFIGURATION,
                        vec![16, 64, 0xCA, 0x6C, 0x05, 0x78, 1, 0, 0, 0]
                    ),
                    UNIX_EPOCH
                )
                .status,
            STATUS_CONFLICT
        );
        assert_eq!(
            service
                .handle(&request(OPERATION_STOP, Vec::new()), UNIX_EPOCH)
                .status,
            STATUS_OK
        );
        assert_eq!(
            service
                .handle(&request(OPERATION_LIST_SESSIONS, Vec::new()), UNIX_EPOCH)
                .payload,
            Vec::<u8>::new()
        );
    }
}
