use crate::{
    DeviceError, MAX_PACKET_SIZE, PROTOCOL_VERSION, PacketType, ProtocolError, SequenceNumber,
    SessionCipher, SessionId, TransportError, TunnelDevice, TunnelHeader, TunnelPacket,
    UdpTransport,
};
use crate::{KeyRotationPolicy, RotationReason};
use std::time::Instant;

/// Errors returned by the authenticated tunnel data path.
#[derive(Debug, Eq, PartialEq)]
pub enum EncryptedTunnelError {
    Device(DeviceError),
    Protocol(ProtocolError),
    Crypto(crate::CryptoError),
    Transport(TransportError),
    UnexpectedPacketType(PacketType),
    KeyRotationRequired(RotationReason),
    SequenceExhausted,
}

impl From<DeviceError> for EncryptedTunnelError {
    fn from(error: DeviceError) -> Self {
        Self::Device(error)
    }
}

impl From<ProtocolError> for EncryptedTunnelError {
    fn from(error: ProtocolError) -> Self {
        Self::Protocol(error)
    }
}

impl From<crate::CryptoError> for EncryptedTunnelError {
    fn from(error: crate::CryptoError) -> Self {
        Self::Crypto(error)
    }
}

impl From<TransportError> for EncryptedTunnelError {
    fn from(error: TransportError) -> Self {
        Self::Transport(error)
    }
}

/// Authenticated tunnel data path.
pub struct EncryptedTunnel<D> {
    pub(crate) device: D,
    pub(crate) transport: UdpTransport,
    sender: SessionCipher,
    receiver: SessionCipher,
    session_id: SessionId,
    next_sequence: u64,
    transmitted_bytes: u64,
    started_at: Instant,
    rotation_policy: KeyRotationPolicy,
}

impl<D: TunnelDevice> EncryptedTunnel<D> {
    #[must_use]
    pub fn new(
        device: D,
        transport: UdpTransport,
        sender: SessionCipher,
        receiver: SessionCipher,
        session_id: SessionId,
    ) -> Self {
        Self::with_rotation_policy(
            device,
            transport,
            sender,
            receiver,
            session_id,
            KeyRotationPolicy::default(),
        )
    }

    #[must_use]
    pub fn with_rotation_policy(
        device: D,
        transport: UdpTransport,
        sender: SessionCipher,
        receiver: SessionCipher,
        session_id: SessionId,
        rotation_policy: KeyRotationPolicy,
    ) -> Self {
        Self {
            device,
            transport,
            sender,
            receiver,
            session_id,
            next_sequence: 0,
            transmitted_bytes: 0,
            started_at: Instant::now(),
            rotation_policy,
        }
    }

    #[must_use]
    pub const fn transmitted_bytes(&self) -> u64 {
        self.transmitted_bytes
    }

    fn ensure_rotation_window(&self) -> Result<(), EncryptedTunnelError> {
        if let Some(reason) = self.rotation_policy.rotation_reason(
            self.started_at.elapsed(),
            self.transmitted_bytes,
            self.next_sequence,
        ) {
            return Err(EncryptedTunnelError::KeyRotationRequired(reason));
        }
        Ok(())
    }

    /// Encrypts one device packet and sends it as an authenticated datagram.
    ///
    /// # Errors
    ///
    /// Returns a device, encryption, protocol, or transport error.
    pub fn send_next(&mut self) -> Result<usize, EncryptedTunnelError> {
        self.ensure_rotation_window()?;
        let mut payload = vec![0; self.device.mtu()];
        let length = self.device.read_packet(&mut payload)?;
        payload.truncate(length);
        let next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(EncryptedTunnelError::SequenceExhausted)?;
        let next_transmitted_bytes = self
            .transmitted_bytes
            .checked_add(length as u64)
            .ok_or(EncryptedTunnelError::SequenceExhausted)?;
        let header = TunnelHeader {
            version: PROTOCOL_VERSION,
            packet_type: PacketType::TransportData,
            flags: 0,
            session_id: self.session_id,
            sequence_number: SequenceNumber(self.next_sequence),
            key_generation: crate::KeyGeneration(0),
        };
        let packet = self.sender.seal(header, &payload)?;
        let encoded = packet.encode()?;
        let sent = self.transport.send(&encoded)?;
        self.next_sequence = next_sequence;
        self.transmitted_bytes = next_transmitted_bytes;
        Ok(sent)
    }

    /// Sends an authenticated keepalive without touching the tunnel device.
    ///
    /// # Errors
    ///
    /// Returns an encryption, protocol, or transport error.
    pub fn send_keepalive(&mut self) -> Result<usize, EncryptedTunnelError> {
        self.ensure_rotation_window()?;
        let header = TunnelHeader {
            version: PROTOCOL_VERSION,
            packet_type: PacketType::Keepalive,
            flags: 0,
            session_id: self.session_id,
            sequence_number: SequenceNumber(self.next_sequence),
            key_generation: crate::KeyGeneration(0),
        };
        let packet = self.sender.seal(header, &[])?;
        let sent = self.transport.send(&packet.encode()?)?;
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(EncryptedTunnelError::SequenceExhausted)?;
        Ok(sent)
    }

    /// Receives, authenticates, decrypts, and writes one device packet.
    ///
    /// # Errors
    ///
    /// Returns a device, protocol, encryption, or transport error. Failed
    /// authentication never writes plaintext to the device.
    pub fn receive_next(&mut self) -> Result<usize, EncryptedTunnelError> {
        let mut encoded = vec![0; MAX_PACKET_SIZE];
        let (length, _) = self.transport.receive(&mut encoded)?;
        let packet = TunnelPacket::decode(&encoded[..length])?;
        let plaintext = self.receiver.open(&packet)?;
        match packet.header.packet_type {
            PacketType::TransportData => Ok(self.device.write_packet(&plaintext)?),
            PacketType::Keepalive => Ok(0),
            packet_type => Err(EncryptedTunnelError::UnexpectedPacketType(packet_type)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::EncryptedTunnel;
    use crate::{
        DeviceError, KeyGeneration, KeyRotationPolicy, MemoryDevice, RotationReason, SessionCipher,
        SessionId, TunnelDevice, UdpTransport,
    };
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn loopback() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
    }

    #[test]
    fn transfers_an_authenticated_packet_over_udp() {
        let key = [9; 32];
        let session = SessionId::new(8).expect("session ID");
        let (mut client_device, server_device) = MemoryDevice::pair(1_400);
        let mut server_application = server_device.clone();
        let mut client_application = client_device.clone();
        client_device
            .inject(b"encrypted packet")
            .expect("packet injects");
        let client_transport = UdpTransport::bind(loopback(), 1_400).expect("client binds");
        let server_transport = UdpTransport::bind(loopback(), 1_400).expect("server binds");
        let client_address = client_transport.local_addr().expect("client address");
        let server_address = server_transport.local_addr().expect("server address");
        let sender = SessionCipher::new(key, session, KeyGeneration(0), 1);
        let receiver_cipher = SessionCipher::new(key, session, KeyGeneration(0), 1);
        let mut client = EncryptedTunnel::new(
            client_device,
            client_transport,
            sender,
            SessionCipher::new(key, session, KeyGeneration(0), 2),
            session,
        );
        let mut server = EncryptedTunnel::new(
            server_device,
            server_transport,
            SessionCipher::new(key, session, KeyGeneration(0), 2),
            receiver_cipher,
            session,
        );
        client.transport.set_remote(server_address);
        server.transport.set_remote(client_address);
        client.send_next().expect("packet sends");
        server.receive_next().expect("packet receives");
        let mut output = [0; 1_400];
        assert_eq!(client_application.read_packet(&mut output), Ok(16));
        assert_eq!(&output[..16], b"encrypted packet");
        client.send_keepalive().expect("keepalive sends");
        assert_eq!(server.receive_next(), Ok(0));
        assert_eq!(
            server_application.read_packet(&mut output),
            Err(DeviceError::WouldBlock)
        );
    }

    #[test]
    fn stops_sending_before_key_rotation_byte_limit() {
        let key = [4; 32];
        let session = SessionId::new(12).expect("session ID");
        let (mut device, _) = MemoryDevice::pair(1_400);
        device.inject(b"first").expect("packet injects");
        let client_transport = UdpTransport::bind(loopback(), 1_400).expect("client binds");
        let server_transport = UdpTransport::bind(loopback(), 1_400).expect("server binds");
        let server_address = server_transport.local_addr().expect("server address");
        let policy = KeyRotationPolicy {
            max_age: std::time::Duration::from_secs(3_600),
            max_bytes: 5,
            max_sequence: u64::MAX - 1,
        };
        let mut tunnel = EncryptedTunnel::with_rotation_policy(
            device,
            client_transport,
            SessionCipher::new(key, session, KeyGeneration(0), 1),
            SessionCipher::new(key, session, KeyGeneration(0), 2),
            session,
            policy,
        );
        tunnel.transport.set_remote(server_address);
        tunnel.send_next().expect("first packet sends");
        assert_eq!(tunnel.transmitted_bytes(), 5);
        assert_eq!(
            tunnel.send_next(),
            Err(super::EncryptedTunnelError::KeyRotationRequired(
                RotationReason::Bytes
            ))
        );
    }

    #[test]
    fn rejects_sequence_rotation_boundary_before_nonce_reuse() {
        let key = [5; 32];
        let session = SessionId::new(13).expect("session ID");
        let (device, _) = MemoryDevice::pair(1_400);
        let client_transport = UdpTransport::bind(loopback(), 1_400).expect("client binds");
        let server_transport = UdpTransport::bind(loopback(), 1_400).expect("server binds");
        let policy = KeyRotationPolicy {
            max_age: std::time::Duration::from_secs(3_600),
            max_bytes: u64::MAX,
            max_sequence: 0,
        };
        let mut tunnel = EncryptedTunnel::with_rotation_policy(
            device,
            client_transport,
            SessionCipher::new(key, session, KeyGeneration(0), 1),
            SessionCipher::new(key, session, KeyGeneration(0), 2),
            session,
            policy,
        );
        tunnel
            .transport
            .set_remote(server_transport.local_addr().expect("server address"));
        assert_eq!(
            tunnel.send_keepalive(),
            Err(super::EncryptedTunnelError::KeyRotationRequired(
                RotationReason::Counter
            ))
        );
    }
}
