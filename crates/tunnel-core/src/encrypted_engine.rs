use crate::protocol::HEADER_SIZE;
use crate::{AEAD_TAG_SIZE, InnerIpPacketError, validate_inner_ip_packet};
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
    InvalidInnerPacket(InnerIpPacketError),
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

impl From<InnerIpPacketError> for EncryptedTunnelError {
    fn from(error: InnerIpPacketError) -> Self {
        Self::InvalidInnerPacket(error)
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
    inner_packet_mtu: usize,
    dual_stack: bool,
    metrics: Option<crate::Metrics>,
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
        let inner_packet_mtu = device.mtu().saturating_sub(HEADER_SIZE + AEAD_TAG_SIZE);
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
            inner_packet_mtu,
            dual_stack: true,
            metrics: None,
        }
    }

    /// Attaches optional secret-free counters to this tunnel.
    #[must_use]
    pub fn with_metrics(mut self, metrics: crate::Metrics) -> Self {
        self.metrics = Some(metrics);
        self
    }

    fn record_packet_error(&self) {
        if let Some(metrics) = &self.metrics {
            metrics.record_packet_error();
        }
    }

    /// Restricts inner packets to an explicit MTU and address-family policy.
    #[must_use]
    pub fn with_inner_packet_policy(mut self, mtu: usize, dual_stack: bool) -> Self {
        self.inner_packet_mtu = mtu;
        self.dual_stack = dual_stack;
        self
    }

    #[must_use]
    pub const fn transmitted_bytes(&self) -> u64 {
        self.transmitted_bytes
    }

    #[must_use]
    pub const fn key_generation(&self) -> crate::KeyGeneration {
        self.sender.key_generation()
    }

    /// Closes the device and transport, then consumes the tunnel state.
    ///
    /// Consuming the tunnel ensures that session ciphers and their key
    /// material are dropped together with sequence and byte counters after
    /// the endpoints have been closed.
    ///
    /// # Errors
    ///
    /// Returns a device error when the device cannot be closed. The UDP
    /// transport is closed even when the device reports an error.
    pub fn close(mut self) -> Result<(), EncryptedTunnelError> {
        let device_result = self.device.close();
        self.transport.close();
        device_result.map_err(EncryptedTunnelError::from)
    }

    /// Installs new directional keys from an authenticated re-handshake.
    ///
    /// The sender and receiver must move to the same strictly newer
    /// generation. Replay windows, sequence numbers, byte counters, and the
    /// age threshold are reset together so the old generation cannot be
    /// reused.
    ///
    /// # Errors
    ///
    /// Returns a crypto error when the generations are inconsistent or the
    /// requested generation is not newer than the active one.
    pub fn rekey(
        &mut self,
        sender_key: [u8; 32],
        receiver_key: [u8; 32],
        key_generation: crate::KeyGeneration,
    ) -> Result<(), EncryptedTunnelError> {
        if self.sender.key_generation() != self.receiver.key_generation()
            || key_generation.0 <= self.sender.key_generation().0
        {
            return Err(crate::CryptoError::InvalidKeyGeneration.into());
        }
        self.sender.rekey(sender_key, key_generation)?;
        self.receiver.rekey(receiver_key, key_generation)?;
        self.next_sequence = 0;
        self.transmitted_bytes = 0;
        self.started_at = Instant::now();
        Ok(())
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
        let result = (|| {
            self.ensure_rotation_window()?;
            let mut payload = vec![0; self.device.mtu()];
            let length = self.device.read_packet(&mut payload)?;
            payload.truncate(length);
            validate_inner_ip_packet(&payload, self.inner_packet_mtu, self.dual_stack)?;
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
                key_generation: self.sender.key_generation(),
            };
            let packet = self.sender.seal(header, &payload)?;
            let encoded = packet.encode()?;
            let sent = self.transport.send(&encoded)?;
            self.next_sequence = next_sequence;
            self.transmitted_bytes = next_transmitted_bytes;
            if let Some(metrics) = &self.metrics {
                metrics.record_tx(sent as u64);
            }
            Ok(sent)
        })();
        if result.is_err() {
            self.record_packet_error();
        }
        result
    }

    /// Sends an authenticated keepalive without touching the tunnel device.
    ///
    /// # Errors
    ///
    /// Returns an encryption, protocol, or transport error.
    pub fn send_keepalive(&mut self) -> Result<usize, EncryptedTunnelError> {
        self.ensure_rotation_window()?;
        let next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(EncryptedTunnelError::SequenceExhausted)?;
        let header = TunnelHeader {
            version: PROTOCOL_VERSION,
            packet_type: PacketType::Keepalive,
            flags: 0,
            session_id: self.session_id,
            sequence_number: SequenceNumber(self.next_sequence),
            key_generation: self.sender.key_generation(),
        };
        let packet = self.sender.seal(header, &[])?;
        let sent = self.transport.send(&packet.encode()?)?;
        self.next_sequence = next_sequence;
        Ok(sent)
    }

    /// Receives, authenticates, decrypts, and writes one device packet.
    ///
    /// # Errors
    ///
    /// Returns a device, protocol, encryption, or transport error. Failed
    /// authentication never writes plaintext to the device.
    pub fn receive_next(&mut self) -> Result<usize, EncryptedTunnelError> {
        let result = (|| {
            let mut encoded = vec![0; MAX_PACKET_SIZE];
            let (length, _) = self.transport.receive(&mut encoded)?;
            let packet = TunnelPacket::decode(&encoded[..length])?;
            let plaintext = self.receiver.open(&packet)?;
            match packet.header.packet_type {
                PacketType::TransportData => {
                    validate_inner_ip_packet(&plaintext, self.inner_packet_mtu, self.dual_stack)?;
                    let written = self.device.write_packet(&plaintext)?;
                    if let Some(metrics) = &self.metrics {
                        metrics.record_rx(written as u64);
                    }
                    Ok(written)
                }
                PacketType::Keepalive => Ok(0),
                packet_type => Err(EncryptedTunnelError::UnexpectedPacketType(packet_type)),
            }
        })();
        if result.is_err() {
            self.record_packet_error();
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::EncryptedTunnel;
    use crate::{
        DeviceError, KeyGeneration, KeyRotationPolicy, MemoryDevice, Metrics, RotationReason,
        SessionCipher, SessionId, TunnelDevice, UdpTransport, ipv4_header_checksum,
    };
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn loopback() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
    }

    fn ipv4_packet(payload: &[u8]) -> Vec<u8> {
        let mut packet = vec![0; 20 + payload.len()];
        packet[0] = 0x45;
        let length = u16::try_from(packet.len()).expect("test packet fits IPv4 length");
        packet[2..4].copy_from_slice(&length.to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[10, 80, 0, 2]);
        packet[16..20].copy_from_slice(&[1, 1, 1, 1]);
        packet[20..].copy_from_slice(payload);
        let checksum = ipv4_header_checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&checksum.to_be_bytes());
        packet
    }

    #[test]
    fn transfers_an_authenticated_packet_over_udp() {
        let key = [9; 32];
        let session = SessionId::new(8).expect("session ID");
        let (mut client_device, server_device) = MemoryDevice::pair(1_400);
        let mut server_application = server_device.clone();
        let mut client_application = client_device.clone();
        let packet = ipv4_packet(b"encrypted packet");
        client_device.inject(&packet).expect("packet injects");
        let client_transport = UdpTransport::bind(loopback(), 1_400).expect("client binds");
        let server_transport = UdpTransport::bind(loopback(), 1_400).expect("server binds");
        let client_address = client_transport.local_addr().expect("client address");
        let server_address = server_transport.local_addr().expect("server address");
        let sender = SessionCipher::new(key, session, KeyGeneration(0), 1);
        let receiver_cipher = SessionCipher::new(key, session, KeyGeneration(0), 1);
        let client_metrics = Metrics::default();
        let server_metrics = Metrics::default();
        let mut client = EncryptedTunnel::new(
            client_device,
            client_transport,
            sender,
            SessionCipher::new(key, session, KeyGeneration(0), 2),
            session,
        )
        .with_metrics(client_metrics.clone());
        let mut server = EncryptedTunnel::new(
            server_device,
            server_transport,
            SessionCipher::new(key, session, KeyGeneration(0), 2),
            receiver_cipher,
            session,
        )
        .with_metrics(server_metrics.clone());
        client.transport.set_remote(server_address);
        server.transport.set_remote(client_address);
        client.send_next().expect("packet sends");
        server.receive_next().expect("packet receives");
        assert_eq!(client_metrics.snapshot().tx_packets, 1);
        assert_eq!(server_metrics.snapshot().rx_packets, 1);
        let mut output = [0; 1_400];
        assert_eq!(client_application.read_packet(&mut output), Ok(36));
        assert_eq!(&output[..36], packet);
        client.send_keepalive().expect("keepalive sends");
        assert_eq!(server.receive_next(), Ok(0));
        assert_eq!(
            server_application.read_packet(&mut output),
            Err(DeviceError::WouldBlock)
        );
    }

    #[test]
    fn rejects_non_ip_payload_before_encryption() {
        let session = SessionId::new(9).expect("session ID");
        let (mut device, _) = MemoryDevice::pair(1_400);
        device.inject(b"not an IP packet").expect("packet injects");
        let client_transport = UdpTransport::bind(loopback(), 1_400).expect("client binds");
        let server_transport = UdpTransport::bind(loopback(), 1_400).expect("server binds");
        let mut tunnel = EncryptedTunnel::new(
            device,
            client_transport,
            SessionCipher::new([7; 32], session, KeyGeneration(0), 1),
            SessionCipher::new([8; 32], session, KeyGeneration(0), 2),
            session,
        );
        tunnel
            .transport
            .set_remote(server_transport.local_addr().expect("server address"));
        assert!(matches!(
            tunnel.send_next(),
            Err(super::EncryptedTunnelError::InvalidInnerPacket(_))
        ));
    }

    #[test]
    fn closes_device_and_transport_before_discarding_session_state() {
        let session = SessionId::new(15).expect("session ID");
        let (device, _) = MemoryDevice::pair(1_400);
        let mut device_observer = device.clone();
        let transport = UdpTransport::bind(loopback(), 1_400).expect("transport binds");
        let tunnel = EncryptedTunnel::new(
            device,
            transport,
            SessionCipher::new([1; 32], session, KeyGeneration(0), 1),
            SessionCipher::new([2; 32], session, KeyGeneration(0), 2),
            session,
        );

        tunnel.close().expect("tunnel closes");
        let mut buffer = [0; 1_400];
        assert_eq!(
            device_observer.read_packet(&mut buffer),
            Err(DeviceError::Closed)
        );
    }

    #[test]
    fn stops_sending_before_key_rotation_byte_limit() {
        let key = [4; 32];
        let session = SessionId::new(12).expect("session ID");
        let (mut device, _) = MemoryDevice::pair(1_400);
        let packet = ipv4_packet(b"first");
        device.inject(&packet).expect("packet injects");
        let client_transport = UdpTransport::bind(loopback(), 1_400).expect("client binds");
        let server_transport = UdpTransport::bind(loopback(), 1_400).expect("server binds");
        let server_address = server_transport.local_addr().expect("server address");
        let policy = KeyRotationPolicy {
            max_age: std::time::Duration::from_secs(3_600),
            max_bytes: 25,
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
        assert_eq!(tunnel.transmitted_bytes(), 25);
        assert_eq!(
            tunnel.send_next(),
            Err(super::EncryptedTunnelError::KeyRotationRequired(
                RotationReason::Bytes
            ))
        );
    }

    #[test]
    fn rekey_resets_data_counters_and_generation() {
        let session = SessionId::new(14).expect("session ID");
        let (device, _) = MemoryDevice::pair(1_400);
        let client_transport = UdpTransport::bind(loopback(), 1_400).expect("client binds");
        let server_transport = UdpTransport::bind(loopback(), 1_400).expect("server binds");
        let mut tunnel = EncryptedTunnel::new(
            device,
            client_transport,
            SessionCipher::new([1; 32], session, KeyGeneration(0), 1),
            SessionCipher::new([2; 32], session, KeyGeneration(0), 2),
            session,
        );
        tunnel
            .transport
            .set_remote(server_transport.local_addr().expect("server address"));
        tunnel.rekey([3; 32], [4; 32], KeyGeneration(1)).unwrap();
        assert_eq!(tunnel.key_generation(), KeyGeneration(1));
        assert_eq!(tunnel.transmitted_bytes(), 0);
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
