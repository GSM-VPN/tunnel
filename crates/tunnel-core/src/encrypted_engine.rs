use crate::{
    DeviceError, MAX_PACKET_SIZE, PROTOCOL_VERSION, PacketType, ProtocolError, SequenceNumber,
    SessionCipher, SessionId, TransportError, TunnelDevice, TunnelHeader, TunnelPacket,
    UdpTransport,
};

/// Errors returned by the authenticated tunnel data path.
#[derive(Debug, Eq, PartialEq)]
pub enum EncryptedTunnelError {
    Device(DeviceError),
    Protocol(ProtocolError),
    Crypto(crate::CryptoError),
    Transport(TransportError),
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
        Self {
            device,
            transport,
            sender,
            receiver,
            session_id,
            next_sequence: 0,
        }
    }

    /// Encrypts one device packet and sends it as an authenticated datagram.
    ///
    /// # Errors
    ///
    /// Returns a device, encryption, protocol, or transport error.
    pub fn send_next(&mut self) -> Result<usize, EncryptedTunnelError> {
        let mut payload = vec![0; self.device.mtu()];
        let length = self.device.read_packet(&mut payload)?;
        payload.truncate(length);
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
        self.next_sequence = self.next_sequence.saturating_add(1);
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
        Ok(self.device.write_packet(&plaintext)?)
    }
}

#[cfg(test)]
mod tests {
    use super::EncryptedTunnel;
    use crate::{
        KeyGeneration, MemoryDevice, SessionCipher, SessionId, TunnelDevice, UdpTransport,
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
    }
}
