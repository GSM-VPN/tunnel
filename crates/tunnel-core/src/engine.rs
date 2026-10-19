use crate::{
    DeviceError, MAX_PACKET_SIZE, Metrics, PROTOCOL_VERSION, PacketType, ProtocolError,
    SequenceNumber, SessionId, TransportError, TunnelDevice, TunnelHeader, TunnelPacket,
    UdpTransport,
};

/// Errors returned by the unencrypted research tunnel.
#[derive(Debug, Eq, PartialEq)]
pub enum TunnelError {
    Device(DeviceError),
    Protocol(ProtocolError),
    Transport(TransportError),
    UnexpectedSession {
        expected: SessionId,
        actual: SessionId,
    },
    UnexpectedPacketType(PacketType),
    SequenceExhausted,
}

impl From<DeviceError> for TunnelError {
    fn from(error: DeviceError) -> Self {
        Self::Device(error)
    }
}

impl From<ProtocolError> for TunnelError {
    fn from(error: ProtocolError) -> Self {
        Self::Protocol(error)
    }
}

impl From<TransportError> for TunnelError {
    fn from(error: TransportError) -> Self {
        Self::Transport(error)
    }
}

/// Research-only unencrypted packet path used to validate tunnel wiring.
///
/// This type must not be used on a public or untrusted network. Encryption and
/// authenticated session establishment are implemented in later phases.
pub struct PlainTunnel<D> {
    pub(crate) device: D,
    pub(crate) transport: UdpTransport,
    session_id: SessionId,
    next_sequence: u64,
    metrics: Option<Metrics>,
}

impl<D: TunnelDevice> PlainTunnel<D> {
    #[must_use]
    pub fn new(device: D, transport: UdpTransport, session_id: SessionId) -> Self {
        Self {
            device,
            transport,
            session_id,
            next_sequence: 0,
            metrics: None,
        }
    }

    /// Attaches optional secret-free counters to this tunnel.
    #[must_use]
    pub fn with_metrics(mut self, metrics: Metrics) -> Self {
        self.metrics = Some(metrics);
        self
    }

    fn record_packet_error(&self) {
        if let Some(metrics) = &self.metrics {
            metrics.record_packet_error();
        }
    }

    /// Reads one inner packet, wraps it in a `TransportData` packet, and sends it.
    ///
    /// # Errors
    ///
    /// Returns a device, protocol, or transport error when any stage fails.
    pub fn send_next(&mut self) -> Result<usize, TunnelError> {
        let result = (|| {
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
            let packet = TunnelPacket::new(header, payload)?;
            let encoded = packet.encode()?;
            let sent = self.transport.send(&encoded)?;
            self.next_sequence = self
                .next_sequence
                .checked_add(1)
                .ok_or(TunnelError::SequenceExhausted)?;
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

    /// Receives one datagram, validates its session and type, and writes its payload.
    ///
    /// # Errors
    ///
    /// Returns a device, protocol, or transport error, or rejects an unexpected
    /// session and packet type without writing to the device.
    pub fn receive_next(&mut self) -> Result<usize, TunnelError> {
        let result = (|| {
            let mut encoded = vec![0; MAX_PACKET_SIZE];
            let (length, _) = self.transport.receive(&mut encoded)?;
            let packet = TunnelPacket::decode(&encoded[..length])?;
            if packet.header.session_id != self.session_id {
                return Err(TunnelError::UnexpectedSession {
                    expected: self.session_id,
                    actual: packet.header.session_id,
                });
            }
            if packet.header.packet_type != PacketType::TransportData {
                return Err(TunnelError::UnexpectedPacketType(packet.header.packet_type));
            }
            let written = self.device.write_packet(&packet.payload)?;
            if let Some(metrics) = &self.metrics {
                metrics.record_rx(written as u64);
            }
            Ok(written)
        })();
        if result.is_err() {
            self.record_packet_error();
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::{PlainTunnel, TunnelError};
    use crate::{MemoryDevice, Metrics, SessionId, TunnelDevice, UdpTransport};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::Duration;

    fn loopback() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
    }

    #[test]
    fn moves_a_packet_from_device_to_device_over_udp() {
        let (mut client_device, server_device) = MemoryDevice::pair(1_400);
        let mut client_application = client_device.clone();
        client_device
            .inject(b"inner packet")
            .expect("application injects packet");
        let client_transport = UdpTransport::bind(loopback(), 1_400).expect("client binds");
        let server_transport = UdpTransport::bind(loopback(), 1_400).expect("server binds");
        let client_address = client_transport.local_addr().expect("client address");
        let server_address = server_transport.local_addr().expect("server address");
        let session = SessionId::new(7).expect("session ID");
        let client_metrics = Metrics::default();
        let server_metrics = Metrics::default();
        let mut client = PlainTunnel::new(client_device, client_transport, session);
        let mut server = PlainTunnel::new(server_device, server_transport, session)
            .with_metrics(server_metrics.clone());
        client = client.with_metrics(client_metrics.clone());
        client.transport.set_remote(server_address);
        server.transport.set_remote(client_address);
        client.send_next().expect("client sends");
        server.receive_next().expect("server receives");
        assert_eq!(client_metrics.snapshot().tx_packets, 1);
        assert_eq!(server_metrics.snapshot().rx_packets, 1);
        let mut received = [0; 1_400];
        assert_eq!(client_application.read_packet(&mut received), Ok(12));
        assert_eq!(&received[..12], b"inner packet");
    }

    #[test]
    fn rejects_a_packet_from_another_session_without_writing() {
        let (mut sender_device, receiver_device) = MemoryDevice::pair(1_400);
        sender_device.inject(b"packet").expect("packet injects");
        let sender_transport = UdpTransport::bind(loopback(), 1_400).expect("sender binds");
        let receiver_transport = UdpTransport::bind(loopback(), 1_400).expect("receiver binds");
        let receiver_address = receiver_transport.local_addr().expect("receiver address");
        let sender_address = sender_transport.local_addr().expect("sender address");
        let mut sender = PlainTunnel::new(
            sender_device,
            sender_transport,
            SessionId::new(1).expect("session ID"),
        );
        let mut receiver = PlainTunnel::new(
            receiver_device,
            receiver_transport,
            SessionId::new(2).expect("session ID"),
        );
        sender.transport.set_remote(receiver_address);
        receiver.transport.set_remote(sender_address);
        sender.send_next().expect("packet sends");
        receiver
            .transport
            .set_read_timeout(Some(Duration::from_millis(100)))
            .expect("timeout configures");
        assert!(matches!(
            receiver.receive_next(),
            Err(TunnelError::UnexpectedSession { .. })
        ));
    }
}
