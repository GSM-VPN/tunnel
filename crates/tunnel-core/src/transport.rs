use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

/// Errors returned by the UDP transport.
#[derive(Debug, Eq, PartialEq)]
pub enum TransportError {
    Closed,
    MissingRemoteEndpoint,
    PacketTooLarge { actual: usize, maximum: usize },
    Io(io::ErrorKind),
}

/// UDP datagram transport used by the tunnel protocol.
pub struct UdpTransport {
    socket: Option<UdpSocket>,
    remote: Option<SocketAddr>,
    maximum_datagram: usize,
}

impl UdpTransport {
    /// Binds a UDP socket to a local endpoint.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Io`] if the socket cannot be bound.
    pub fn bind(local: SocketAddr, maximum_datagram: usize) -> Result<Self, TransportError> {
        let socket = UdpSocket::bind(local).map_err(|error| TransportError::Io(error.kind()))?;
        Ok(Self {
            socket: Some(socket),
            remote: None,
            maximum_datagram,
        })
    }

    #[must_use]
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.socket
            .as_ref()
            .and_then(|socket| socket.local_addr().ok())
    }

    /// Sets the remote endpoint used by [`Self::send`].
    pub fn set_remote(&mut self, remote: SocketAddr) {
        self.remote = Some(remote);
    }

    /// Configures the receive timeout.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Closed`] if the socket was closed, or
    /// [`TransportError::Io`] if the operating system rejects the timeout.
    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> Result<(), TransportError> {
        let socket = self.socket.as_ref().ok_or(TransportError::Closed)?;
        socket
            .set_read_timeout(timeout)
            .map_err(|error| TransportError::Io(error.kind()))
    }

    /// Sends one datagram to the configured remote endpoint.
    ///
    /// # Errors
    ///
    /// Returns an error when no endpoint is configured, the datagram is too
    /// large, the transport is closed, or the OS rejects the send.
    pub fn send(&self, datagram: &[u8]) -> Result<usize, TransportError> {
        if datagram.len() > self.maximum_datagram {
            return Err(TransportError::PacketTooLarge {
                actual: datagram.len(),
                maximum: self.maximum_datagram,
            });
        }
        let socket = self.socket.as_ref().ok_or(TransportError::Closed)?;
        let remote = self.remote.ok_or(TransportError::MissingRemoteEndpoint)?;
        socket
            .send_to(datagram, remote)
            .map_err(|error| TransportError::Io(error.kind()))
    }

    /// Receives one datagram and returns its sender endpoint.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Closed`] if the transport is closed or
    /// [`TransportError::Io`] for timeout and other socket errors.
    pub fn receive(&self, buffer: &mut [u8]) -> Result<(usize, SocketAddr), TransportError> {
        let socket = self.socket.as_ref().ok_or(TransportError::Closed)?;
        socket
            .recv_from(buffer)
            .map_err(|error| TransportError::Io(error.kind()))
    }

    /// Closes the socket. Calling close more than once is harmless.
    pub fn close(&mut self) {
        self.socket.take();
        self.remote = None;
    }
}

#[cfg(test)]
mod tests {
    use super::{TransportError, UdpTransport};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::Duration;

    fn loopback() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
    }

    #[test]
    fn sends_and_receives_datagrams() {
        let mut sender = UdpTransport::bind(loopback(), 1_400).expect("sender binds");
        let receiver = UdpTransport::bind(loopback(), 1_400).expect("receiver binds");
        sender.set_remote(receiver.local_addr().expect("receiver has address"));
        sender.send(b"hello").expect("datagram sends");

        let mut buffer = [0; 1_400];
        let (length, source) = receiver.receive(&mut buffer).expect("datagram receives");
        assert_eq!(&buffer[..length], b"hello");
        assert_eq!(source, sender.local_addr().expect("sender has address"));
    }

    #[test]
    fn rejects_datagrams_without_a_remote_endpoint() {
        let sender = UdpTransport::bind(loopback(), 1_400).expect("sender binds");
        assert_eq!(
            sender.send(b"hello"),
            Err(TransportError::MissingRemoteEndpoint)
        );
    }

    #[test]
    fn rejects_datagrams_above_the_configured_limit() {
        let sender = UdpTransport::bind(loopback(), 4).expect("sender binds");
        assert_eq!(
            sender.send(b"12345"),
            Err(TransportError::PacketTooLarge {
                actual: 5,
                maximum: 4
            })
        );
    }

    #[test]
    fn reports_receive_timeout() {
        let receiver = UdpTransport::bind(loopback(), 1_400).expect("receiver binds");
        receiver
            .set_read_timeout(Some(Duration::from_millis(1)))
            .expect("timeout configures");
        let mut buffer = [0; 1_400];
        assert_eq!(
            receiver.receive(&mut buffer),
            Err(TransportError::Io(std::io::ErrorKind::WouldBlock))
        );
    }

    #[test]
    fn rejects_operations_after_close() {
        let mut transport = UdpTransport::bind(loopback(), 1_400).expect("socket binds");
        transport.close();
        assert_eq!(transport.send(b"hello"), Err(TransportError::Closed));
        let mut buffer = [0; 1_400];
        assert_eq!(transport.receive(&mut buffer), Err(TransportError::Closed));
    }
}
