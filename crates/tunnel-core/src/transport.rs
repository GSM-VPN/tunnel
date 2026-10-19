use std::collections::VecDeque;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

/// Errors returned by the UDP transport.
#[derive(Debug, Eq, PartialEq)]
pub enum TransportError {
    Closed,
    MissingRemoteEndpoint,
    UnexpectedRemoteEndpoint {
        expected: SocketAddr,
        actual: SocketAddr,
    },
    PacketTooLarge {
        actual: usize,
        maximum: usize,
    },
    Io(io::ErrorKind),
}

/// Queue admission errors for an asynchronous UDP adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DatagramQueueError {
    InvalidLimits,
    PacketLimit,
    ByteLimit,
}

/// Bounded ownership queue for datagrams.
pub struct DatagramQueue {
    max_packets: usize,
    max_bytes: usize,
    bytes: usize,
    packets: VecDeque<Vec<u8>>,
}

impl DatagramQueue {
    /// Creates a queue with positive packet-count and byte limits.
    ///
    /// # Errors
    ///
    /// Returns [`DatagramQueueError::InvalidLimits`] when either limit is zero.
    pub fn new(max_packets: usize, max_bytes: usize) -> Result<Self, DatagramQueueError> {
        if max_packets == 0 || max_bytes == 0 {
            return Err(DatagramQueueError::InvalidLimits);
        }
        Ok(Self {
            max_packets,
            max_bytes,
            bytes: 0,
            packets: VecDeque::with_capacity(max_packets),
        })
    }

    /// Moves one datagram into the queue without copying it.
    ///
    /// # Errors
    ///
    /// Returns a packet or byte limit error when admitting the datagram would
    /// exceed the configured queue bounds.
    pub fn push(&mut self, packet: Vec<u8>) -> Result<(), DatagramQueueError> {
        if self.packets.len() >= self.max_packets {
            return Err(DatagramQueueError::PacketLimit);
        }
        if packet.len() > self.max_bytes.saturating_sub(self.bytes) {
            return Err(DatagramQueueError::ByteLimit);
        }
        self.bytes += packet.len();
        self.packets.push_back(packet);
        Ok(())
    }

    /// Returns the oldest datagram and its owned allocation.
    pub fn pop(&mut self) -> Option<Vec<u8>> {
        let packet = self.packets.pop_front()?;
        self.bytes -= packet.len();
        Some(packet)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.packets.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.packets.is_empty()
    }

    #[must_use]
    pub fn bytes(&self) -> usize {
        self.bytes
    }
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

    /// Reports whether `close` has already been called.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.socket.is_none()
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
        let (length, actual) = socket
            .recv_from(buffer)
            .map_err(|error| TransportError::Io(error.kind()))?;
        if let Some(expected) = self.remote
            && actual != expected
        {
            return Err(TransportError::UnexpectedRemoteEndpoint { expected, actual });
        }
        Ok((length, actual))
    }

    /// Closes the socket. Calling close more than once is harmless.
    pub fn close(&mut self) {
        self.socket.take();
        self.remote = None;
    }
}

#[cfg(test)]
mod tests {
    use super::{DatagramQueue, DatagramQueueError, TransportError, UdpTransport};
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
        assert!(!transport.is_closed());
        transport.close();
        assert!(transport.is_closed());
        assert_eq!(transport.send(b"hello"), Err(TransportError::Closed));
        let mut buffer = [0; 1_400];
        assert_eq!(transport.receive(&mut buffer), Err(TransportError::Closed));
    }

    #[test]
    fn rejects_datagrams_from_an_unexpected_remote_endpoint() {
        let sender = UdpTransport::bind(loopback(), 1_400).expect("sender binds");
        let unexpected = UdpTransport::bind(loopback(), 1_400).expect("unexpected binds");
        let mut receiver = UdpTransport::bind(loopback(), 1_400).expect("receiver binds");
        receiver.set_remote(unexpected.local_addr().expect("unexpected address"));

        sender
            .socket
            .as_ref()
            .expect("sender socket")
            .send_to(b"spoofed", receiver.local_addr().expect("receiver address"))
            .expect("datagram sends");

        let mut buffer = [0; 1_400];
        assert_eq!(
            receiver.receive(&mut buffer),
            Err(TransportError::UnexpectedRemoteEndpoint {
                expected: unexpected.local_addr().expect("unexpected address"),
                actual: sender.local_addr().expect("sender address"),
            })
        );
    }

    #[test]
    fn bounds_queue_packets_and_bytes_without_copying_buffers() {
        assert!(matches!(
            DatagramQueue::new(0, 1),
            Err(DatagramQueueError::InvalidLimits)
        ));
        let mut queue = DatagramQueue::new(2, 5).expect("queue creates");
        let packet = vec![1, 2, 3];
        let pointer = packet.as_ptr();
        queue.push(packet).expect("packet enqueues");
        assert_eq!(queue.bytes(), 3);
        let dequeued = queue.pop().expect("packet dequeues");
        assert_eq!(dequeued.as_ptr(), pointer);
        assert!(queue.is_empty());
        queue.push(vec![1, 2, 3, 4]).expect("packet enqueues");
        assert_eq!(queue.push(vec![5, 6]), Err(DatagramQueueError::ByteLimit));
        queue.push(vec![5]).expect("packet enqueues");
        assert_eq!(queue.push(vec![9]), Err(DatagramQueueError::PacketLimit));
    }
}
