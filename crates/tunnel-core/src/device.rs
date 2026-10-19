use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

/// Errors returned by a tunnel device.
#[derive(Debug, Eq, PartialEq)]
pub enum DeviceError {
    Closed,
    WouldBlock,
    PacketTooLarge { actual: usize, mtu: usize },
    BufferTooSmall { buffer: usize, packet: usize },
    Poisoned,
    Io(std::io::ErrorKind),
}

/// Common packet I/O contract for TUN and test devices.
pub trait TunnelDevice {
    fn mtu(&self) -> usize;

    /// Reads one packet into `buffer`.
    ///
    /// # Errors
    ///
    /// Returns a [`DeviceError`] if the device is closed, has no packet ready,
    /// or the buffer cannot hold the next packet.
    fn read_packet(&mut self, buffer: &mut [u8]) -> Result<usize, DeviceError>;

    /// Writes one packet to the device.
    ///
    /// # Errors
    ///
    /// Returns a [`DeviceError`] if the device is closed or the packet exceeds
    /// the configured MTU.
    fn write_packet(&mut self, packet: &[u8]) -> Result<usize, DeviceError>;

    /// Closes the device and releases its logical endpoint.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError::Poisoned`] if the device state lock is invalid.
    fn close(&mut self) -> Result<(), DeviceError>;
}

struct MemoryState {
    mtu: usize,
    queue: VecDeque<Vec<u8>>,
    closed: bool,
}

/// In-memory endpoint used for deterministic device and tunnel tests.
pub struct MemoryDevice {
    input: Arc<Mutex<MemoryState>>,
    output: Arc<Mutex<MemoryState>>,
}

impl MemoryDevice {
    /// Creates two connected memory endpoints with the same MTU.
    #[must_use]
    pub fn pair(mtu: usize) -> (Self, Self) {
        let left = Arc::new(Mutex::new(MemoryState {
            mtu,
            queue: VecDeque::new(),
            closed: false,
        }));
        let right = Arc::new(Mutex::new(MemoryState {
            mtu,
            queue: VecDeque::new(),
            closed: false,
        }));
        (
            Self {
                input: Arc::clone(&left),
                output: Arc::clone(&right),
            },
            Self {
                input: right,
                output: left,
            },
        )
    }

    fn lock(
        state: &Mutex<MemoryState>,
    ) -> Result<std::sync::MutexGuard<'_, MemoryState>, DeviceError> {
        state.lock().map_err(|_| DeviceError::Poisoned)
    }
}

impl TunnelDevice for MemoryDevice {
    fn mtu(&self) -> usize {
        self.input.lock().map_or(0, |state| state.mtu)
    }

    fn read_packet(&mut self, buffer: &mut [u8]) -> Result<usize, DeviceError> {
        let mut state = Self::lock(&self.input)?;
        if state.closed {
            return Err(DeviceError::Closed);
        }
        let packet = state.queue.front().ok_or(DeviceError::WouldBlock)?;
        if buffer.len() < packet.len() {
            return Err(DeviceError::BufferTooSmall {
                buffer: buffer.len(),
                packet: packet.len(),
            });
        }
        let packet = state.queue.pop_front().ok_or(DeviceError::WouldBlock)?;
        buffer[..packet.len()].copy_from_slice(&packet);
        Ok(packet.len())
    }

    fn write_packet(&mut self, packet: &[u8]) -> Result<usize, DeviceError> {
        if Self::lock(&self.input)?.closed {
            return Err(DeviceError::Closed);
        }
        let mut state = Self::lock(&self.output)?;
        if state.closed {
            return Err(DeviceError::Closed);
        }
        if packet.len() > state.mtu {
            return Err(DeviceError::PacketTooLarge {
                actual: packet.len(),
                mtu: state.mtu,
            });
        }
        state.queue.push_back(packet.to_vec());
        Ok(packet.len())
    }

    fn close(&mut self) -> Result<(), DeviceError> {
        let mut input = Self::lock(&self.input)?;
        input.closed = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{DeviceError, MemoryDevice, TunnelDevice};

    #[test]
    fn exchanges_packets_between_endpoints() {
        let (mut left, mut right) = MemoryDevice::pair(1_400);
        assert_eq!(left.write_packet(b"hello"), Ok(5));
        let mut buffer = [0; 1_400];
        assert_eq!(right.read_packet(&mut buffer), Ok(5));
        assert_eq!(&buffer[..5], b"hello");
        assert_eq!(right.write_packet(b"world"), Ok(5));
        assert_eq!(left.read_packet(&mut buffer), Ok(5));
        assert_eq!(&buffer[..5], b"world");
    }

    #[test]
    fn rejects_oversized_packets() {
        let (mut left, _) = MemoryDevice::pair(4);
        assert_eq!(
            left.write_packet(b"12345"),
            Err(DeviceError::PacketTooLarge { actual: 5, mtu: 4 })
        );
    }

    #[test]
    fn rejects_small_read_buffers_without_consuming_packet() {
        let (mut left, mut right) = MemoryDevice::pair(16);
        left.write_packet(b"packet").expect("packet fits");
        let mut small = [0; 2];
        assert_eq!(
            right.read_packet(&mut small),
            Err(DeviceError::BufferTooSmall {
                buffer: 2,
                packet: 6
            })
        );
        let mut enough = [0; 16];
        assert_eq!(right.read_packet(&mut enough), Ok(6));
    }

    #[test]
    fn reports_empty_queue_as_would_block() {
        let (_, mut right) = MemoryDevice::pair(16);
        let mut buffer = [0; 16];
        assert_eq!(right.read_packet(&mut buffer), Err(DeviceError::WouldBlock));
    }

    #[test]
    fn rejects_io_after_close() {
        let (mut left, mut right) = MemoryDevice::pair(16);
        left.close().expect("close succeeds");
        assert_eq!(left.write_packet(b"x"), Err(DeviceError::Closed));
        right.close().expect("close succeeds");
        let mut buffer = [0; 16];
        assert_eq!(right.read_packet(&mut buffer), Err(DeviceError::Closed));
    }
}
