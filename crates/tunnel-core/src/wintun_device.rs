#![cfg(target_os = "windows")]
#![allow(unsafe_code)]

use std::ffi::OsStr;
use std::sync::Arc;

use crate::{DeviceError, TunnelDevice};

const MAX_WINTUN_PACKET: usize = u16::MAX as usize;

/// Windows TUN device backed by a Wintun adapter and packet session.
pub struct WintunDevice {
    adapter: Option<Arc<wintun::Adapter>>,
    session: Option<Arc<wintun::Session>>,
    mtu: usize,
}

impl WintunDevice {
    /// Loads `wintun.dll`, creates an adapter, and starts its packet session.
    ///
    /// The caller is responsible for running this operation with the Windows
    /// privileges required to install or open a Wintun adapter. The DLL path
    /// is explicit so the deployment layer can control which signed binary is
    /// loaded.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] when the DLL cannot be loaded, the adapter or
    /// session cannot be created, the MTU cannot be applied, or an input
    /// value is outside Wintun's supported range.
    pub fn create(
        dll_path: impl AsRef<OsStr>,
        adapter_name: &str,
        tunnel_type: &str,
        mtu: usize,
        ring_capacity: u32,
    ) -> Result<Self, DeviceError> {
        validate_mtu(mtu)?;

        // SAFETY: loading a DLL is intentionally an explicit deployment boundary;
        // the caller supplies the path to the signed Wintun binary.
        let wintun = unsafe { wintun::load_from_path(dll_path) }.map_err(map_error)?;
        let adapter =
            wintun::Adapter::create(&wintun, adapter_name, tunnel_type, None).map_err(map_error)?;
        adapter.set_mtu(mtu).map_err(map_error)?;
        let session = adapter.start_session(ring_capacity).map_err(map_error)?;

        Ok(Self {
            adapter: Some(adapter),
            session: Some(Arc::new(session)),
            mtu,
        })
    }

    /// Returns the Windows adapter's friendly name.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError::Closed`] after [`TunnelDevice::close`] or a
    /// mapped Wintun error when Windows cannot read the adapter name.
    pub fn adapter_name(&self) -> Result<String, DeviceError> {
        self.adapter
            .as_ref()
            .ok_or(DeviceError::Closed)?
            .get_name()
            .map_err(map_error)
    }

    /// Returns the Wintun adapter's current MTU.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError::Closed`] after [`TunnelDevice::close`] or a
    /// mapped Wintun error when Windows cannot read the adapter MTU.
    pub fn adapter_mtu(&self) -> Result<usize, DeviceError> {
        self.adapter
            .as_ref()
            .ok_or(DeviceError::Closed)?
            .get_mtu()
            .map_err(map_error)
    }
}

impl TunnelDevice for WintunDevice {
    fn mtu(&self) -> usize {
        self.mtu
    }

    fn read_packet(&mut self, buffer: &mut [u8]) -> Result<usize, DeviceError> {
        let session = self.session.as_ref().ok_or(DeviceError::Closed)?;
        let Some(packet) = session.try_receive().map_err(map_error)? else {
            return Err(DeviceError::WouldBlock);
        };

        let packet = packet.bytes();
        if packet.len() > self.mtu {
            return Err(DeviceError::PacketTooLarge {
                actual: packet.len(),
                mtu: self.mtu,
            });
        }
        if buffer.len() < packet.len() {
            return Err(DeviceError::BufferTooSmall {
                buffer: buffer.len(),
                packet: packet.len(),
            });
        }
        buffer[..packet.len()].copy_from_slice(packet);
        Ok(packet.len())
    }

    fn write_packet(&mut self, packet: &[u8]) -> Result<usize, DeviceError> {
        if packet.len() > self.mtu {
            return Err(DeviceError::PacketTooLarge {
                actual: packet.len(),
                mtu: self.mtu,
            });
        }
        let session = self.session.as_ref().ok_or(DeviceError::Closed)?;
        let packet_size = u16::try_from(packet.len())
            .map_err(|_| DeviceError::Io(std::io::ErrorKind::InvalidInput))?;
        let mut writable = session
            .allocate_send_packet(packet_size)
            .map_err(map_error)?;
        writable.bytes_mut().copy_from_slice(packet);
        session.send_packet(writable);
        Ok(packet.len())
    }

    fn close(&mut self) -> Result<(), DeviceError> {
        let Some(session) = self.session.take() else {
            return Ok(());
        };
        session.shutdown().map_err(map_error)?;
        drop(session);
        let Some(adapter) = self.adapter.take() else {
            return Ok(());
        };
        let adapter =
            Arc::try_unwrap(adapter).map_err(|_| DeviceError::Io(std::io::ErrorKind::Other))?;
        adapter.delete().map_err(map_error)?;
        Ok(())
    }
}

impl Drop for WintunDevice {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

fn validate_mtu(mtu: usize) -> Result<(), DeviceError> {
    if mtu == 0 || mtu > MAX_WINTUN_PACKET {
        return Err(DeviceError::Io(std::io::ErrorKind::InvalidInput));
    }
    Ok(())
}

fn map_error(error: wintun::Error) -> DeviceError {
    match error {
        wintun::Error::Io(error) => DeviceError::Io(error.kind()),
        _ => DeviceError::Io(std::io::ErrorKind::Other),
    }
}

#[cfg(test)]
mod tests {
    use super::validate_mtu;
    use crate::DeviceError;

    #[test]
    fn rejects_mtu_values_that_wintun_packet_sizes_cannot_represent() {
        assert_eq!(
            validate_mtu(0),
            Err(DeviceError::Io(std::io::ErrorKind::InvalidInput))
        );
        assert_eq!(
            validate_mtu(u16::MAX as usize + 1),
            Err(DeviceError::Io(std::io::ErrorKind::InvalidInput))
        );
        assert!(validate_mtu(1_400).is_ok());
    }
}
