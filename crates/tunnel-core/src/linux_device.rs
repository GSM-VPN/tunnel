#![cfg(target_os = "linux")]
#![allow(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]

use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;

use crate::{DeviceError, TunnelDevice};

const IFNAMSIZ: usize = 16;
const IFF_TUN: libc::c_short = 0x0001;
const IFF_NO_PI: libc::c_short = 0x1000;

#[repr(C)]
struct IfReq {
    name: [libc::c_char; IFNAMSIZ],
    flags: libc::c_short,
}

/// Linux TUN device backed by `/dev/net/tun`.
pub struct LinuxTunDevice {
    file: Option<File>,
    name: String,
    mtu: usize,
}

impl LinuxTunDevice {
    /// Creates and attaches a TUN device without packet-information headers.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError::Io`] when the device cannot be opened or the
    /// kernel rejects the TUN ioctl.
    pub fn create(requested_name: Option<&str>, mtu: usize) -> Result<Self, DeviceError> {
        if mtu == 0 {
            return Err(DeviceError::Io(std::io::ErrorKind::InvalidInput));
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/net/tun")
            .map_err(|error| DeviceError::Io(error.kind()))?;

        let requested_name = requested_name.unwrap_or("gsm0");
        let name = CString::new(requested_name)
            .map_err(|_| DeviceError::Io(std::io::ErrorKind::InvalidInput))?;
        let bytes = name.as_bytes_with_nul();
        if bytes.len() > IFNAMSIZ {
            return Err(DeviceError::Io(std::io::ErrorKind::InvalidInput));
        }

        let mut request = IfReq {
            name: [0; IFNAMSIZ],
            flags: IFF_TUN | IFF_NO_PI,
        };
        for (destination, source) in request.name.iter_mut().zip(bytes) {
            *destination = *source as libc::c_char;
        }

        // SAFETY: `request` has the kernel-defined ifreq prefix layout and
        // remains valid for the duration of the ioctl call.
        let result = unsafe { libc::ioctl(file.as_raw_fd(), libc::TUNSETIFF as _, &request) };
        if result < 0 {
            let error = std::io::Error::last_os_error();
            return Err(DeviceError::Io(error.kind()));
        }

        let actual_name = request
            .name
            .iter()
            .take_while(|byte| **byte != 0)
            .map(|byte| *byte as u8)
            .collect::<Vec<_>>();
        let actual_name = String::from_utf8(actual_name)
            .map_err(|_| DeviceError::Io(std::io::ErrorKind::InvalidData))?;

        Ok(Self {
            file: Some(file),
            name: actual_name,
            mtu,
        })
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
}

impl TunnelDevice for LinuxTunDevice {
    fn mtu(&self) -> usize {
        self.mtu
    }

    fn read_packet(&mut self, buffer: &mut [u8]) -> Result<usize, DeviceError> {
        let file = self.file.as_mut().ok_or(DeviceError::Closed)?;
        file.read(buffer)
            .map_err(|error| DeviceError::Io(error.kind()))
    }

    fn write_packet(&mut self, packet: &[u8]) -> Result<usize, DeviceError> {
        if packet.len() > self.mtu {
            return Err(DeviceError::PacketTooLarge {
                actual: packet.len(),
                mtu: self.mtu,
            });
        }
        let file = self.file.as_mut().ok_or(DeviceError::Closed)?;
        file.write(packet)
            .map_err(|error| DeviceError::Io(error.kind()))
    }

    fn close(&mut self) -> Result<(), DeviceError> {
        self.file.take();
        Ok(())
    }
}
