//! Unix Domain Socket server for the Rust Core management plane.

use std::{
    io,
    io::{Read, Write},
    path::{Path, PathBuf},
    time::SystemTime,
};

use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};

const IPC_IO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

use crate::{MAX_MANAGEMENT_FRAME_SIZE, ManagementRequest, ManagementService};

/// Single-request Unix IPC server for the Rust Core.
pub struct UnixManagementServer {
    listener: UnixListener,
    socket_path: PathBuf,
    service: ManagementService,
}

impl UnixManagementServer {
    /// Binds a local Unix socket to the explicit management path.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the path cannot be removed or bound.
    pub fn bind(path: impl AsRef<Path>, service: ManagementService) -> io::Result<Self> {
        let socket_path = path.as_ref().to_path_buf();
        match std::fs::remove_file(&socket_path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let listener = UnixListener::bind(&socket_path)?;
        std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600))?;
        Ok(Self {
            listener,
            socket_path,
            service,
        })
    }

    /// Accepts and handles one request, then returns to the caller.
    ///
    /// # Errors
    ///
    /// Returns an I/O error for transport failures. Malformed requests are
    /// rejected by closing only the current connection.
    pub fn serve_once(&mut self) -> io::Result<()> {
        let (mut stream, _) = self.listener.accept()?;
        stream.set_read_timeout(Some(IPC_IO_TIMEOUT))?;
        stream.set_write_timeout(Some(IPC_IO_TIMEOUT))?;
        let Ok(frame) = read_frame(&mut stream) else {
            return Ok(());
        };
        let Ok(request) = ManagementRequest::decode(&frame) else {
            return Ok(());
        };
        let response = self.service.handle(&request, SystemTime::now());
        let encoded = response.encode().map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "response exceeds IPC limit")
        })?;
        stream.write_all(&encoded)
    }
}

impl Drop for UnixManagementServer {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

fn read_frame(stream: &mut UnixStream) -> io::Result<Vec<u8>> {
    let mut prefix = [0; 4];
    stream.read_exact(&mut prefix)?;
    let length = u32::from_be_bytes(prefix) as usize;
    if length > MAX_MANAGEMENT_FRAME_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "IPC frame too large",
        ));
    }
    let mut frame = vec![0; 4 + length];
    frame[..4].copy_from_slice(&prefix);
    stream.read_exact(&mut frame[4..])?;
    Ok(frame)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::{
        io::{Read, Write},
        os::unix::net::UnixStream,
    };

    use super::UnixManagementServer;
    use crate::{ManagementRequest, ManagementService, Metrics, OPERATION_GET_HEALTH};

    #[test]
    fn serves_health_request_over_unix_socket() {
        let path =
            std::env::temp_dir().join(format!("gsm-tunnel-test-{}.sock", std::process::id()));
        let mut server =
            UnixManagementServer::bind(&path, ManagementService::new(4, Metrics::default()))
                .unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let handle = std::thread::spawn(move || server.serve_once());
        let mut client = UnixStream::connect(&path).unwrap();
        let request = ManagementRequest {
            version: 1,
            request_id: 9,
            operation: OPERATION_GET_HEALTH,
            payload: Vec::new(),
        };
        client.write_all(&request.encode().unwrap()).unwrap();
        let mut prefix = [0; 4];
        client.read_exact(&mut prefix).unwrap();
        let response_length = u32::from_be_bytes(prefix) as usize;
        let mut response = vec![0; 4 + response_length];
        response[..4].copy_from_slice(&prefix);
        client.read_exact(&mut response[4..]).unwrap();
        let decoded = crate::ManagementResponse::decode(&response).unwrap();
        assert_eq!(decoded.request_id, 9);
        assert_eq!(decoded.status, 503);
        assert_eq!(decoded.payload, b"uninitialized");
        handle.join().unwrap().unwrap();
    }
}
