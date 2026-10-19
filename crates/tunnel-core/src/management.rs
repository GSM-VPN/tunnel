//! Versioned control-plane IPC frames shared with the Go controller.

const FRAME_PREFIX: usize = 4;
const REQUEST_HEADER: usize = 2 + 8 + 2 + 4;
const RESPONSE_HEADER: usize = 2 + 8 + 2 + 2 + 4;
pub const MAX_MANAGEMENT_FRAME_SIZE: usize = 1 << 20;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagementRequest {
    pub version: u16,
    pub request_id: u64,
    pub operation: u16,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagementResponse {
    pub version: u16,
    pub request_id: u64,
    pub status: u16,
    pub error_code: u16,
    pub payload: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManagementError {
    FrameTooLarge,
    Truncated,
    LengthMismatch,
    ZeroVersion,
}

impl ManagementRequest {
    /// Encodes a request using the Go controller's big-endian wire format.
    ///
    /// # Errors
    ///
    /// Returns an error when the version is zero or the frame exceeds the
    /// configured management message limit.
    pub fn encode(&self) -> Result<Vec<u8>, ManagementError> {
        if self.version == 0 {
            return Err(ManagementError::ZeroVersion);
        }
        let payload_len =
            u32::try_from(self.payload.len()).map_err(|_| ManagementError::FrameTooLarge)?;
        encode_frame(REQUEST_HEADER, self.payload.len(), |frame| {
            frame[4..6].copy_from_slice(&self.version.to_be_bytes());
            frame[6..14].copy_from_slice(&self.request_id.to_be_bytes());
            frame[14..16].copy_from_slice(&self.operation.to_be_bytes());
            frame[16..20].copy_from_slice(&payload_len.to_be_bytes());
            frame[20..].copy_from_slice(&self.payload);
        })
    }

    /// Decodes one complete length-prefixed request frame.
    ///
    /// # Errors
    ///
    /// Returns an error when the frame is truncated, oversized, or internally
    /// inconsistent.
    pub fn decode(frame: &[u8]) -> Result<Self, ManagementError> {
        validate_frame(frame, REQUEST_HEADER)?;
        let payload_len = read_u32(frame, 16)? as usize;
        if payload_len != frame.len() - FRAME_PREFIX - REQUEST_HEADER {
            return Err(ManagementError::LengthMismatch);
        }
        Ok(Self {
            version: read_u16(frame, 4)?,
            request_id: read_u64(frame, 6)?,
            operation: read_u16(frame, 14)?,
            payload: frame.get(20..).ok_or(ManagementError::Truncated)?.to_vec(),
        })
    }
}

impl ManagementResponse {
    /// Encodes a response using the Go controller's big-endian wire format.
    ///
    /// # Errors
    ///
    /// Returns an error when the version is zero or the frame exceeds the
    /// configured management message limit.
    pub fn encode(&self) -> Result<Vec<u8>, ManagementError> {
        if self.version == 0 {
            return Err(ManagementError::ZeroVersion);
        }
        let payload_len =
            u32::try_from(self.payload.len()).map_err(|_| ManagementError::FrameTooLarge)?;
        encode_frame(RESPONSE_HEADER, self.payload.len(), |frame| {
            frame[4..6].copy_from_slice(&self.version.to_be_bytes());
            frame[6..14].copy_from_slice(&self.request_id.to_be_bytes());
            frame[14..16].copy_from_slice(&self.status.to_be_bytes());
            frame[16..18].copy_from_slice(&self.error_code.to_be_bytes());
            frame[18..22].copy_from_slice(&payload_len.to_be_bytes());
            frame[22..].copy_from_slice(&self.payload);
        })
    }

    /// Decodes one complete length-prefixed response frame.
    ///
    /// # Errors
    ///
    /// Returns an error when the frame is truncated, oversized, or internally
    /// inconsistent.
    pub fn decode(frame: &[u8]) -> Result<Self, ManagementError> {
        validate_frame(frame, RESPONSE_HEADER)?;
        let payload_len = read_u32(frame, 18)? as usize;
        if payload_len != frame.len() - FRAME_PREFIX - RESPONSE_HEADER {
            return Err(ManagementError::LengthMismatch);
        }
        Ok(Self {
            version: read_u16(frame, 4)?,
            request_id: read_u64(frame, 6)?,
            status: read_u16(frame, 14)?,
            error_code: read_u16(frame, 16)?,
            payload: frame.get(22..).ok_or(ManagementError::Truncated)?.to_vec(),
        })
    }
}

fn encode_frame<F>(
    header_size: usize,
    payload_len: usize,
    write: F,
) -> Result<Vec<u8>, ManagementError>
where
    F: FnOnce(&mut [u8]),
{
    let frame_len = header_size
        .checked_add(payload_len)
        .ok_or(ManagementError::FrameTooLarge)?;
    if frame_len > MAX_MANAGEMENT_FRAME_SIZE {
        return Err(ManagementError::FrameTooLarge);
    }
    let mut frame = vec![0; FRAME_PREFIX + frame_len];
    let frame_len = u32::try_from(frame_len).map_err(|_| ManagementError::FrameTooLarge)?;
    frame[..FRAME_PREFIX].copy_from_slice(&frame_len.to_be_bytes());
    write(&mut frame);
    Ok(frame)
}

fn validate_frame(frame: &[u8], header_size: usize) -> Result<(), ManagementError> {
    if frame.len() < FRAME_PREFIX + header_size {
        return Err(ManagementError::Truncated);
    }
    let declared = read_u32(frame, 0)? as usize;
    if declared > MAX_MANAGEMENT_FRAME_SIZE {
        return Err(ManagementError::FrameTooLarge);
    }
    if declared != frame.len() - FRAME_PREFIX {
        return Err(ManagementError::LengthMismatch);
    }
    Ok(())
}

fn read_u16(frame: &[u8], start: usize) -> Result<u16, ManagementError> {
    let bytes = frame
        .get(start..start + 2)
        .ok_or(ManagementError::Truncated)?;
    Ok(u16::from_be_bytes(
        bytes.try_into().map_err(|_| ManagementError::Truncated)?,
    ))
}

fn read_u32(frame: &[u8], start: usize) -> Result<u32, ManagementError> {
    let bytes = frame
        .get(start..start + 4)
        .ok_or(ManagementError::Truncated)?;
    Ok(u32::from_be_bytes(
        bytes.try_into().map_err(|_| ManagementError::Truncated)?,
    ))
}

fn read_u64(frame: &[u8], start: usize) -> Result<u64, ManagementError> {
    let bytes = frame
        .get(start..start + 8)
        .ok_or(ManagementError::Truncated)?;
    Ok(u64::from_be_bytes(
        bytes.try_into().map_err(|_| ManagementError::Truncated)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_matches_go_layout() {
        let request = ManagementRequest {
            version: 1,
            request_id: 42,
            operation: 2,
            payload: b"config".to_vec(),
        };
        let encoded = request.encode().unwrap();
        assert_eq!(&encoded[..4], &[0, 0, 0, 22]);
        assert_eq!(ManagementRequest::decode(&encoded).unwrap(), request);
    }

    #[test]
    fn response_round_trips_and_rejects_truncation() {
        let response = ManagementResponse {
            version: 1,
            request_id: 42,
            status: 200,
            error_code: 0,
            payload: b"ok".to_vec(),
        };
        let encoded = response.encode().unwrap();
        assert_eq!(ManagementResponse::decode(&encoded).unwrap(), response);
        assert_eq!(
            ManagementResponse::decode(&encoded[..encoded.len() - 1]),
            Err(ManagementError::LengthMismatch)
        );
    }

    #[test]
    fn rejects_zero_version_and_oversize_payload() {
        let zero = ManagementRequest {
            version: 0,
            request_id: 1,
            operation: 1,
            payload: Vec::new(),
        };
        assert_eq!(zero.encode(), Err(ManagementError::ZeroVersion));
        let large = ManagementRequest {
            version: 1,
            request_id: 1,
            operation: 1,
            payload: vec![0; MAX_MANAGEMENT_FRAME_SIZE],
        };
        assert_eq!(large.encode(), Err(ManagementError::FrameTooLarge));
    }
}
