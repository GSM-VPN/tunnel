//! Foundational types for the GSM Tunnel data plane.

/// Protocol identifier defined by the project specification.
pub const PROTOCOL_NAME: &str = "gsm-tunnel";

/// Initial protocol version defined by the project specification.
pub const PROTOCOL_VERSION: (u8, u8, u8) = (1, 0, 0);

#[cfg(test)]
mod tests {
    use super::{PROTOCOL_NAME, PROTOCOL_VERSION};

    #[test]
    fn exposes_initial_protocol_identity() {
        assert_eq!(PROTOCOL_NAME, "gsm-tunnel");
        assert_eq!(PROTOCOL_VERSION, (1, 0, 0));
    }
}
