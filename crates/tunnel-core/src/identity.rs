//! Long-term server identity key boundary.

use std::{env, fmt};

use x25519_dalek::{PublicKey, StaticSecret};

const SERVER_PRIVATE_KEY_ENV: &str = "SERVER_PRIVATE_KEY";

/// Errors returned while loading the Rust Core's long-term identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityConfigError {
    MissingPrivateKey,
    InvalidPrivateKeyLength,
    InvalidPrivateKeyEncoding,
}

/// Server identity held by the Rust Core. The private key is never exposed in
/// formatting, IPC, metrics, or public accessors.
pub struct ServerIdentity {
    private_key: StaticSecret,
    public_key: PublicKey,
}

impl fmt::Debug for ServerIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServerIdentity")
            .field("private_key", &"[redacted]")
            .field("public_key", &hex_encode(self.public_key.as_bytes()))
            .finish()
    }
}

impl ServerIdentity {
    /// Loads `SERVER_PRIVATE_KEY` as exactly 32 bytes of lowercase/uppercase
    /// hexadecimal without logging or copying the secret into a String field.
    ///
    /// # Errors
    ///
    /// Returns an error when the variable is missing, not 64 hex characters,
    /// or contains a non-hex character.
    pub fn from_env() -> Result<Self, IdentityConfigError> {
        let encoded =
            env::var(SERVER_PRIVATE_KEY_ENV).map_err(|_| IdentityConfigError::MissingPrivateKey)?;
        Self::from_hex(&encoded)
    }

    /// Builds an identity from a 64-character hexadecimal private key.
    ///
    /// # Errors
    ///
    /// Returns an error when the encoding is not exactly 32 bytes of hex.
    pub fn from_hex(encoded: &str) -> Result<Self, IdentityConfigError> {
        if encoded.len() != 64 {
            return Err(IdentityConfigError::InvalidPrivateKeyLength);
        }
        let mut private_bytes = [0; 32];
        for (index, byte) in private_bytes.iter_mut().enumerate() {
            *byte = (hex_value(encoded.as_bytes()[index * 2])? << 4)
                | hex_value(encoded.as_bytes()[index * 2 + 1])?;
        }
        let private_key = StaticSecret::from(private_bytes);
        let public_key = PublicKey::from(&private_key);
        Ok(Self {
            private_key,
            public_key,
        })
    }

    /// Returns the derived public key for pinning and authorization metadata.
    #[must_use]
    pub fn public_key(&self) -> [u8; 32] {
        *self.public_key.as_bytes()
    }

    pub(crate) fn private_key(&self) -> &[u8; 32] {
        self.private_key.as_bytes()
    }
}

fn hex_value(value: u8) -> Result<u8, IdentityConfigError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(IdentityConfigError::InvalidPrivateKeyEncoding),
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|byte| {
            [
                HEX[(byte >> 4) as usize] as char,
                HEX[(byte & 0x0f) as usize] as char,
            ]
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{IdentityConfigError, ServerIdentity};

    #[test]
    fn derives_a_stable_public_key_without_exposing_private_material() {
        let identity = ServerIdentity::from_hex(&"11".repeat(32)).unwrap();
        assert_ne!(identity.public_key(), [0; 32]);
        let debug = format!("{identity:?}");
        assert!(debug.contains("redacted"));
        assert!(!debug.contains(&"11".repeat(32)));
    }

    #[test]
    fn rejects_missing_length_and_invalid_hex() {
        assert!(matches!(
            ServerIdentity::from_hex("00"),
            Err(IdentityConfigError::InvalidPrivateKeyLength)
        ));
        assert!(matches!(
            ServerIdentity::from_hex(&format!("{}gg", "00".repeat(31))),
            Err(IdentityConfigError::InvalidPrivateKeyEncoding)
        ));
    }
}
