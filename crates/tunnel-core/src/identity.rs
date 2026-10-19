//! Long-term server identity key boundary.

use std::{env, fmt};

use base64::{Engine, engine::general_purpose::STANDARD};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

const SERVER_PRIVATE_KEY_ENV: &str = "SERVER_PRIVATE_KEY";

/// Errors returned while loading the Rust Core's long-term identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityConfigError {
    MissingPrivateKey,
    InvalidPrivateKeyLength,
    InvalidPrivateKeyEncoding,
    RandomGeneration,
}

/// Server identity held by the Rust Core. The private key is never exposed in
/// formatting, IPC, metrics, or public accessors.
pub struct ServerIdentity {
    private_key: Zeroizing<[u8; 32]>,
    public_key: PublicKey,
}

impl fmt::Debug for ServerIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServerIdentity")
            .field("private_key", &"[redacted]")
            .field("public_key", &self.public_key_base64())
            .finish()
    }
}

impl ServerIdentity {
    /// Generates a new identity using the operating system's CSPRNG.
    ///
    /// Stable deployments should load their provisioned key through
    /// [`Self::from_env`] rather than generating a replacement at restart.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityConfigError::RandomGeneration`] when the operating
    /// system CSPRNG cannot provide key material.
    pub fn generate() -> Result<Self, IdentityConfigError> {
        let mut private_bytes = Zeroizing::new([0; 32]);
        getrandom::fill(&mut *private_bytes).map_err(|_| IdentityConfigError::RandomGeneration)?;
        let private_secret = StaticSecret::from(*private_bytes);
        let public_key = PublicKey::from(&private_secret);
        Ok(Self {
            private_key: private_bytes,
            public_key,
        })
    }

    /// Loads `SERVER_PRIVATE_KEY` as exactly 32 bytes of standard Base64
    /// without logging or copying the secret into a String field.
    ///
    /// # Errors
    ///
    /// Returns an error when the variable is missing, not a canonical 44-byte
    /// Base64 encoding, or does not decode to exactly 32 bytes.
    pub fn from_env() -> Result<Self, IdentityConfigError> {
        let encoded =
            env::var(SERVER_PRIVATE_KEY_ENV).map_err(|_| IdentityConfigError::MissingPrivateKey)?;
        Self::from_base64(&encoded)
    }

    /// Builds an identity from a canonical standard Base64 private key.
    ///
    /// # Errors
    ///
    /// Returns an error when the encoding is not exactly 32 bytes of Base64.
    pub fn from_base64(encoded: &str) -> Result<Self, IdentityConfigError> {
        if encoded.len() != 44 || !encoded.ends_with('=') {
            return Err(IdentityConfigError::InvalidPrivateKeyLength);
        }
        let decoded = STANDARD
            .decode(encoded)
            .map_err(|_| IdentityConfigError::InvalidPrivateKeyEncoding)?;
        if STANDARD.encode(&decoded) != encoded {
            return Err(IdentityConfigError::InvalidPrivateKeyEncoding);
        }
        let private_bytes: Zeroizing<[u8; 32]> = decoded
            .try_into()
            .map(Zeroizing::new)
            .map_err(|_| IdentityConfigError::InvalidPrivateKeyLength)?;
        let private_secret = StaticSecret::from(*private_bytes);
        let public_key = PublicKey::from(&private_secret);
        Ok(Self {
            private_key: private_bytes,
            public_key,
        })
    }

    /// Returns the derived public key for pinning and authorization metadata.
    #[must_use]
    pub fn public_key(&self) -> [u8; 32] {
        *self.public_key.as_bytes()
    }

    /// Returns the public key in the Base64 representation used by
    /// `vpn-server` and its `WireGuard` integration.
    #[must_use]
    pub fn public_key_base64(&self) -> String {
        STANDARD.encode(self.public_key.as_bytes())
    }

    pub(crate) fn private_key(&self) -> &[u8; 32] {
        &self.private_key
    }
}

#[cfg(test)]
mod tests {
    use base64::{Engine, engine::general_purpose::STANDARD};

    use super::{IdentityConfigError, ServerIdentity};

    #[test]
    fn derives_a_stable_public_key_without_exposing_private_material() {
        let identity = ServerIdentity::from_base64(&STANDARD.encode([0x11; 32])).unwrap();
        assert_ne!(identity.public_key(), [0; 32]);
        let debug = format!("{identity:?}");
        assert!(debug.contains("redacted"));
        assert_eq!(identity.public_key_base64().len(), 44);
    }

    #[test]
    fn generates_identity_from_os_csprng_without_exposing_private_material() {
        let identity = ServerIdentity::generate().expect("OS CSPRNG is available");
        assert_ne!(identity.public_key(), [0; 32]);
        let debug = format!("{identity:?}");
        assert!(debug.contains("redacted"));
    }

    #[test]
    fn rejects_missing_length_non_base64_and_legacy_hex() {
        assert!(matches!(
            ServerIdentity::from_base64("AA=="),
            Err(IdentityConfigError::InvalidPrivateKeyLength)
        ));
        assert!(matches!(
            ServerIdentity::from_base64(&format!("{}==", "!".repeat(42))),
            Err(IdentityConfigError::InvalidPrivateKeyEncoding)
        ));
        assert!(matches!(
            ServerIdentity::from_base64(STANDARD.encode([0; 32]).trim_end_matches('=')),
            Err(IdentityConfigError::InvalidPrivateKeyLength)
        ));
        assert!(matches!(
            ServerIdentity::from_base64(&"11".repeat(32)),
            Err(IdentityConfigError::InvalidPrivateKeyLength)
        ));
    }
}
