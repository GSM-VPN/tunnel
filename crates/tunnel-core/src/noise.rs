//! Noise IK handshake boundary.

use std::time::SystemTime;

use snow::{Builder, HandshakeState, TransportState, params::NoiseParams};

use crate::{PeerRegistry, ServerIdentity};

/// Noise pattern selected by the protocol specification.
pub const NOISE_IK_PARAMS: &str = "Noise_IK_25519_ChaChaPoly_SHA256";
const MAX_HANDSHAKE_MESSAGE_SIZE: usize = 1_400;

#[derive(Debug)]
pub enum NoiseHandshakeError {
    Snow(snow::Error),
    MessageTooLarge,
    NotMyTurn,
    NotFinished,
    UnauthorizedPeer,
}

impl From<snow::Error> for NoiseHandshakeError {
    fn from(error: snow::Error) -> Self {
        Self::Snow(error)
    }
}

/// A two-message Noise IK handshake with a pinned responder static key.
pub struct NoiseHandshake {
    state: Option<HandshakeState>,
    expected_remote_static: Option<Vec<u8>>,
}

impl NoiseHandshake {
    /// Builds an initiator that authenticates the expected responder key.
    ///
    /// # Errors
    ///
    /// Returns a Noise construction error when the static keys or parameters
    /// are invalid.
    pub fn initiator(
        static_private_key: &[u8],
        responder_public_key: &[u8],
    ) -> Result<Self, NoiseHandshakeError> {
        let params: NoiseParams = NOISE_IK_PARAMS.parse()?;
        let state = Builder::new(params)
            .local_private_key(static_private_key)
            .map_err(NoiseHandshakeError::from)?
            .remote_public_key(responder_public_key)
            .map_err(NoiseHandshakeError::from)?
            .build_initiator()
            .map_err(NoiseHandshakeError::from)?;
        Ok(Self {
            state: Some(state),
            expected_remote_static: None,
        })
    }

    /// Builds a responder using its long-term static private key and an
    /// approved initiator public key.
    ///
    /// # Errors
    ///
    /// Returns a Noise construction error when the static key or parameters
    /// are invalid.
    pub fn responder(
        static_private_key: &[u8],
        initiator_public_key: &[u8],
    ) -> Result<Self, NoiseHandshakeError> {
        let params: NoiseParams = NOISE_IK_PARAMS.parse()?;
        let state = Builder::new(params)
            .local_private_key(static_private_key)
            .map_err(NoiseHandshakeError::from)?
            .build_responder()
            .map_err(NoiseHandshakeError::from)?;
        Ok(Self {
            state: Some(state),
            expected_remote_static: Some(initiator_public_key.to_vec()),
        })
    }

    /// Builds a responder directly from the Core's protected server identity.
    ///
    /// # Errors
    ///
    /// Returns a construction error when the approved peer key or Noise
    /// parameters are invalid.
    pub fn responder_for_identity(
        identity: &ServerIdentity,
        initiator_public_key: &[u8],
    ) -> Result<Self, NoiseHandshakeError> {
        Self::responder(identity.private_key(), initiator_public_key)
    }

    /// Builds a responder only when the peer key is currently approved.
    ///
    /// The approval check happens before allocating a Noise handshake state,
    /// while the handshake still repeats the exact public-key check after the
    /// peer's first message. This keeps authorization and cryptographic
    /// authentication as separate, required gates.
    ///
    /// # Errors
    ///
    /// Returns [`NoiseHandshakeError::UnauthorizedPeer`] for an unknown,
    /// expired, or mismatched peer approval.
    pub fn responder_for_approved_peer(
        identity: &ServerIdentity,
        peers: &PeerRegistry,
        peer_id: u64,
        initiator_public_key: &[u8; 32],
        now: SystemTime,
    ) -> Result<Self, NoiseHandshakeError> {
        if !peers.is_authorized(peer_id, initiator_public_key, now) {
            return Err(NoiseHandshakeError::UnauthorizedPeer);
        }
        Self::responder_for_identity(identity, initiator_public_key)
    }

    #[must_use]
    pub fn is_my_turn(&self) -> bool {
        self.state.as_ref().is_some_and(HandshakeState::is_my_turn)
    }

    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.state
            .as_ref()
            .is_some_and(HandshakeState::is_handshake_finished)
    }

    /// Writes the next handshake message.
    ///
    /// # Errors
    ///
    /// Returns [`NoiseHandshakeError::NotMyTurn`] when the peer must send
    /// first, or a Noise error when the state machine rejects the message.
    pub fn write_message(&mut self, payload: &[u8]) -> Result<Vec<u8>, NoiseHandshakeError> {
        let state = self
            .state
            .as_mut()
            .ok_or(NoiseHandshakeError::NotFinished)?;
        if !state.is_my_turn() {
            return Err(NoiseHandshakeError::NotMyTurn);
        }
        let mut message = vec![0; MAX_HANDSHAKE_MESSAGE_SIZE];
        let written = state.write_message(payload, &mut message)?;
        message.truncate(written);
        Ok(message)
    }

    /// Reads the peer's next handshake message and returns its payload.
    ///
    /// # Errors
    ///
    /// Returns [`NoiseHandshakeError::NotMyTurn`] when this side must write,
    /// or a Noise error when authentication or message parsing fails.
    pub fn read_message(&mut self, message: &[u8]) -> Result<Vec<u8>, NoiseHandshakeError> {
        if message.len() > MAX_HANDSHAKE_MESSAGE_SIZE {
            return Err(NoiseHandshakeError::MessageTooLarge);
        }
        let state = self
            .state
            .as_mut()
            .ok_or(NoiseHandshakeError::NotFinished)?;
        if state.is_my_turn() {
            return Err(NoiseHandshakeError::NotMyTurn);
        }
        let mut payload = vec![0; MAX_HANDSHAKE_MESSAGE_SIZE];
        let written = state.read_message(message, &mut payload)?;
        if let Some(expected) = &self.expected_remote_static {
            let actual = state
                .get_remote_static()
                .ok_or(NoiseHandshakeError::UnauthorizedPeer)?;
            if actual != expected {
                return Err(NoiseHandshakeError::UnauthorizedPeer);
            }
        }
        payload.truncate(written);
        Ok(payload)
    }

    /// Converts a completed handshake into an authenticated transport state.
    ///
    /// # Errors
    ///
    /// Returns [`NoiseHandshakeError::NotFinished`] until all handshake
    /// messages have been exchanged, or a Noise state error otherwise.
    pub fn into_transport(mut self) -> Result<NoiseTransport, NoiseHandshakeError> {
        let state = self.state.take().ok_or(NoiseHandshakeError::NotFinished)?;
        if !state.is_handshake_finished() {
            return Err(NoiseHandshakeError::NotFinished);
        }
        Ok(NoiseTransport(state.into_transport_mode()?))
    }
}

/// Transport mode produced only by a completed Noise IK handshake.
pub struct NoiseTransport(TransportState);

impl NoiseTransport {
    /// Encrypts one transport payload using Noise's derived session keys.
    ///
    /// # Errors
    ///
    /// Returns a Noise state error when the transport nonce is exhausted or
    /// the output exceeds the Noise message limit.
    pub fn write_message(&mut self, payload: &[u8]) -> Result<Vec<u8>, NoiseHandshakeError> {
        let mut message = vec![0; MAX_HANDSHAKE_MESSAGE_SIZE];
        let written = self.0.write_message(payload, &mut message)?;
        message.truncate(written);
        Ok(message)
    }

    /// Decrypts one transport payload.
    ///
    /// # Errors
    ///
    /// Returns a Noise authentication or state error for invalid ciphertext
    /// or an exhausted transport nonce.
    pub fn read_message(&mut self, message: &[u8]) -> Result<Vec<u8>, NoiseHandshakeError> {
        if message.len() > MAX_HANDSHAKE_MESSAGE_SIZE {
            return Err(NoiseHandshakeError::MessageTooLarge);
        }
        let mut payload = vec![0; MAX_HANDSHAKE_MESSAGE_SIZE];
        let written = self.0.read_message(message, &mut payload)?;
        payload.truncate(written);
        Ok(payload)
    }
}

#[cfg(test)]
mod tests {
    use snow::{Builder, params::NoiseParams};

    use std::{
        net::Ipv4Addr,
        time::{Duration, SystemTime, UNIX_EPOCH},
    };

    use crate::{PeerAuthorization, PeerRegistry};

    use super::{NOISE_IK_PARAMS, NoiseHandshake, NoiseHandshakeError};

    #[test]
    fn completes_ik_and_encrypts_transport_payload() {
        let params: NoiseParams = NOISE_IK_PARAMS.parse().unwrap();
        let builder = Builder::new(params);
        let initiator_key = builder.generate_keypair().unwrap();
        let responder_key = builder.generate_keypair().unwrap();
        let mut initiator =
            NoiseHandshake::initiator(&initiator_key.private, &responder_key.public).unwrap();
        let mut responder =
            NoiseHandshake::responder(&responder_key.private, &initiator_key.public).unwrap();

        let first = initiator.write_message(b"hello").unwrap();
        assert_eq!(responder.read_message(&first).unwrap(), b"hello");
        let second = responder.write_message(b"welcome").unwrap();
        assert_eq!(initiator.read_message(&second).unwrap(), b"welcome");
        assert!(initiator.is_finished());
        assert!(responder.is_finished());

        let mut initiator_transport = initiator.into_transport().unwrap();
        let mut responder_transport = responder.into_transport().unwrap();
        let encrypted = initiator_transport.write_message(b"payload").unwrap();
        assert_eq!(
            responder_transport.read_message(&encrypted).unwrap(),
            b"payload"
        );
    }

    #[test]
    fn approved_peer_gate_rejects_unknown_and_expired_keys() {
        let params: NoiseParams = NOISE_IK_PARAMS.parse().unwrap();
        let builder = Builder::new(params);
        let initiator_key = builder.generate_keypair().unwrap();
        let identity = crate::ServerIdentity::from_hex(&"11".repeat(32)).unwrap();
        let initiator_public_key: [u8; 32] = initiator_key.public.try_into().unwrap();
        let mut peers = PeerRegistry::new(1);
        let now = UNIX_EPOCH + Duration::from_secs(10);
        peers
            .register(
                PeerAuthorization {
                    peer_id: 7,
                    user_id: "approved".to_string(),
                    public_key: initiator_public_key,
                    ipv4: Some(Ipv4Addr::new(10, 80, 0, 2)),
                    ipv6: None,
                    expires_at: now + Duration::from_secs(10),
                },
                now,
            )
            .unwrap();

        assert!(
            NoiseHandshake::responder_for_approved_peer(
                &identity,
                &peers,
                7,
                &initiator_public_key,
                now,
            )
            .is_ok()
        );
        assert!(matches!(
            NoiseHandshake::responder_for_approved_peer(&identity, &peers, 7, &[9; 32], now,),
            Err(NoiseHandshakeError::UnauthorizedPeer)
        ));
        assert!(matches!(
            NoiseHandshake::responder_for_approved_peer(
                &identity,
                &peers,
                7,
                &initiator_public_key,
                SystemTime::now(),
            ),
            Err(NoiseHandshakeError::UnauthorizedPeer)
        ));
    }

    #[test]
    fn rejects_client_authentication_and_wrong_message_order() {
        let params: NoiseParams = NOISE_IK_PARAMS.parse().unwrap();
        let builder = Builder::new(params);
        let initiator_key = builder.generate_keypair().unwrap();
        let responder_key = builder.generate_keypair().unwrap();
        let unauthorized_key = builder.generate_keypair().unwrap();
        let mut initiator =
            NoiseHandshake::initiator(&unauthorized_key.private, &responder_key.public).unwrap();
        let mut responder =
            NoiseHandshake::responder(&responder_key.private, &initiator_key.public).unwrap();
        assert!(matches!(
            initiator.read_message(b"not yet"),
            Err(NoiseHandshakeError::NotMyTurn)
        ));
        assert!(matches!(
            responder.write_message(b"not yet"),
            Err(NoiseHandshakeError::NotMyTurn)
        ));
        let first = initiator.write_message(b"hello").unwrap();
        assert!(matches!(
            responder.read_message(&first),
            Err(NoiseHandshakeError::UnauthorizedPeer)
        ));

        let mut approved_initiator =
            NoiseHandshake::initiator(&initiator_key.private, &responder_key.public).unwrap();
        let mut approved_responder =
            NoiseHandshake::responder(&responder_key.private, &initiator_key.public).unwrap();
        let approved_first = approved_initiator.write_message(b"hello").unwrap();
        assert!(matches!(
            approved_responder.read_message(&approved_first),
            Ok(payload) if payload == b"hello"
        ));
    }

    #[test]
    fn responder_can_use_the_protected_server_identity_boundary() {
        let params: NoiseParams = NOISE_IK_PARAMS.parse().unwrap();
        let builder = Builder::new(params);
        let initiator_key = builder.generate_keypair().unwrap();
        let identity = crate::ServerIdentity::from_hex(&"22".repeat(32)).unwrap();
        let mut initiator =
            NoiseHandshake::initiator(&initiator_key.private, &identity.public_key()).unwrap();
        let mut responder =
            NoiseHandshake::responder_for_identity(&identity, &initiator_key.public).unwrap();
        let first = initiator.write_message(b"identity-bound").unwrap();
        assert_eq!(responder.read_message(&first).unwrap(), b"identity-bound");
    }
}
