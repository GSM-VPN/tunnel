//! Noise IK handshake boundary.

use snow::{Builder, HandshakeState, TransportState, params::NoiseParams};

/// Noise pattern selected by the protocol specification.
pub const NOISE_IK_PARAMS: &str = "Noise_IK_25519_ChaChaPoly_SHA256";
const MAX_HANDSHAKE_MESSAGE_SIZE: usize = 1_400;

#[derive(Debug)]
pub enum NoiseHandshakeError {
    Snow(snow::Error),
    MessageTooLarge,
    NotMyTurn,
    NotFinished,
}

impl From<snow::Error> for NoiseHandshakeError {
    fn from(error: snow::Error) -> Self {
        Self::Snow(error)
    }
}

/// A two-message Noise IK handshake with a pinned responder static key.
pub struct NoiseHandshake {
    state: Option<HandshakeState>,
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
        Ok(Self { state: Some(state) })
    }

    /// Builds a responder using its long-term static private key.
    ///
    /// # Errors
    ///
    /// Returns a Noise construction error when the static key or parameters
    /// are invalid.
    pub fn responder(static_private_key: &[u8]) -> Result<Self, NoiseHandshakeError> {
        let params: NoiseParams = NOISE_IK_PARAMS.parse()?;
        let state = Builder::new(params)
            .local_private_key(static_private_key)
            .map_err(NoiseHandshakeError::from)?
            .build_responder()
            .map_err(NoiseHandshakeError::from)?;
        Ok(Self { state: Some(state) })
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

    use super::{NOISE_IK_PARAMS, NoiseHandshake, NoiseHandshakeError};

    #[test]
    fn completes_ik_and_encrypts_transport_payload() {
        let params: NoiseParams = NOISE_IK_PARAMS.parse().unwrap();
        let builder = Builder::new(params);
        let initiator_key = builder.generate_keypair().unwrap();
        let responder_key = builder.generate_keypair().unwrap();
        let mut initiator =
            NoiseHandshake::initiator(&initiator_key.private, &responder_key.public).unwrap();
        let mut responder = NoiseHandshake::responder(&responder_key.private).unwrap();

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
    fn rejects_wrong_responder_key_and_message_order() {
        let params: NoiseParams = NOISE_IK_PARAMS.parse().unwrap();
        let builder = Builder::new(params);
        let initiator_key = builder.generate_keypair().unwrap();
        let responder_key = builder.generate_keypair().unwrap();
        let wrong_key = builder.generate_keypair().unwrap();
        let mut initiator =
            NoiseHandshake::initiator(&initiator_key.private, &wrong_key.public).unwrap();
        let mut responder = NoiseHandshake::responder(&responder_key.private).unwrap();
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
            Err(NoiseHandshakeError::Snow(_))
        ));
    }
}
