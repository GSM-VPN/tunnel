use chacha20poly1305::{
    ChaCha20Poly1305, Key, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use sha2::{Digest, Sha256};
use std::sync::Mutex;
use zeroize::{Zeroize, Zeroizing};

use crate::protocol::{AEAD_TAG_SIZE, HEADER_SIZE};
use crate::{
    KeyGeneration, MAX_PAYLOAD_SIZE, ProtocolError, SessionId, TunnelHeader, TunnelPacket,
};

const REPLAY_WINDOW_SIZE: u64 = 2_048;
const REPLAY_WORDS: usize = 32;

/// Errors returned by authenticated session encryption.
#[derive(Debug, Eq, PartialEq)]
pub enum CryptoError {
    Protocol(ProtocolError),
    InvalidCiphertext,
    InvalidSession,
    InvalidKeyGeneration,
    Replay,
    PayloadTooLarge,
}

impl From<ProtocolError> for CryptoError {
    fn from(error: ProtocolError) -> Self {
        Self::Protocol(error)
    }
}

/// A fixed-size replay window for one session and key generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayWindow {
    highest: Option<u64>,
    bits: [u64; REPLAY_WORDS],
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self {
            highest: None,
            bits: [0; REPLAY_WORDS],
        }
    }
}

impl ReplayWindow {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            highest: None,
            bits: [0; REPLAY_WORDS],
        }
    }

    #[must_use]
    pub fn accepts(&self, sequence: u64) -> bool {
        let Some(highest) = self.highest else {
            return true;
        };
        if sequence > highest {
            return true;
        }
        let distance = highest - sequence;
        if distance >= REPLAY_WINDOW_SIZE {
            return false;
        }
        let word = (distance / 64) as usize;
        let mask = 1_u64 << (distance % 64);
        self.bits[word] & mask == 0
    }

    /// Records an authenticated sequence number.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Replay`] when the sequence is duplicate or
    /// outside the replay window.
    pub fn accept(&mut self, sequence: u64) -> Result<(), CryptoError> {
        if !self.accepts(sequence) {
            return Err(CryptoError::Replay);
        }
        let Some(highest) = self.highest else {
            self.highest = Some(sequence);
            self.bits[0] = 1;
            return Ok(());
        };
        if sequence > highest {
            self.shift(sequence - highest);
            self.highest = Some(sequence);
            self.bits[0] |= 1;
            return Ok(());
        }
        let distance = highest - sequence;
        self.bits[(distance / 64) as usize] |= 1_u64 << (distance % 64);
        Ok(())
    }

    fn shift(&mut self, distance: u64) {
        if distance >= REPLAY_WINDOW_SIZE {
            self.bits = [0; REPLAY_WORDS];
            return;
        }
        let word_shift = (distance / 64) as usize;
        let bit_shift = distance % 64;
        let previous = self.bits;
        for index in (0..REPLAY_WORDS).rev() {
            let source = index.checked_sub(word_shift);
            self.bits[index] = source.map_or(0, |source| {
                let mut value = previous[source] << bit_shift;
                if bit_shift != 0 {
                    value |= source
                        .checked_sub(1)
                        .map_or(0, |lower| previous[lower] >> (64 - bit_shift));
                }
                value
            });
        }
    }
}

/// Thread-safe Replay Window for parallel authenticated-packet workers.
#[derive(Debug, Default)]
pub struct ConcurrentReplayWindow {
    inner: Mutex<ReplayWindow>,
}

impl ConcurrentReplayWindow {
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(ReplayWindow::new()),
        }
    }

    /// Checks a sequence without reserving it.
    #[must_use]
    pub fn accepts(&self, sequence: u64) -> bool {
        self.inner
            .lock()
            .is_ok_and(|window| window.accepts(sequence))
    }

    /// Atomically checks and records a sequence.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Replay`] for a duplicate, stale, or poisoned
    /// window.
    pub fn accept(&self, sequence: u64) -> Result<(), CryptoError> {
        self.inner
            .lock()
            .map_err(|_| CryptoError::Replay)?
            .accept(sequence)
    }
}

/// ChaCha20-Poly1305 session cipher with a direction-specific nonce domain.
pub struct SessionCipher {
    key: Zeroizing<[u8; 32]>,
    session_id: SessionId,
    key_generation: KeyGeneration,
    direction: u8,
    replay: ReplayWindow,
}

impl SessionCipher {
    #[must_use]
    pub fn new(
        key: [u8; 32],
        session_id: SessionId,
        key_generation: KeyGeneration,
        direction: u8,
    ) -> Self {
        Self {
            key: Zeroizing::new(key),
            session_id,
            key_generation,
            direction,
            replay: ReplayWindow::new(),
        }
    }

    #[must_use]
    pub const fn key_generation(&self) -> KeyGeneration {
        self.key_generation
    }

    /// Installs a key from a newly authenticated handshake generation.
    ///
    /// # Errors
    ///
    /// Returns `InvalidKeyGeneration` when the generation is not strictly newer
    /// than the active generation. The key and replay state remain unchanged
    /// in that case.
    pub fn rekey(
        &mut self,
        key: [u8; 32],
        key_generation: KeyGeneration,
    ) -> Result<(), CryptoError> {
        if key_generation.0 <= self.key_generation.0 {
            return Err(CryptoError::InvalidKeyGeneration);
        }
        self.key.zeroize();
        self.key = Zeroizing::new(key);
        self.key_generation = key_generation;
        self.replay = ReplayWindow::new();
        Ok(())
    }

    /// Encrypts a payload and returns an authenticated tunnel packet.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::PayloadTooLarge`] or a protocol error when the
    /// resulting packet cannot fit in the configured maximum size.
    pub fn seal(
        &self,
        mut header: TunnelHeader,
        plaintext: &[u8],
    ) -> Result<TunnelPacket, CryptoError> {
        if plaintext.len() + AEAD_TAG_SIZE > MAX_PAYLOAD_SIZE {
            return Err(CryptoError::PayloadTooLarge);
        }
        header.session_id = self.session_id;
        header.key_generation = self.key_generation;
        let placeholder = TunnelPacket::new(header, vec![0; plaintext.len() + AEAD_TAG_SIZE])?;
        let encoded = placeholder.encode()?;
        let ciphertext = self
            .cipher()
            .encrypt(
                &self.nonce(header.sequence_number.0),
                Payload {
                    msg: plaintext,
                    aad: &encoded[..HEADER_SIZE],
                },
            )
            .map_err(|_| CryptoError::InvalidCiphertext)?;
        Ok(TunnelPacket::new(header, ciphertext)?)
    }

    /// Authenticates and decrypts a tunnel packet, updating replay state only
    /// after successful authentication.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Replay`] for duplicate or stale sequences and
    /// [`CryptoError::InvalidCiphertext`] for failed authentication.
    pub fn open(&mut self, packet: &TunnelPacket) -> Result<Vec<u8>, CryptoError> {
        if packet.header.session_id != self.session_id {
            return Err(CryptoError::InvalidSession);
        }
        if packet.header.key_generation != self.key_generation {
            return Err(CryptoError::InvalidKeyGeneration);
        }
        if packet.payload.len() < AEAD_TAG_SIZE
            || !self.replay.accepts(packet.header.sequence_number.0)
        {
            return Err(CryptoError::Replay);
        }
        let encoded = packet.encode()?;
        let plaintext = self
            .cipher()
            .decrypt(
                &self.nonce(packet.header.sequence_number.0),
                Payload {
                    msg: &packet.payload,
                    aad: &encoded[..HEADER_SIZE],
                },
            )
            .map_err(|_| CryptoError::InvalidCiphertext)?;
        self.replay.accept(packet.header.sequence_number.0)?;
        Ok(plaintext)
    }

    fn cipher(&self) -> ChaCha20Poly1305 {
        ChaCha20Poly1305::new(Key::from_slice(&*self.key))
    }

    fn nonce(&self, sequence: u64) -> Nonce {
        let mut hasher = Sha256::new();
        hasher.update(self.session_id.0.to_be_bytes());
        hasher.update(self.key_generation.0.to_be_bytes());
        hasher.update([self.direction]);
        hasher.update(sequence.to_be_bytes());
        let digest = hasher.finalize();
        *Nonce::from_slice(&digest[..12])
    }
}

#[cfg(test)]
mod tests {
    use super::{ConcurrentReplayWindow, CryptoError, ReplayWindow, SessionCipher};
    use crate::{
        KeyGeneration, MAX_ENCRYPTED_PAYLOAD_SIZE, PacketType, ProtocolVersion, SessionId,
        TunnelHeader,
    };

    fn header(sequence: u64) -> TunnelHeader {
        TunnelHeader {
            version: ProtocolVersion::new(1, 0, 0),
            packet_type: PacketType::TransportData,
            flags: 0,
            session_id: SessionId::new(7).expect("session ID"),
            sequence_number: crate::SequenceNumber(sequence),
            key_generation: KeyGeneration(2),
        }
    }

    #[test]
    fn seals_and_opens_authenticated_payload() {
        let key = [7; 32];
        let session = SessionId::new(7).expect("session ID");
        let mut receiver = SessionCipher::new(key, session, KeyGeneration(2), 1);
        let sender = SessionCipher::new(key, session, KeyGeneration(2), 1);
        let packet = sender.seal(header(1), b"secret").expect("seal succeeds");
        assert_eq!(receiver.open(&packet).expect("open succeeds"), b"secret");
    }

    #[test]
    fn rejects_tampering_without_consuming_replay_slot() {
        let key = [7; 32];
        let session = SessionId::new(7).expect("session ID");
        let sender = SessionCipher::new(key, session, KeyGeneration(2), 1);
        let mut receiver = SessionCipher::new(key, session, KeyGeneration(2), 1);
        let mut packet = sender.seal(header(1), b"secret").expect("seal succeeds");
        packet.payload[0] ^= 1;
        assert_eq!(receiver.open(&packet), Err(CryptoError::InvalidCiphertext));
        let valid = sender.seal(header(1), b"secret").expect("seal succeeds");
        assert_eq!(
            receiver.open(&valid).expect("valid packet opens"),
            b"secret"
        );
    }

    #[test]
    fn rekey_resets_generation_and_replay_window() {
        let session = SessionId::new(7).expect("session ID");
        let old_key = [7; 32];
        let new_key = [8; 32];
        let mut receiver = SessionCipher::new(old_key, session, KeyGeneration(2), 1);
        let mut sender = SessionCipher::new(old_key, session, KeyGeneration(2), 1);
        let old_packet = sender.seal(header(0), b"old").expect("old packet");
        assert_eq!(receiver.open(&old_packet).unwrap(), b"old");

        sender.rekey(new_key, KeyGeneration(3)).unwrap();
        receiver.rekey(new_key, KeyGeneration(3)).unwrap();
        assert_eq!(sender.key_generation(), KeyGeneration(3));
        assert_eq!(
            receiver.open(&old_packet),
            Err(CryptoError::InvalidKeyGeneration)
        );

        let new_packet = sender.seal(header(0), b"new").expect("new packet");
        assert_eq!(receiver.open(&new_packet).unwrap(), b"new");
    }

    #[test]
    fn rejects_non_monotonic_rekey_without_changing_active_key() {
        let session = SessionId::new(7).expect("session ID");
        let mut cipher = SessionCipher::new([7; 32], session, KeyGeneration(2), 1);
        assert_eq!(
            cipher.rekey([8; 32], KeyGeneration(2)),
            Err(CryptoError::InvalidKeyGeneration)
        );
        assert_eq!(cipher.key_generation(), KeyGeneration(2));
    }

    #[test]
    fn concurrent_replay_window_accepts_a_sequence_once() {
        use std::sync::Arc;
        use std::thread;

        let window = Arc::new(ConcurrentReplayWindow::new());
        let workers: Vec<_> = (0..8)
            .map(|_| {
                let window = Arc::clone(&window);
                thread::spawn(move || window.accept(42).is_ok())
            })
            .collect();
        let accepted = workers
            .into_iter()
            .map(|worker| worker.join().expect("worker completes"))
            .filter(|accepted| *accepted)
            .count();
        assert_eq!(accepted, 1);
        assert_eq!(window.accept(42), Err(CryptoError::Replay));
    }

    #[test]
    fn rejects_replays_and_stale_sequences() {
        let key = [7; 32];
        let session = SessionId::new(7).expect("session ID");
        let sender = SessionCipher::new(key, session, KeyGeneration(2), 1);
        let mut receiver = SessionCipher::new(key, session, KeyGeneration(2), 1);
        let packet = sender.seal(header(1), b"secret").expect("seal succeeds");
        receiver.open(&packet).expect("first packet opens");
        assert_eq!(receiver.open(&packet), Err(CryptoError::Replay));
        let stale = sender.seal(header(3_000), b"new").expect("seal succeeds");
        receiver.open(&stale).expect("new packet opens");
        let old = sender.seal(header(1), b"old").expect("seal succeeds");
        assert_eq!(receiver.open(&old), Err(CryptoError::Replay));
    }

    #[test]
    fn replay_window_shifts_and_rejects_duplicates() {
        let mut window = ReplayWindow::new();
        window.accept(10).expect("first sequence");
        window.accept(9).expect("reordered sequence");
        assert_eq!(window.accept(9), Err(CryptoError::Replay));
        assert!(window.accept(2_100).is_ok());
        assert_eq!(window.accept(10), Err(CryptoError::Replay));
    }

    #[test]
    fn enforces_plaintext_budget_after_aead_tag() {
        let key = [7; 32];
        let session = SessionId::new(7).expect("session ID");
        let sender = SessionCipher::new(key, session, KeyGeneration(2), 1);
        let maximum = vec![0; MAX_ENCRYPTED_PAYLOAD_SIZE];
        assert!(sender.seal(header(1), &maximum).is_ok());
        let oversized = vec![0; MAX_ENCRYPTED_PAYLOAD_SIZE + 1];
        assert_eq!(
            sender.seal(header(2), &oversized),
            Err(CryptoError::PayloadTooLarge)
        );
    }
}
