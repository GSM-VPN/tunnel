//! Approved peer authorization state.

use std::{collections::HashMap, fmt, time::SystemTime};

/// A peer's approved network identity without secret material.
#[derive(Clone, Eq, PartialEq)]
pub struct PeerAuthorization {
    pub peer_id: u64,
    pub user_id: String,
    pub public_key: [u8; 32],
    pub ipv4: Option<std::net::Ipv4Addr>,
    pub ipv6: Option<std::net::Ipv6Addr>,
    pub expires_at: SystemTime,
}

/// Information safe to expose through status and metrics APIs.
#[derive(Clone, Eq, PartialEq)]
pub struct PeerSummary {
    pub peer_id: u64,
    pub user_id: String,
    pub ipv4: Option<std::net::Ipv4Addr>,
    pub ipv6: Option<std::net::Ipv6Addr>,
    pub expires_at: SystemTime,
}

impl fmt::Debug for PeerAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PeerAuthorization")
            .field("peer_id", &self.peer_id)
            .field("user_id", &"[redacted]")
            .field("public_key", &"[redacted]")
            .field("ipv4", &self.ipv4)
            .field("ipv6", &self.ipv6)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl fmt::Debug for PeerSummary {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PeerSummary")
            .field("peer_id", &self.peer_id)
            .field("user_id", &"[redacted]")
            .field("ipv4", &self.ipv4)
            .field("ipv6", &self.ipv6)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl From<&PeerAuthorization> for PeerSummary {
    fn from(peer: &PeerAuthorization) -> Self {
        Self {
            peer_id: peer.peer_id,
            user_id: peer.user_id.clone(),
            ipv4: peer.ipv4,
            ipv6: peer.ipv6,
            expires_at: peer.expires_at,
        }
    }
}

/// Errors returned while updating the approved peer set.
#[derive(Debug, Eq, PartialEq)]
pub enum PeerRegistryError {
    Capacity,
    DuplicatePeer,
    DuplicatePublicKey,
    DuplicateAddress,
    EmptyUserId,
    InvalidAddress,
    InvalidExpiry,
    UnknownPeer,
}

/// Bounded in-memory registry for approved peers.
pub struct PeerRegistry {
    capacity: usize,
    peers: HashMap<u64, PeerAuthorization>,
}

impl PeerRegistry {
    /// Creates a registry with a fixed peer capacity.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            peers: HashMap::with_capacity(capacity),
        }
    }

    /// Adds a peer approval without retaining any private key or service secret.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid identity data, duplicate IDs, expired
    /// approvals, or a full registry.
    pub fn register(
        &mut self,
        peer: PeerAuthorization,
        now: SystemTime,
    ) -> Result<(), PeerRegistryError> {
        if peer.user_id.trim().is_empty() {
            return Err(PeerRegistryError::EmptyUserId);
        }
        if peer.ipv4.is_none() && peer.ipv6.is_none() {
            return Err(PeerRegistryError::InvalidAddress);
        }
        if peer.expires_at <= now {
            return Err(PeerRegistryError::InvalidExpiry);
        }
        if self.peers.contains_key(&peer.peer_id) {
            return Err(PeerRegistryError::DuplicatePeer);
        }
        if self.peers.len() >= self.capacity {
            return Err(PeerRegistryError::Capacity);
        }
        if self
            .peers
            .values()
            .any(|existing| existing.public_key == peer.public_key)
        {
            return Err(PeerRegistryError::DuplicatePublicKey);
        }
        if self.peers.values().any(|existing| {
            peer.ipv4
                .is_some_and(|address| existing.ipv4 == Some(address))
                || peer
                    .ipv6
                    .is_some_and(|address| existing.ipv6 == Some(address))
        }) {
            return Err(PeerRegistryError::DuplicateAddress);
        }
        self.peers.insert(peer.peer_id, peer);
        Ok(())
    }

    /// Returns whether a peer is currently approved and unexpired.
    #[must_use]
    pub fn is_authorized(&self, peer_id: u64, public_key: &[u8; 32], now: SystemTime) -> bool {
        self.peers
            .get(&peer_id)
            .is_some_and(|peer| peer.public_key == *public_key && peer.expires_at > now)
    }

    /// Revokes an approval immediately.
    ///
    /// # Errors
    ///
    /// Returns [`PeerRegistryError::UnknownPeer`] when the ID is not present.
    pub fn revoke(&mut self, peer_id: u64) -> Result<PeerAuthorization, PeerRegistryError> {
        self.peers
            .remove(&peer_id)
            .ok_or(PeerRegistryError::UnknownPeer)
    }

    /// Lists active, non-secret peer summaries.
    #[must_use]
    pub fn active_summaries(&self, now: SystemTime) -> Vec<PeerSummary> {
        self.peers
            .values()
            .filter(|peer| peer.expires_at > now)
            .map(PeerSummary::from)
            .collect()
    }

    /// Removes expired approvals and returns their peer IDs.
    pub fn purge_expired(&mut self, now: SystemTime) -> Vec<u64> {
        let expired: Vec<_> = self
            .peers
            .values()
            .filter(|peer| peer.expires_at <= now)
            .map(|peer| peer.peer_id)
            .collect();
        for peer_id in &expired {
            self.peers.remove(peer_id);
        }
        expired
    }

    /// Returns the number of registered approvals, including expired entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.peers.len()
    }

    /// Returns whether the registry contains no approvals.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::{Ipv4Addr, Ipv6Addr},
        time::{Duration, UNIX_EPOCH},
    };

    use super::{PeerAuthorization, PeerRegistry, PeerRegistryError, PeerSummary};

    fn peer(id: u64, key: [u8; 32]) -> PeerAuthorization {
        PeerAuthorization {
            peer_id: id,
            user_id: format!("user-{id}"),
            public_key: key,
            ipv4: Some(Ipv4Addr::new(10, 80, 0, 2)),
            ipv6: Some(Ipv6Addr::LOCALHOST),
            expires_at: UNIX_EPOCH + Duration::from_secs(120),
        }
    }

    #[test]
    fn authorizes_matching_key_until_expiry_and_hides_it_from_summary() {
        let now = UNIX_EPOCH + Duration::from_secs(60);
        let key = [7; 32];
        let mut registry = PeerRegistry::new(1);
        registry.register(peer(1, key), now).unwrap();
        assert!(registry.is_authorized(1, &key, now));
        assert!(!registry.is_authorized(1, &[8; 32], now));
        assert!(!registry.is_authorized(1, &key, UNIX_EPOCH + Duration::from_secs(120)));
        let summaries = registry.active_summaries(now);
        assert_eq!(summaries.len(), 1);
        assert!(!format!("{:?}", summaries[0]).contains('7'));
    }

    #[test]
    fn rejects_duplicates_invalid_approvals_and_capacity_overflow() {
        let now = UNIX_EPOCH;
        let mut registry = PeerRegistry::new(1);
        assert_eq!(registry.register(peer(1, [1; 32]), now), Ok(()));
        assert_eq!(
            registry.register(peer(1, [2; 32]), now),
            Err(PeerRegistryError::DuplicatePeer)
        );
        assert_eq!(
            registry.register(peer(2, [2; 32]), now),
            Err(PeerRegistryError::Capacity)
        );
        assert_eq!(
            registry.register(peer(3, [3; 32]), UNIX_EPOCH + Duration::from_secs(120)),
            Err(PeerRegistryError::InvalidExpiry)
        );
    }

    #[test]
    fn revocation_removes_authorization() {
        let now = UNIX_EPOCH;
        let key = [4; 32];
        let mut registry = PeerRegistry::new(1);
        registry.register(peer(1, key), now).unwrap();
        registry.revoke(1).unwrap();
        assert!(!registry.is_authorized(1, &key, now));
        assert!(registry.is_empty());
    }

    #[test]
    fn rejects_reused_public_keys_and_tunnel_addresses() {
        let now = UNIX_EPOCH;
        let mut registry = PeerRegistry::new(3);
        registry.register(peer(1, [1; 32]), now).unwrap();
        assert_eq!(
            registry.register(peer(2, [1; 32]), now),
            Err(PeerRegistryError::DuplicatePublicKey)
        );
        let mut duplicate_address = peer(3, [3; 32]);
        duplicate_address.ipv6 = Some(Ipv6Addr::LOCALHOST);
        assert_eq!(
            registry.register(duplicate_address, now),
            Err(PeerRegistryError::DuplicateAddress)
        );
    }

    #[test]
    fn purges_expired_approvals_for_reallocation() {
        let mut registry = PeerRegistry::new(1);
        registry.register(peer(1, [1; 32]), UNIX_EPOCH).unwrap();
        assert_eq!(
            registry.purge_expired(UNIX_EPOCH + Duration::from_secs(120)),
            vec![1]
        );
        assert!(registry.is_empty());
        registry.register(peer(2, [2; 32]), UNIX_EPOCH).unwrap();
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn debug_output_redacts_peer_identity_fields() {
        let peer = peer(7, [0xabu8; 32]);
        let summary = PeerSummary::from(&peer);
        for debug in [format!("{peer:?}"), format!("{summary:?}")] {
            assert!(debug.contains("redacted"));
            assert!(!debug.contains("user-7"));
            assert!(!debug.contains("ab"));
        }
    }
}
