//! Approved peer authorization state.

use std::{collections::HashMap, time::SystemTime};

/// A peer's approved network identity without secret material.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerAuthorization {
    pub peer_id: u64,
    pub user_id: String,
    pub public_key: [u8; 32],
    pub ipv4: Option<std::net::Ipv4Addr>,
    pub ipv6: Option<std::net::Ipv6Addr>,
    pub expires_at: SystemTime,
}

/// Information safe to expose through status and metrics APIs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerSummary {
    pub peer_id: u64,
    pub user_id: String,
    pub ipv4: Option<std::net::Ipv4Addr>,
    pub ipv6: Option<std::net::Ipv6Addr>,
    pub expires_at: SystemTime,
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

    use super::{PeerAuthorization, PeerRegistry, PeerRegistryError};

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
}
