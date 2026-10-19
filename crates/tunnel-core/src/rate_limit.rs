//! Bounded per-peer rate limiting for control and packet admission.

use std::{
    collections::HashMap,
    time::{Duration, SystemTime},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RateLimitKind {
    Handshake,
    Packet,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RateLimitPolicy {
    pub window: Duration,
    pub max_handshakes: u32,
    pub max_packets: u32,
    pub max_subjects: usize,
}

impl Default for RateLimitPolicy {
    fn default() -> Self {
        Self {
            window: Duration::from_secs(1),
            max_handshakes: 5,
            max_packets: 1_000,
            max_subjects: 216,
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct Window {
    started_at: SystemTime,
    handshakes: u32,
    packets: u32,
}

pub struct PeerRateLimiter {
    policy: RateLimitPolicy,
    windows: HashMap<u64, Window>,
}

impl PeerRateLimiter {
    #[must_use]
    pub fn new(policy: RateLimitPolicy) -> Self {
        Self {
            policy,
            windows: HashMap::with_capacity(policy.max_subjects),
        }
    }

    #[must_use]
    pub fn allow(&mut self, peer_id: u64, kind: RateLimitKind, now: SystemTime) -> bool {
        let Some(window) = self.windows.get_mut(&peer_id) else {
            if self.windows.len() >= self.policy.max_subjects {
                return false;
            }
            self.windows.insert(
                peer_id,
                Window {
                    started_at: now,
                    handshakes: 0,
                    packets: 0,
                },
            );
            return self.allow_existing(peer_id, kind);
        };
        if now.duration_since(window.started_at).unwrap_or_default() >= self.policy.window {
            window.started_at = now;
            window.handshakes = 0;
            window.packets = 0;
        }
        self.allow_existing(peer_id, kind)
    }

    #[must_use]
    pub fn tracked_subjects(&self) -> usize {
        self.windows.len()
    }

    fn allow_existing(&mut self, peer_id: u64, kind: RateLimitKind) -> bool {
        let window = self
            .windows
            .get_mut(&peer_id)
            .expect("window inserted before admission");
        match kind {
            RateLimitKind::Handshake if window.handshakes < self.policy.max_handshakes => {
                window.handshakes += 1;
                true
            }
            RateLimitKind::Packet if window.packets < self.policy.max_packets => {
                window.packets += 1;
                true
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{PeerRateLimiter, RateLimitKind, RateLimitPolicy};
    use std::time::{Duration, UNIX_EPOCH};

    #[test]
    fn limits_handshakes_and_packets_per_window() {
        let policy = RateLimitPolicy {
            window: Duration::from_secs(10),
            max_handshakes: 2,
            max_packets: 3,
            max_subjects: 2,
        };
        let mut limiter = PeerRateLimiter::new(policy);
        let now = UNIX_EPOCH + Duration::from_secs(1);
        assert!(limiter.allow(7, RateLimitKind::Handshake, now));
        assert!(limiter.allow(7, RateLimitKind::Handshake, now));
        assert!(!limiter.allow(7, RateLimitKind::Handshake, now));
        assert!(limiter.allow(7, RateLimitKind::Packet, now));
        assert!(limiter.allow(7, RateLimitKind::Packet, now));
        assert!(limiter.allow(7, RateLimitKind::Packet, now));
        assert!(!limiter.allow(7, RateLimitKind::Packet, now));
        assert!(limiter.allow(7, RateLimitKind::Handshake, now + Duration::from_secs(10)));
    }

    #[test]
    fn bounds_subject_state_and_resets_expired_windows() {
        let policy = RateLimitPolicy {
            max_subjects: 1,
            max_handshakes: 1,
            ..RateLimitPolicy::default()
        };
        let mut limiter = PeerRateLimiter::new(policy);
        let now = UNIX_EPOCH + Duration::from_secs(1);
        assert!(limiter.allow(1, RateLimitKind::Handshake, now));
        assert!(!limiter.allow(2, RateLimitKind::Handshake, now));
        assert!(limiter.allow(1, RateLimitKind::Handshake, now + Duration::from_secs(1)));
        assert_eq!(limiter.tracked_subjects(), 1);
    }

    #[test]
    fn isolates_packet_bursts_between_peers() {
        let policy = RateLimitPolicy {
            max_packets: 1,
            max_subjects: 2,
            ..RateLimitPolicy::default()
        };
        let mut limiter = PeerRateLimiter::new(policy);
        let now = UNIX_EPOCH + Duration::from_secs(1);
        assert!(limiter.allow(1, RateLimitKind::Packet, now));
        assert!(!limiter.allow(1, RateLimitKind::Packet, now));
        assert!(limiter.allow(2, RateLimitKind::Packet, now));
    }
}
