//! Low-cardinality, secret-free Core metrics.

use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime},
};

use crate::SessionId;

const MAX_SESSION_METRICS: usize = 216;

#[derive(Clone, Copy, Default)]
struct SessionTraffic {
    tx_bytes: u64,
    rx_bytes: u64,
    tx_packets: u64,
    rx_packets: u64,
}

#[derive(Default)]
struct MetricsInner {
    active_sessions: AtomicU64,
    tx_bytes: AtomicU64,
    rx_bytes: AtomicU64,
    tx_packets: AtomicU64,
    rx_packets: AtomicU64,
    authentication_failures: AtomicU64,
    replay_rejections: AtomicU64,
    reconnects: AtomicU64,
    handshake_failures: AtomicU64,
    keepalive_failures: AtomicU64,
    packet_errors: AtomicU64,
    session_traffic: Mutex<HashMap<SessionId, SessionTraffic>>,
    reconnect_started: Mutex<HashMap<SessionId, SystemTime>>,
    recovered_reconnects: AtomicU64,
    recovery_millis: AtomicU64,
}

/// Thread-safe counters that never retain keys, plaintext, or user identity.
#[derive(Clone, Default)]
pub struct Metrics {
    inner: Arc<MetricsInner>,
}

/// Point-in-time copy of all Core counters.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MetricsSnapshot {
    pub active_sessions: u64,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub tx_packets: u64,
    pub rx_packets: u64,
    pub authentication_failures: u64,
    pub replay_rejections: u64,
    pub reconnects: u64,
    pub handshake_failures: u64,
    pub keepalive_failures: u64,
    pub packet_errors: u64,
}

/// Secret-free traffic counters for one tunnel session.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SessionMetricsSnapshot {
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub tx_packets: u64,
    pub rx_packets: u64,
}

/// Secret-free reconnect timing counters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryMetricsSnapshot {
    pub reconnects: u64,
    pub completed: u64,
    pub average_recovery: Option<Duration>,
}

impl Metrics {
    pub fn session_started(&self) {
        self.inner.active_sessions.fetch_add(1, Ordering::Relaxed);
    }

    pub fn session_closed(&self) {
        let _ =
            self.inner
                .active_sessions
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                    value.checked_sub(1)
                });
    }

    pub fn record_tx(&self, bytes: u64) {
        self.inner.tx_packets.fetch_add(1, Ordering::Relaxed);
        self.inner.tx_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Records a successful data-plane send for one session.
    pub fn record_tx_for(&self, session_id: SessionId, bytes: u64) {
        self.record_tx(bytes);
        if let Ok(mut traffic) = self.inner.session_traffic.lock()
            && (traffic.len() < MAX_SESSION_METRICS || traffic.contains_key(&session_id))
        {
            let entry = traffic.entry(session_id).or_default();
            entry.tx_packets = entry.tx_packets.saturating_add(1);
            entry.tx_bytes = entry.tx_bytes.saturating_add(bytes);
        }
    }

    pub fn record_rx(&self, bytes: u64) {
        self.inner.rx_packets.fetch_add(1, Ordering::Relaxed);
        self.inner.rx_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Records a successful data-plane receive for one session.
    pub fn record_rx_for(&self, session_id: SessionId, bytes: u64) {
        self.record_rx(bytes);
        if let Ok(mut traffic) = self.inner.session_traffic.lock()
            && (traffic.len() < MAX_SESSION_METRICS || traffic.contains_key(&session_id))
        {
            let entry = traffic.entry(session_id).or_default();
            entry.rx_packets = entry.rx_packets.saturating_add(1);
            entry.rx_bytes = entry.rx_bytes.saturating_add(bytes);
        }
    }

    /// Removes traffic counters when a session is closed.
    pub fn session_closed_for(&self, session_id: SessionId) {
        if let Ok(mut traffic) = self.inner.session_traffic.lock() {
            traffic.remove(&session_id);
        }
        self.session_closed();
    }

    #[must_use]
    pub fn session_snapshot(&self, session_id: SessionId) -> Option<SessionMetricsSnapshot> {
        self.inner
            .session_traffic
            .lock()
            .ok()
            .and_then(|traffic| traffic.get(&session_id).copied())
            .map(|traffic| SessionMetricsSnapshot {
                tx_bytes: traffic.tx_bytes,
                rx_bytes: traffic.rx_bytes,
                tx_packets: traffic.tx_packets,
                rx_packets: traffic.rx_packets,
            })
    }

    pub fn record_authentication_failure(&self) {
        self.inner
            .authentication_failures
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_replay_rejection(&self) {
        self.inner.replay_rejections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_reconnect(&self) {
        self.inner.reconnects.fetch_add(1, Ordering::Relaxed);
    }

    /// Records the beginning of a reconnect and retains only its start time.
    pub fn record_reconnect_start(&self, session_id: SessionId, started_at: SystemTime) {
        self.record_reconnect();
        if let Ok(mut reconnects) = self.inner.reconnect_started.lock()
            && (reconnects.len() < MAX_SESSION_METRICS || reconnects.contains_key(&session_id))
        {
            reconnects.insert(session_id, started_at);
        }
    }

    /// Completes a reconnect and returns its measured duration when valid.
    #[must_use]
    pub fn record_reconnect_recovered(
        &self,
        session_id: SessionId,
        recovered_at: SystemTime,
    ) -> Option<Duration> {
        let started_at = self
            .inner
            .reconnect_started
            .lock()
            .ok()?
            .remove(&session_id)?;
        let duration = recovered_at.duration_since(started_at).ok()?;
        self.inner
            .recovered_reconnects
            .fetch_add(1, Ordering::Relaxed);
        let millis =
            u64::try_from(duration.as_millis().min(u128::from(u64::MAX))).unwrap_or(u64::MAX);
        self.inner
            .recovery_millis
            .fetch_add(millis, Ordering::Relaxed);
        Some(duration)
    }

    #[must_use]
    pub fn recovery_snapshot(&self) -> RecoveryMetricsSnapshot {
        let completed = self.inner.recovered_reconnects.load(Ordering::Relaxed);
        let average_recovery = (completed > 0).then(|| {
            Duration::from_millis(self.inner.recovery_millis.load(Ordering::Relaxed) / completed)
        });
        RecoveryMetricsSnapshot {
            reconnects: self.inner.reconnects.load(Ordering::Relaxed),
            completed,
            average_recovery,
        }
    }

    pub fn record_handshake_failure(&self) {
        self.inner
            .handshake_failures
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_keepalive_failure(&self) {
        self.inner
            .keepalive_failures
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_packet_error(&self) {
        self.inner.packet_errors.fetch_add(1, Ordering::Relaxed);
    }

    #[must_use]
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            active_sessions: self.inner.active_sessions.load(Ordering::Relaxed),
            tx_bytes: self.inner.tx_bytes.load(Ordering::Relaxed),
            rx_bytes: self.inner.rx_bytes.load(Ordering::Relaxed),
            tx_packets: self.inner.tx_packets.load(Ordering::Relaxed),
            rx_packets: self.inner.rx_packets.load(Ordering::Relaxed),
            authentication_failures: self.inner.authentication_failures.load(Ordering::Relaxed),
            replay_rejections: self.inner.replay_rejections.load(Ordering::Relaxed),
            reconnects: self.inner.reconnects.load(Ordering::Relaxed),
            handshake_failures: self.inner.handshake_failures.load(Ordering::Relaxed),
            keepalive_failures: self.inner.keepalive_failures.load(Ordering::Relaxed),
            packet_errors: self.inner.packet_errors.load(Ordering::Relaxed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Metrics;
    use crate::SessionId;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn snapshot_contains_secret_free_counters() {
        let metrics = Metrics::default();
        metrics.session_started();
        metrics.record_tx(12);
        metrics.record_rx(8);
        metrics.record_authentication_failure();
        metrics.record_replay_rejection();
        metrics.record_reconnect();
        metrics.record_handshake_failure();
        metrics.record_keepalive_failure();
        metrics.record_packet_error();
        assert_eq!(metrics.snapshot().active_sessions, 1);
        assert_eq!(metrics.snapshot().tx_bytes, 12);
        assert_eq!(metrics.snapshot().rx_packets, 1);
        assert_eq!(metrics.snapshot().authentication_failures, 1);
        metrics.session_closed();
        assert_eq!(metrics.snapshot().active_sessions, 0);
    }

    #[test]
    fn tracks_bounded_secret_free_session_traffic() {
        let metrics = Metrics::default();
        let session = SessionId::new(7).unwrap();
        metrics.record_tx_for(session, 12);
        metrics.record_rx_for(session, 8);
        assert_eq!(
            metrics.session_snapshot(session),
            Some(super::SessionMetricsSnapshot {
                tx_bytes: 12,
                rx_bytes: 8,
                tx_packets: 1,
                rx_packets: 1,
            })
        );
        metrics.session_closed_for(session);
        assert_eq!(metrics.session_snapshot(session), None);
    }

    #[test]
    fn counters_are_safe_to_update_concurrently() {
        let metrics = Arc::new(Metrics::default());
        let workers: Vec<_> = (0..4)
            .map(|_| {
                let metrics = Arc::clone(&metrics);
                thread::spawn(move || {
                    for _ in 0..100 {
                        metrics.record_tx(1);
                    }
                })
            })
            .collect();
        for worker in workers {
            worker.join().expect("worker completes");
        }
        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.tx_packets, 400);
        assert_eq!(snapshot.tx_bytes, 400);
    }

    #[test]
    fn measures_average_reconnect_recovery_without_retaining_session_data() {
        let metrics = Metrics::default();
        let first = SessionId::new(7).unwrap();
        let second = SessionId::new(8).unwrap();
        let start = std::time::UNIX_EPOCH + std::time::Duration::from_secs(10);
        metrics.record_reconnect_start(first, start);
        metrics.record_reconnect_start(second, start);
        assert_eq!(
            metrics.record_reconnect_recovered(first, start + std::time::Duration::from_secs(2)),
            Some(std::time::Duration::from_secs(2))
        );
        assert_eq!(
            metrics.record_reconnect_recovered(second, start + std::time::Duration::from_secs(4)),
            Some(std::time::Duration::from_secs(4))
        );
        assert_eq!(
            metrics.recovery_snapshot(),
            super::RecoveryMetricsSnapshot {
                reconnects: 2,
                completed: 2,
                average_recovery: Some(std::time::Duration::from_secs(3)),
            }
        );
        assert_eq!(metrics.record_reconnect_recovered(first, start), None);
    }
}
