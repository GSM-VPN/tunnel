//! Low-cardinality, secret-free Core metrics.

use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

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

    pub fn record_rx(&self, bytes: u64) {
        self.inner.rx_packets.fetch_add(1, Ordering::Relaxed);
        self.inner.rx_bytes.fetch_add(bytes, Ordering::Relaxed);
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
}
