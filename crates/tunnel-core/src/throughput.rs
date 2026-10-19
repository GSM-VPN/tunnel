//! Secret-free throughput measurement and per-session byte fairness.

use std::{
    collections::HashMap,
    time::{Duration, SystemTime},
};

/// Server-wide throughput policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ThroughputPolicy {
    /// Target aggregate rate in decimal bytes per second.
    pub target_bytes_per_second: u64,
    /// Maximum burst granted to one session.
    pub burst_bytes: u64,
    /// Maximum number of session buckets retained by the limiter.
    pub max_sessions: usize,
}

impl Default for ThroughputPolicy {
    fn default() -> Self {
        Self {
            target_bytes_per_second: 512_000_000,
            burst_bytes: 1_000_000,
            max_sessions: 216,
        }
    }
}

impl ThroughputPolicy {
    /// Returns the equal session share of the server-wide target.
    #[must_use]
    pub fn per_session_bytes_per_second(self) -> u64 {
        if self.max_sessions == 0 {
            return 0;
        }
        self.target_bytes_per_second
            .div_ceil(self.max_sessions as u64)
    }
}

/// A point-in-time throughput result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ThroughputSample {
    pub bytes: u64,
    pub elapsed: Duration,
    pub bytes_per_second: u64,
}

/// Measures aggregate bytes without retaining packet contents or identities.
#[derive(Clone, Copy, Debug)]
pub struct ThroughputMeter {
    started_at: SystemTime,
    bytes: u64,
}

impl ThroughputMeter {
    #[must_use]
    pub fn new(started_at: SystemTime) -> Self {
        Self {
            started_at,
            bytes: 0,
        }
    }

    pub fn record(&mut self, bytes: u64) {
        self.bytes = self.bytes.saturating_add(bytes);
    }

    #[must_use]
    pub fn sample(&self, now: SystemTime) -> ThroughputSample {
        let elapsed = now.duration_since(self.started_at).unwrap_or_default();
        let elapsed_nanos = elapsed.as_nanos().max(1);
        let bytes_per_second = u64::try_from(
            (u128::from(self.bytes) * 1_000_000_000 / elapsed_nanos).min(u128::from(u64::MAX)),
        )
        .unwrap_or(u64::MAX);
        ThroughputSample {
            bytes: self.bytes,
            elapsed,
            bytes_per_second,
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct Bucket {
    updated_at: SystemTime,
    tokens: u64,
}

/// Per-session token buckets with equal byte rates and bounded state.
pub struct FairByteRateLimiter {
    policy: ThroughputPolicy,
    buckets: HashMap<u64, Bucket>,
}

impl FairByteRateLimiter {
    #[must_use]
    pub fn new(policy: ThroughputPolicy) -> Self {
        Self {
            buckets: HashMap::with_capacity(policy.max_sessions),
            policy,
        }
    }

    /// Admits a byte count when the session has enough fair-share tokens.
    #[must_use]
    pub fn allow(&mut self, session_id: u64, bytes: u64, now: SystemTime) -> bool {
        if bytes > self.policy.burst_bytes {
            return false;
        }
        let Some(bucket) = self.buckets.get_mut(&session_id) else {
            if self.buckets.len() >= self.policy.max_sessions {
                return false;
            }
            self.buckets.insert(
                session_id,
                Bucket {
                    updated_at: now,
                    tokens: self.policy.burst_bytes,
                },
            );
            return self.allow_existing(session_id, bytes);
        };
        refill(
            bucket,
            self.policy.per_session_bytes_per_second(),
            self.policy.burst_bytes,
            now,
        );
        self.allow_existing(session_id, bytes)
    }

    #[must_use]
    pub fn tracked_sessions(&self) -> usize {
        self.buckets.len()
    }

    fn allow_existing(&mut self, session_id: u64, bytes: u64) -> bool {
        let bucket = self
            .buckets
            .get_mut(&session_id)
            .expect("bucket inserted before admission");
        if bucket.tokens < bytes {
            return false;
        }
        bucket.tokens -= bytes;
        true
    }
}

fn refill(bucket: &mut Bucket, bytes_per_second: u64, burst_bytes: u64, now: SystemTime) {
    let elapsed_nanos = now
        .duration_since(bucket.updated_at)
        .unwrap_or_default()
        .as_nanos();
    let added = (elapsed_nanos * u128::from(bytes_per_second)) / 1_000_000_000;
    let added = u64::try_from(added.min(u128::from(burst_bytes))).unwrap_or(u64::MAX);
    bucket.tokens = bucket.tokens.saturating_add(added).min(burst_bytes);
    bucket.updated_at = now;
}

#[cfg(test)]
mod tests {
    use super::{FairByteRateLimiter, ThroughputMeter, ThroughputPolicy};
    use std::time::{Duration, UNIX_EPOCH};

    #[test]
    fn measures_target_rate_without_packet_data() {
        let start = UNIX_EPOCH + Duration::from_secs(1);
        let mut meter = ThroughputMeter::new(start);
        meter.record(512);
        let sample = meter.sample(start + Duration::from_millis(1));
        assert_eq!(sample.bytes, 512);
        assert_eq!(sample.bytes_per_second, 512_000);
    }

    #[test]
    fn gives_each_session_an_equal_bounded_byte_budget() {
        let policy = ThroughputPolicy {
            target_bytes_per_second: 1_000,
            burst_bytes: 100,
            max_sessions: 2,
        };
        let start = UNIX_EPOCH + Duration::from_secs(1);
        let mut limiter = FairByteRateLimiter::new(policy);
        assert_eq!(policy.per_session_bytes_per_second(), 500);
        assert!(limiter.allow(1, 100, start));
        assert!(!limiter.allow(1, 1, start));
        assert!(limiter.allow(2, 100, start));
        assert!(limiter.allow(1, 1, start + Duration::from_millis(10)));
        assert!(!limiter.allow(3, 1, start));
        assert_eq!(limiter.tracked_sessions(), 2);
    }

    #[test]
    fn measures_the_configured_216_session_capacity() {
        let policy = ThroughputPolicy::default();
        let start = UNIX_EPOCH + Duration::from_secs(1);
        let mut limiter = FairByteRateLimiter::new(policy);
        for session_id in 1..=216 {
            assert!(limiter.allow(session_id, 1, start));
        }
        assert_eq!(limiter.tracked_sessions(), 216);
        assert!(!limiter.allow(217, 1, start));
    }
}
