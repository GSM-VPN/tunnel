//! Session data-key rotation thresholds.

use std::time::Duration;

/// The first rotation condition reached by a session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RotationReason {
    Age,
    Bytes,
    Counter,
}

/// Limits that force a new session data-key generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyRotationPolicy {
    pub max_age: Duration,
    pub max_bytes: u64,
    pub max_sequence: u64,
}

impl Default for KeyRotationPolicy {
    fn default() -> Self {
        Self {
            max_age: Duration::from_hours(1),
            max_bytes: 1 << 30,
            max_sequence: u64::MAX - 1,
        }
    }
}

impl KeyRotationPolicy {
    /// Returns the first condition that requires rotation, if any.
    #[must_use]
    pub fn rotation_reason(
        &self,
        age: Duration,
        transmitted_bytes: u64,
        next_sequence: u64,
    ) -> Option<RotationReason> {
        if age >= self.max_age {
            return Some(RotationReason::Age);
        }
        if transmitted_bytes >= self.max_bytes {
            return Some(RotationReason::Bytes);
        }
        if next_sequence >= self.max_sequence {
            return Some(RotationReason::Counter);
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::{KeyRotationPolicy, RotationReason};
    use std::time::Duration;

    #[test]
    fn defaults_to_specified_age_and_volume_limits() {
        let policy = KeyRotationPolicy::default();
        assert_eq!(policy.max_age, Duration::from_secs(3_600));
        assert_eq!(policy.max_bytes, 1_073_741_824);
    }

    #[test]
    fn reports_the_first_reached_condition() {
        let policy = KeyRotationPolicy::default();
        assert_eq!(
            policy.rotation_reason(Duration::from_secs(3_600), 0, 0),
            Some(RotationReason::Age)
        );
        assert_eq!(
            policy.rotation_reason(Duration::ZERO, 1_073_741_824, 0),
            Some(RotationReason::Bytes)
        );
        assert_eq!(
            policy.rotation_reason(Duration::ZERO, 0, u64::MAX - 1),
            Some(RotationReason::Counter)
        );
    }

    #[test]
    fn stays_below_limits_without_overflowing_counter_math() {
        let policy = KeyRotationPolicy::default();
        assert_eq!(
            policy.rotation_reason(Duration::from_secs(3_599), 1_073_741_823, 0),
            None
        );
        assert_eq!(
            policy.rotation_reason(Duration::ZERO, 0, u64::MAX - 2),
            None
        );
    }
}
