//! Session lifecycle state and bounded reconnect policy.

use std::time::Duration;

/// Connection lifecycle states owned by the tunnel core.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleState {
    Disconnected,
    Connecting,
    Handshaking,
    Established,
    Rekeying,
    Reconnecting,
    Closing,
    Closed,
}

/// Events that can change the lifecycle state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionEvent {
    ConnectRequested,
    HandshakeStarted,
    HandshakeSucceeded,
    HandshakeFailed,
    HandshakeTimedOut,
    AuthenticationFailed,
    KeepaliveSucceeded,
    KeepaliveTimeout,
    NetworkChanged,
    RekeyRequested,
    RekeySucceeded,
    RekeyFailed,
    ServerShutdown,
    PermissionRevoked,
    CloseRequested,
    RetryRequested,
    Closed,
}

/// Why a lifecycle transition could not be applied.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionError {
    InvalidTransition {
        state: LifecycleState,
        event: SessionEvent,
    },
    RetryLimitReached,
}

/// A successful state transition and the next reconnect delay, if any.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Transition {
    pub from: LifecycleState,
    pub to: LifecycleState,
    pub reconnect_delay: Option<Duration>,
}

/// Work selected by the session timer for an established session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdleAction {
    SendKeepalive,
    Reconnect,
    None,
}

/// Session timing and retry defaults from `STEP.md`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionPolicy {
    pub handshake_timeout: Duration,
    pub max_handshake_attempts: u32,
    pub keepalive_after_idle: Duration,
    pub idle_timeout: Duration,
    pub reconnect_base_delay: Duration,
    pub reconnect_max_delay: Duration,
    pub max_reconnect_attempts: u32,
}

impl Default for SessionPolicy {
    fn default() -> Self {
        Self {
            handshake_timeout: Duration::from_secs(5),
            max_handshake_attempts: 5,
            keepalive_after_idle: Duration::from_secs(25),
            idle_timeout: Duration::from_secs(120),
            reconnect_base_delay: Duration::from_secs(1),
            reconnect_max_delay: Duration::from_secs(60),
            max_reconnect_attempts: 10,
        }
    }
}

impl SessionPolicy {
    #[must_use]
    pub fn reconnect_delay(&self, attempt: u32) -> Duration {
        let factor = 2_u32.saturating_pow(attempt.saturating_sub(1));
        self.reconnect_base_delay
            .saturating_mul(factor)
            .min(self.reconnect_max_delay)
    }

    #[must_use]
    pub fn keepalive_due(&self, idle_for: Duration) -> bool {
        idle_for >= self.keepalive_after_idle && idle_for < self.idle_timeout
    }

    #[must_use]
    pub fn peer_timed_out(&self, idle_for: Duration) -> bool {
        idle_for >= self.idle_timeout
    }

    #[must_use]
    pub fn idle_action(&self, idle_for: Duration) -> IdleAction {
        if self.peer_timed_out(idle_for) {
            IdleAction::Reconnect
        } else if self.keepalive_due(idle_for) {
            IdleAction::SendKeepalive
        } else {
            IdleAction::None
        }
    }
}

/// Explicit, bounded state machine for a single tunnel session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionMachine {
    state: LifecycleState,
    handshake_attempts: u32,
    reconnect_attempts: u32,
    policy: SessionPolicy,
}

impl SessionMachine {
    #[must_use]
    pub const fn new(policy: SessionPolicy) -> Self {
        Self {
            state: LifecycleState::Disconnected,
            handshake_attempts: 0,
            reconnect_attempts: 0,
            policy,
        }
    }

    #[must_use]
    pub const fn state(&self) -> LifecycleState {
        self.state
    }

    #[must_use]
    pub const fn reconnect_attempts(&self) -> u32 {
        self.reconnect_attempts
    }

    #[must_use]
    pub const fn handshake_attempts(&self) -> u32 {
        self.handshake_attempts
    }

    /// Applies one event and returns the resulting transition.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::InvalidTransition`] for an event that is not
    /// valid in the current state, or [`SessionError::RetryLimitReached`] when
    /// the reconnect policy has exhausted its bounded attempts.
    pub fn apply(&mut self, event: SessionEvent) -> Result<Transition, SessionError> {
        let from = self.state;
        let (to, reconnect_delay) = match (from, event) {
            (LifecycleState::Disconnected, SessionEvent::ConnectRequested) => {
                (LifecycleState::Connecting, None)
            }
            (LifecycleState::Connecting, SessionEvent::HandshakeStarted) => {
                self.start_handshake()?;
                (LifecycleState::Handshaking, None)
            }
            (LifecycleState::Handshaking, SessionEvent::HandshakeSucceeded) => {
                self.handshake_attempts = 0;
                self.reconnect_attempts = 0;
                (LifecycleState::Established, None)
            }
            (
                LifecycleState::Handshaking,
                SessionEvent::HandshakeFailed | SessionEvent::HandshakeTimedOut,
            ) => {
                if self.handshake_attempts >= self.policy.max_handshake_attempts {
                    (LifecycleState::Closing, None)
                } else {
                    (LifecycleState::Reconnecting, Some(self.next_retry_delay()?))
                }
            }
            (
                LifecycleState::Established,
                SessionEvent::KeepaliveTimeout | SessionEvent::NetworkChanged,
            ) => (LifecycleState::Reconnecting, Some(self.next_retry_delay()?)),
            (LifecycleState::Rekeying, SessionEvent::RekeyFailed) => {
                (LifecycleState::Closing, None)
            }
            (LifecycleState::Handshaking, SessionEvent::AuthenticationFailed)
            | (
                LifecycleState::Disconnected
                | LifecycleState::Connecting
                | LifecycleState::Handshaking
                | LifecycleState::Reconnecting
                | LifecycleState::Established
                | LifecycleState::Rekeying,
                SessionEvent::CloseRequested
                | SessionEvent::PermissionRevoked
                | SessionEvent::ServerShutdown,
            ) => (LifecycleState::Closing, None),
            (LifecycleState::Established, SessionEvent::RekeyRequested) => {
                (LifecycleState::Rekeying, None)
            }
            (LifecycleState::Rekeying, SessionEvent::RekeySucceeded)
            | (LifecycleState::Established, SessionEvent::KeepaliveSucceeded) => {
                (LifecycleState::Established, None)
            }
            (LifecycleState::Reconnecting, SessionEvent::RetryRequested) => {
                self.reconnect_attempts = self.reconnect_attempts.saturating_add(1);
                (LifecycleState::Connecting, None)
            }
            (LifecycleState::Closing, SessionEvent::Closed) => (LifecycleState::Closed, None),
            _ => return Err(SessionError::InvalidTransition { state: from, event }),
        };

        self.state = to;
        Ok(Transition {
            from,
            to,
            reconnect_delay,
        })
    }

    fn next_retry_delay(&self) -> Result<Duration, SessionError> {
        if self.reconnect_attempts >= self.policy.max_reconnect_attempts {
            return Err(SessionError::RetryLimitReached);
        }
        Ok(self
            .policy
            .reconnect_delay(self.reconnect_attempts.saturating_add(1)))
    }

    fn start_handshake(&mut self) -> Result<(), SessionError> {
        if self.handshake_attempts >= self.policy.max_handshake_attempts {
            return Err(SessionError::RetryLimitReached);
        }
        self.handshake_attempts = self.handshake_attempts.saturating_add(1);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn follows_established_lifecycle_and_resets_attempts() {
        let mut session = SessionMachine::new(SessionPolicy::default());
        for event in [
            SessionEvent::ConnectRequested,
            SessionEvent::HandshakeStarted,
            SessionEvent::HandshakeSucceeded,
        ] {
            session.apply(event).expect("valid transition");
        }
        assert_eq!(session.state(), LifecycleState::Established);
        assert_eq!(session.reconnect_attempts(), 0);
        assert_eq!(session.handshake_attempts(), 0);
    }

    #[test]
    fn bounds_reconnect_attempts_and_exposes_backoff() {
        let policy = SessionPolicy {
            max_reconnect_attempts: 2,
            ..SessionPolicy::default()
        };
        let mut session = SessionMachine::new(policy);
        session.apply(SessionEvent::ConnectRequested).unwrap();
        session.apply(SessionEvent::HandshakeStarted).unwrap();
        let first = session.apply(SessionEvent::HandshakeFailed).unwrap();
        assert_eq!(first.reconnect_delay, Some(Duration::from_secs(1)));
        session.apply(SessionEvent::RetryRequested).unwrap();
        session.apply(SessionEvent::HandshakeStarted).unwrap();
        let second = session.apply(SessionEvent::HandshakeFailed).unwrap();
        assert_eq!(second.reconnect_delay, Some(Duration::from_secs(2)));
        session.apply(SessionEvent::RetryRequested).unwrap();
        session.apply(SessionEvent::HandshakeStarted).unwrap();
        assert_eq!(
            session.apply(SessionEvent::HandshakeFailed),
            Err(SessionError::RetryLimitReached)
        );
    }

    #[test]
    fn policy_identifies_keepalive_and_timeout_windows() {
        let policy = SessionPolicy::default();
        assert!(!policy.keepalive_due(Duration::from_secs(24)));
        assert!(policy.keepalive_due(Duration::from_secs(25)));
        assert!(!policy.keepalive_due(Duration::from_secs(120)));
        assert!(policy.peer_timed_out(Duration::from_secs(120)));
        assert_eq!(
            policy.idle_action(Duration::from_secs(24)),
            IdleAction::None
        );
        assert_eq!(
            policy.idle_action(Duration::from_secs(25)),
            IdleAction::SendKeepalive
        );
        assert_eq!(
            policy.idle_action(Duration::from_secs(120)),
            IdleAction::Reconnect
        );
    }

    #[test]
    fn accepts_authenticated_keepalive_without_leaving_established_state() {
        let mut session = SessionMachine::new(SessionPolicy::default());
        for event in [
            SessionEvent::ConnectRequested,
            SessionEvent::HandshakeStarted,
            SessionEvent::HandshakeSucceeded,
        ] {
            session.apply(event).unwrap();
        }
        let transition = session.apply(SessionEvent::KeepaliveSucceeded).unwrap();
        assert_eq!(transition.from, LifecycleState::Established);
        assert_eq!(transition.to, LifecycleState::Established);
    }

    #[test]
    fn handshake_timeout_uses_bounded_reconnect_policy() {
        let mut session = SessionMachine::new(SessionPolicy::default());
        session.apply(SessionEvent::ConnectRequested).unwrap();
        session.apply(SessionEvent::HandshakeStarted).unwrap();
        let transition = session.apply(SessionEvent::HandshakeTimedOut).unwrap();
        assert_eq!(transition.to, LifecycleState::Reconnecting);
        assert_eq!(transition.reconnect_delay, Some(Duration::from_secs(1)));
    }

    #[test]
    fn closes_after_handshake_attempt_limit() {
        let policy = SessionPolicy {
            max_handshake_attempts: 2,
            ..SessionPolicy::default()
        };
        let mut session = SessionMachine::new(policy);
        session.apply(SessionEvent::ConnectRequested).unwrap();
        session.apply(SessionEvent::HandshakeStarted).unwrap();
        session.apply(SessionEvent::HandshakeFailed).unwrap();
        session.apply(SessionEvent::RetryRequested).unwrap();
        session.apply(SessionEvent::HandshakeStarted).unwrap();

        let transition = session.apply(SessionEvent::HandshakeTimedOut).unwrap();
        assert_eq!(transition.to, LifecycleState::Closing);
        assert_eq!(session.handshake_attempts(), 2);
        assert!(session.apply(SessionEvent::RetryRequested).is_err());
    }

    #[test]
    fn rejects_authentication_failure_reconnect() {
        let mut session = SessionMachine::new(SessionPolicy::default());
        session.apply(SessionEvent::ConnectRequested).unwrap();
        session.apply(SessionEvent::HandshakeStarted).unwrap();
        session.apply(SessionEvent::AuthenticationFailed).unwrap();
        assert_eq!(session.state(), LifecycleState::Closing);
        assert!(session.apply(SessionEvent::RetryRequested).is_err());
    }

    #[test]
    fn closes_when_rekey_fails_without_reusing_the_old_session() {
        let mut session = SessionMachine::new(SessionPolicy::default());
        for event in [
            SessionEvent::ConnectRequested,
            SessionEvent::HandshakeStarted,
            SessionEvent::HandshakeSucceeded,
            SessionEvent::RekeyRequested,
        ] {
            session.apply(event).unwrap();
        }
        let transition = session.apply(SessionEvent::RekeyFailed).unwrap();
        assert_eq!(transition.to, LifecycleState::Closing);
        assert!(session.apply(SessionEvent::RetryRequested).is_err());
    }

    #[test]
    fn permission_revocation_closes_a_reconnecting_session() {
        let mut session = SessionMachine::new(SessionPolicy::default());
        for event in [
            SessionEvent::ConnectRequested,
            SessionEvent::HandshakeStarted,
            SessionEvent::HandshakeFailed,
        ] {
            session.apply(event).unwrap();
        }
        let transition = session.apply(SessionEvent::PermissionRevoked).unwrap();
        assert_eq!(transition.to, LifecycleState::Closing);
        assert!(session.apply(SessionEvent::RetryRequested).is_err());
    }

    #[test]
    fn server_shutdown_closes_during_handshake() {
        let mut session = SessionMachine::new(SessionPolicy::default());
        session.apply(SessionEvent::ConnectRequested).unwrap();
        session.apply(SessionEvent::HandshakeStarted).unwrap();
        assert_eq!(
            session.apply(SessionEvent::ServerShutdown).unwrap().to,
            LifecycleState::Closing
        );
    }

    #[test]
    fn explicit_close_is_valid_before_connecting() {
        let mut session = SessionMachine::new(SessionPolicy::default());
        assert_eq!(
            session.apply(SessionEvent::CloseRequested).unwrap().to,
            LifecycleState::Closing
        );
        assert!(session.apply(SessionEvent::RetryRequested).is_err());
    }
}
