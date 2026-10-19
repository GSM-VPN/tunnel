//! Bounded mapping between authenticated sessions and UDP endpoints.

use std::collections::HashMap;
use std::net::SocketAddr;

use crate::SessionId;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionEndpointError {
    InvalidCapacity,
    Duplicate(SessionId),
    Full,
    NotFound(SessionId),
    UnexpectedEndpoint {
        expected: SocketAddr,
        actual: SocketAddr,
    },
}

/// Bounded endpoint registry for sessions admitted by the authenticated layer.
///
/// A session is first associated with an endpoint through [`Self::pin`]. An
/// endpoint change must be initiated by the authenticated handshake boundary
/// through [`Self::rebind_after_authenticated_handshake`]; this type never
/// changes an endpoint as a side effect of validation.
#[derive(Debug)]
pub struct SessionEndpointTable {
    max_sessions: usize,
    endpoints: HashMap<SessionId, SocketAddr>,
}

impl SessionEndpointTable {
    /// Creates a table with a non-zero maximum number of session endpoints.
    ///
    /// # Errors
    ///
    /// Returns [`SessionEndpointError::InvalidCapacity`] for a zero limit.
    pub fn new(max_sessions: usize) -> Result<Self, SessionEndpointError> {
        if max_sessions == 0 {
            return Err(SessionEndpointError::InvalidCapacity);
        }
        Ok(Self {
            max_sessions,
            endpoints: HashMap::with_capacity(max_sessions),
        })
    }

    /// Pins the first endpoint after authenticated session admission.
    ///
    /// # Errors
    ///
    /// Returns [`SessionEndpointError::Duplicate`] for a registered session
    /// and [`SessionEndpointError::Full`] when the configured limit is reached.
    pub fn pin(
        &mut self,
        session_id: SessionId,
        endpoint: SocketAddr,
    ) -> Result<(), SessionEndpointError> {
        if self.endpoints.contains_key(&session_id) {
            return Err(SessionEndpointError::Duplicate(session_id));
        }
        if self.endpoints.len() >= self.max_sessions {
            return Err(SessionEndpointError::Full);
        }
        self.endpoints.insert(session_id, endpoint);
        Ok(())
    }

    /// Replaces an endpoint only after the caller completed an authenticated
    /// handshake and verified the server identity for the new path.
    ///
    /// # Errors
    ///
    /// Returns [`SessionEndpointError::NotFound`] when the session is not
    /// registered.
    pub fn rebind_after_authenticated_handshake(
        &mut self,
        session_id: SessionId,
        endpoint: SocketAddr,
    ) -> Result<(), SessionEndpointError> {
        let current = self
            .endpoints
            .get_mut(&session_id)
            .ok_or(SessionEndpointError::NotFound(session_id))?;
        *current = endpoint;
        Ok(())
    }

    /// Verifies that an incoming datagram came from the pinned endpoint.
    ///
    /// # Errors
    ///
    /// Returns [`SessionEndpointError::NotFound`] for an unknown session or
    /// [`SessionEndpointError::UnexpectedEndpoint`] for a mismatched sender.
    pub fn validate(
        &self,
        session_id: SessionId,
        actual: SocketAddr,
    ) -> Result<(), SessionEndpointError> {
        let expected = *self
            .endpoints
            .get(&session_id)
            .ok_or(SessionEndpointError::NotFound(session_id))?;
        if expected != actual {
            return Err(SessionEndpointError::UnexpectedEndpoint { expected, actual });
        }
        Ok(())
    }

    #[must_use]
    /// Returns the pinned endpoint for a registered session.
    pub fn endpoint(&self, session_id: SessionId) -> Option<SocketAddr> {
        self.endpoints.get(&session_id).copied()
    }

    /// Removes a session endpoint.
    ///
    /// # Errors
    ///
    /// Returns [`SessionEndpointError::NotFound`] when the session is not
    /// registered.
    pub fn remove(&mut self, session_id: SessionId) -> Result<SocketAddr, SessionEndpointError> {
        self.endpoints
            .remove(&session_id)
            .ok_or(SessionEndpointError::NotFound(session_id))
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.endpoints.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.endpoints.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::{SessionEndpointError, SessionEndpointTable};
    use crate::SessionId;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn id(value: u32) -> SessionId {
        SessionId::new(value).expect("valid ID")
    }

    fn endpoint(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
    }

    #[test]
    fn pins_and_validates_one_endpoint_per_session() {
        let mut table = SessionEndpointTable::new(2).expect("table creates");
        table.pin(id(1), endpoint(1000)).expect("endpoint pins");
        assert_eq!(table.endpoint(id(1)), Some(endpoint(1000)));
        assert_eq!(table.validate(id(1), endpoint(1000)), Ok(()));
        assert_eq!(
            table.validate(id(1), endpoint(1001)),
            Err(SessionEndpointError::UnexpectedEndpoint {
                expected: endpoint(1000),
                actual: endpoint(1001),
            })
        );
    }

    #[test]
    fn requires_explicit_authenticated_rebind() {
        let mut table = SessionEndpointTable::new(1).expect("table creates");
        table.pin(id(1), endpoint(1000)).expect("endpoint pins");
        assert_eq!(
            table.pin(id(1), endpoint(1001)),
            Err(SessionEndpointError::Duplicate(id(1)))
        );
        table
            .rebind_after_authenticated_handshake(id(1), endpoint(1001))
            .expect("rebind succeeds");
        assert_eq!(table.validate(id(1), endpoint(1001)), Ok(()));
    }

    #[test]
    fn enforces_capacity_and_registration() {
        let mut table = SessionEndpointTable::new(1).expect("table creates");
        table.pin(id(1), endpoint(1000)).expect("endpoint pins");
        assert_eq!(
            table.pin(id(2), endpoint(1001)),
            Err(SessionEndpointError::Full)
        );
        assert_eq!(
            table.validate(id(2), endpoint(1001)),
            Err(SessionEndpointError::NotFound(id(2)))
        );
        assert_eq!(table.remove(id(1)), Ok(endpoint(1000)));
        assert!(table.is_empty());
    }

    #[test]
    fn rejects_zero_capacity() {
        assert!(matches!(
            SessionEndpointTable::new(0),
            Err(SessionEndpointError::InvalidCapacity)
        ));
    }
}
