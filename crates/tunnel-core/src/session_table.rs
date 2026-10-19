//! Bounded session registry for the Rust Core.

use std::collections::HashMap;

use crate::SessionId;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionTableError {
    InvalidCapacity,
    Duplicate(SessionId),
    Full,
    NotFound(SessionId),
}

/// Session metadata registry with an explicit concurrent-session limit.
#[derive(Debug)]
pub struct SessionTable<T> {
    max_sessions: usize,
    sessions: HashMap<SessionId, T>,
}

impl<T> SessionTable<T> {
    /// Creates a table with a non-zero maximum number of sessions.
    ///
    /// # Errors
    ///
    /// Returns [`SessionTableError::InvalidCapacity`] for a zero limit.
    pub fn new(max_sessions: usize) -> Result<Self, SessionTableError> {
        if max_sessions == 0 {
            return Err(SessionTableError::InvalidCapacity);
        }
        Ok(Self {
            max_sessions,
            sessions: HashMap::with_capacity(max_sessions),
        })
    }

    /// Registers metadata without storing keys or packet contents.
    ///
    /// # Errors
    ///
    /// Returns [`SessionTableError::Duplicate`] for an existing ID or
    /// [`SessionTableError::Full`] when the configured limit is reached.
    pub fn insert(&mut self, session_id: SessionId, metadata: T) -> Result<(), SessionTableError> {
        if self.sessions.contains_key(&session_id) {
            return Err(SessionTableError::Duplicate(session_id));
        }
        if self.sessions.len() >= self.max_sessions {
            return Err(SessionTableError::Full);
        }
        self.sessions.insert(session_id, metadata);
        Ok(())
    }

    /// Removes and returns one session's metadata.
    ///
    /// # Errors
    ///
    /// Returns [`SessionTableError::NotFound`] when the ID is not registered.
    pub fn remove(&mut self, session_id: SessionId) -> Result<T, SessionTableError> {
        self.sessions
            .remove(&session_id)
            .ok_or(SessionTableError::NotFound(session_id))
    }

    #[must_use]
    pub fn get(&self, session_id: SessionId) -> Option<&T> {
        self.sessions.get(&session_id)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }

    #[must_use]
    pub fn ids(&self) -> Vec<SessionId> {
        self.sessions.keys().copied().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::{SessionTable, SessionTableError};
    use crate::SessionId;

    fn id(value: u32) -> SessionId {
        SessionId::new(value).expect("valid ID")
    }

    #[test]
    fn enforces_capacity_and_duplicate_ids() {
        let mut table = SessionTable::new(2).expect("table creates");
        table.insert(id(1), "first").unwrap();
        assert_eq!(
            table.insert(id(1), "duplicate"),
            Err(SessionTableError::Duplicate(id(1)))
        );
        table.insert(id(2), "second").unwrap();
        assert_eq!(table.insert(id(3), "full"), Err(SessionTableError::Full));
    }

    #[test]
    fn removes_and_lists_sessions_without_retaining_payloads() {
        let mut table = SessionTable::new(2).expect("table creates");
        table.insert(id(1), 10_u32).unwrap();
        table.insert(id(2), 20_u32).unwrap();
        assert_eq!(table.get(id(1)), Some(&10));
        assert_eq!(table.len(), 2);
        assert!(!table.is_empty());
        assert_eq!(table.ids().len(), 2);
        assert_eq!(table.remove(id(1)), Ok(10));
        assert_eq!(table.remove(id(1)), Err(SessionTableError::NotFound(id(1))));
    }

    #[test]
    fn rejects_zero_capacity() {
        assert!(matches!(
            SessionTable::<()>::new(0),
            Err(SessionTableError::InvalidCapacity)
        ));
    }
}
