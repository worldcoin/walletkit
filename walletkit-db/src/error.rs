//! Database error types for the safe `SQLite` wrapper.

use std::fmt;

/// Error code returned by `SQLite` operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DbErrorCode(pub i32);

impl fmt::Display for DbErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Error returned by database operations.
#[derive(Debug, PartialEq, Eq)]
pub struct DbError {
    /// `SQLite` result code.
    pub code: DbErrorCode,
    /// Human-readable error message (from `sqlite3_errmsg` when available).
    pub message: String,
}

impl DbError {
    /// Creates a new database error.
    pub(crate) fn new(code: i32, message: impl Into<String>) -> Self {
        Self {
            code: DbErrorCode(code),
            message: message.into(),
        }
    }
}

impl fmt::Display for DbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sqlite error {}: {}", self.code, self.message)
    }
}

impl std::error::Error for DbError {}

/// Result type for database operations.
pub type DbResult<T> = Result<T, DbError>;
