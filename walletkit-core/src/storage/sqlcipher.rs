//! Shared `SQLCipher` helpers for storage databases.

use std::fmt;
use std::path::Path;

use rusqlite::{Connection, OpenFlags};

/// `SQLCipher` helper errors.
#[derive(Debug)]
pub enum SqlcipherError {
    /// `SQLite` error.
    Sqlite(rusqlite::Error),
    /// `SQLCipher` is unavailable in the current build.
    CipherUnavailable,
}

impl fmt::Display for SqlcipherError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sqlite(err) => write!(f, "{err}"),
            Self::CipherUnavailable => write!(f, "sqlcipher not available"),
        }
    }
}

impl From<rusqlite::Error> for SqlcipherError {
    fn from(err: rusqlite::Error) -> Self {
        Self::Sqlite(err)
    }
}

/// Result type for `SQLCipher` helper operations.
pub type SqlcipherResult<T> = Result<T, SqlcipherError>;

/// Opens a `SQLite` connection with consistent flags.
pub(super) fn open_connection(path: &Path) -> SqlcipherResult<Connection> {
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
        | OpenFlags::SQLITE_OPEN_CREATE
        | OpenFlags::SQLITE_OPEN_FULL_MUTEX;
    Ok(Connection::open_with_flags(path, flags)?)
}

/// Applies `SQLCipher` keying and validates cipher availability.
pub(super) fn apply_key(
    conn: &Connection,
    k_intermediate: [u8; 32],
) -> SqlcipherResult<()> {
    let key_hex = hex::encode(k_intermediate);
    let pragma = format!("PRAGMA key = \"x'{key_hex}'\";");
    conn.execute_batch(&pragma)?;
    let cipher_version: String =
        conn.query_row("PRAGMA cipher_version;", [], |row| row.get(0))?;
    if cipher_version.trim().is_empty() {
        return Err(SqlcipherError::CipherUnavailable);
    }
    Ok(())
}

/// Configures durable WAL settings.
pub(super) fn configure_connection(conn: &Connection) -> SqlcipherResult<()> {
    conn.execute_batch(
        "PRAGMA foreign_keys = ON;
         PRAGMA journal_mode = WAL;
         PRAGMA synchronous = FULL;",
    )?;
    Ok(())
}

/// Runs an integrity check.
pub(super) fn integrity_check(conn: &Connection) -> SqlcipherResult<bool> {
    let result: String =
        conn.query_row("PRAGMA integrity_check;", [], |row| row.get(0))?;
    Ok(result.trim() == "ok")
}
