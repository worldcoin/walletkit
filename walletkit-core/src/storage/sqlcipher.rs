//! Shared `SQLCipher` helpers for storage databases.

use std::fmt;
use std::path::Path;

use rusqlite::{Connection, OpenFlags};
use zeroize::{Zeroize, Zeroizing};

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
///
/// Pass `read_only = true` for read-only access; `false` enables read/write
/// access and creates the database if needed.
pub(super) fn open_connection(
    path: &Path,
    read_only: bool,
) -> SqlcipherResult<Connection> {
    let flags = if read_only {
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_FULL_MUTEX
    } else {
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_FULL_MUTEX
    };
    Ok(Connection::open_with_flags(path, flags)?)
}

/// Applies `SQLCipher` keying and validates cipher availability.
pub(super) fn apply_key(
    conn: &Connection,
    mut k_intermediate: [u8; 32],
) -> SqlcipherResult<()> {
    let key_hex = Zeroizing::new(hex::encode(k_intermediate));
    let pragma = Zeroizing::new(format!("PRAGMA key = \"x'{key_hex}'\";"));
    conn.execute_batch(&pragma)?;
    let cipher_version: String =
        conn.query_row("PRAGMA cipher_version;", [], |row| row.get(0))?;
    if cipher_version.trim().is_empty() {
        return Err(SqlcipherError::CipherUnavailable);
    }
    k_intermediate.zeroize();
    Ok(())
}

/// Configures durable WAL settings.
///
/// Rationale:
/// - `journal_mode = WAL` enables concurrent readers during writes
/// - `synchronous = FULL` maximizes crash consistency
pub(super) fn configure_connection(conn: &Connection) -> SqlcipherResult<()> {
    conn.execute_batch(
        "PRAGMA foreign_keys = ON;
         PRAGMA journal_mode = WAL;
         PRAGMA synchronous = FULL;",
    )?;
    Ok(())
}

/// Runs an integrity check.
///
/// Uses `PRAGMA integrity_check` to detect corruption on open.
pub(super) fn integrity_check(conn: &Connection) -> SqlcipherResult<bool> {
    let result: String =
        conn.query_row("PRAGMA integrity_check;", [], |row| row.get(0))?;
    Ok(result.trim() == "ok")
}
