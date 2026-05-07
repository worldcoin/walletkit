//! Encrypted vault opener with caller-supplied schema.
//!
//! [`Vault::open`] composes [`crate::sqlite::cipher::open_encrypted`], a
//! consumer-owned schema callback, and an integrity check into the standard
//! "open + key + ensure schema + verify" flow used by all `WalletKit`
//! storage consumers.

use std::path::Path;

use secrecy::SecretBox;

use crate::error::{StoreError, StoreResult};
use crate::lock::LockGuard;
use crate::sqlite::{cipher, Connection, Result as DbResult};

/// Encrypted-database wrapper holding the open `sqlite3mc` connection.
///
/// Consumers compose schema-specific operations on top via
/// [`Vault::connection`].
#[derive(Debug)]
pub struct Vault {
    conn: Connection,
}

impl Vault {
    /// Opens (or creates) an encrypted database at `path`, runs
    /// `ensure_schema`, then verifies integrity.
    ///
    /// `key` is the 32-byte intermediate key passed to `sqlite3mc`. `_lock`
    /// is an in-scope [`LockGuard`] that proves the caller serialized writes
    /// via [`crate::Lock`]. `ensure_schema` runs after the database is
    /// opened and keyed but before the integrity check, and may create
    /// tables, indexes, and triggers.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Db`] if opening, keying, or schema setup fails,
    /// or [`StoreError::IntegrityCheckFailed`] if `PRAGMA integrity_check`
    /// reports corruption.
    pub fn open<F>(
        path: &Path,
        key: &SecretBox<[u8; 32]>,
        _lock: &LockGuard,
        ensure_schema: F,
    ) -> StoreResult<Self>
    where
        F: FnOnce(&Connection) -> DbResult<()>,
    {
        let conn = cipher::open_encrypted(path, key, false)?;
        ensure_schema(&conn)?;
        let vault = Self { conn };
        if !cipher::integrity_check(&vault.conn)? {
            return Err(StoreError::IntegrityCheckFailed(
                "integrity_check failed".to_string(),
            ));
        }
        Ok(vault)
    }

    /// Borrows the underlying connection for direct SQL access.
    #[must_use]
    pub const fn connection(&self) -> &Connection {
        &self.conn
    }
}
