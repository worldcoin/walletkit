//! Encrypted vault opener with caller-supplied schema.
//!
//! [`open_vault`] composes [`crate::sqlite::cipher::open_encrypted`], a
//! consumer-owned schema callback, and an integrity check into the standard
//! "open + key + ensure schema + verify" flow used by all `WalletKit`
//! storage consumers.

use std::path::Path;

use secrecy::SecretBox;

use crate::error::{StoreError, StoreResult};
use crate::lock::LockGuard;
use crate::sqlite::{cipher, Connection, Result as DbResult};

/// Opens (or creates) an encrypted database at `path`, runs `ensure_schema`,
/// then verifies integrity. Returns the open [`Connection`] for the caller
/// to compose schema-specific operations on top.
///
/// `key` is the 32-byte intermediate key passed to `sqlite3mc`. `_lock` is
/// an in-scope [`LockGuard`] that proves the caller serialized writes via
/// [`crate::Lock`]; the lock is required only for the open and the caller
/// re-acquires for each subsequent transaction. `ensure_schema` runs after
/// the database is opened and keyed but before the integrity check, and may
/// create tables, indexes, and triggers.
///
/// # Errors
///
/// Returns [`StoreError::Db`] if opening, keying, or schema setup fails, or
/// [`StoreError::IntegrityCheckFailed`] if `PRAGMA integrity_check` reports
/// corruption.
pub fn open_vault<F>(
    path: &Path,
    key: &SecretBox<[u8; 32]>,
    _lock: &LockGuard,
    ensure_schema: F,
) -> StoreResult<Connection>
where
    F: FnOnce(&Connection) -> DbResult<()>,
{
    let conn = cipher::open_encrypted(path, key, false)?;
    ensure_schema(&conn)?;
    if !cipher::integrity_check(&conn)? {
        return Err(StoreError::IntegrityCheckFailed(
            "integrity_check failed".to_string(),
        ));
    }
    Ok(conn)
}
