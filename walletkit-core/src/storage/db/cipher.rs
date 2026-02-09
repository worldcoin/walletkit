//! sqlite3mc encryption configuration helpers.
//!
//! Replaces the former `sqlcipher.rs` module.  sqlite3mc uses the same
//! `PRAGMA key` syntax so the keying logic is nearly identical, but the
//! "is encryption available?" validation differs (no `PRAGMA cipher_version`
//! in sqlite3mc – we simply try to read from the database after keying).

use std::path::Path;

use zeroize::{Zeroize, Zeroizing};

use super::connection::Connection;
use super::error::{DbError, DbResult};
use super::ffi;

/// Opens a database connection at `path`.
///
/// This is a convenience that mirrors the old `sqlcipher::open_connection`.
pub(crate) fn open_connection(path: &Path, read_only: bool) -> DbResult<Connection> {
    Connection::open(path, read_only)
}

/// Applies sqlite3mc encryption keying.
///
/// The 32-byte `k_intermediate` is hex-encoded and passed via
/// `PRAGMA key = "x'<hex>'"`.  After keying, a lightweight read is
/// performed to verify the cipher is active and the key is correct.
pub(crate) fn apply_key(
    conn: &Connection,
    mut k_intermediate: [u8; 32],
) -> DbResult<()> {
    let key_hex = Zeroizing::new(hex::encode(k_intermediate));
    let pragma = Zeroizing::new(format!("PRAGMA key = \"x'{}'\";", key_hex.as_str()));
    conn.execute_batch(&pragma)?;

    // Verify the key is correct by attempting a read.  If the key is wrong
    // sqlite3mc will return SQLITE_NOTADB when we first touch a page.
    // A lightweight way to trigger this is to read from `sqlite_master`.
    conn.execute_batch("SELECT count(*) FROM sqlite_master;")
        .map_err(|e| {
            DbError::new(
                e.code.0,
                format!(
                    "encryption key verification failed (is the key correct?): {}",
                    e.message
                ),
            )
        })?;

    k_intermediate.zeroize();
    Ok(())
}

/// Configures durable WAL settings and enables foreign keys.
///
/// Rationale:
/// - `journal_mode = WAL` enables concurrent readers during writes
/// - `synchronous = FULL` maximizes crash consistency
/// - `foreign_keys = ON` enforces referential integrity
pub(crate) fn configure_connection(conn: &Connection) -> DbResult<()> {
    conn.execute_batch(
        "PRAGMA foreign_keys = ON;
         PRAGMA journal_mode = WAL;
         PRAGMA synchronous = FULL;",
    )
}

/// Runs a `PRAGMA integrity_check` and returns whether the database is healthy.
pub(crate) fn integrity_check(conn: &Connection) -> DbResult<bool> {
    let result = conn.query_row(
        "PRAGMA integrity_check;",
        &[],
        |stmt| Ok(stmt.column_text(0)),
    )?;
    Ok(result.trim() == "ok")
}

/// Opens a database, applies the encryption key, and configures the connection.
///
/// This is the common open-and-configure sequence used by both vault and cache.
pub(crate) fn open_encrypted(
    path: &Path,
    k_intermediate: [u8; 32],
    read_only: bool,
) -> DbResult<Connection> {
    let conn = open_connection(path, read_only)?;
    apply_key(&conn, k_intermediate)?;
    configure_connection(&conn)?;
    Ok(conn)
}

/// Maps a [`DbError`] into a [`StorageError`](crate::storage::error::StorageError).
pub(crate) fn map_db_err(err: &DbError) -> crate::storage::error::StorageError {
    if err.code.0 == ffi::SQLITE_DONE {
        // "no rows" is usually a vault/cache semantic error, not a DB crash.
        crate::storage::error::StorageError::VaultDb(err.message.clone())
    } else {
        crate::storage::error::StorageError::VaultDb(format!(
            "sqlite error {}: {}",
            err.code, err.message
        ))
    }
}
