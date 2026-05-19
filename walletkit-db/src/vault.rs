//! Encrypted vault: opens an encrypted database with a caller-supplied
//! schema and hands out the underlying [`Connection`].
//!
//! `SQLite` handles cross-process writer serialization itself in WAL mode
//! (which `cipher::open_encrypted` configures), so `Vault` does not wrap
//! mutations in a flock. Where flock IS load-bearing — the first-install
//! bootstrap race in [`crate::init_or_open_envelope_key`] and any
//! file-level orchestration on top of plaintext export/import — callers
//! acquire a [`crate::Lock`] explicitly. Keeping the lock out of `Vault`
//! avoids belt-and-suspenders flock acquisitions that don't add safety
//! beyond what `SQLite`'s own locking already provides.

use std::path::Path;

use secrecy::SecretBox;

use crate::error::{StoreError, StoreResult};
use crate::sqlite::{cipher, Connection, DbResult};

/// Open encrypted database wrapper.
///
/// Exposes the underlying [`Connection`] via [`Vault::connection`].
#[derive(Debug)]
pub struct Vault {
    conn: Connection,
}

impl Vault {
    /// Opens (or creates) the encrypted database at `db_path`, runs
    /// `ensure_schema`, and verifies integrity.
    ///
    /// `ensure_schema` runs after the database is opened and keyed but
    /// before the integrity check.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Db`] if open / key / schema fails or
    /// [`StoreError::IntegrityCheckFailed`] on corruption.
    pub fn open<F>(
        db_path: &Path,
        key: &SecretBox<[u8; 32]>,
        ensure_schema: F,
    ) -> StoreResult<Self>
    where
        F: FnOnce(&Connection) -> DbResult<()>,
    {
        let conn = cipher::open_encrypted(db_path, key, false)?;
        ensure_schema(&conn)?;
        if !cipher::integrity_check(&conn)? {
            return Err(StoreError::IntegrityCheckFailed(
                "integrity_check failed".to_string(),
            ));
        }
        Ok(Self { conn })
    }

    /// Borrows the underlying connection.
    ///
    /// `SQLite` (in WAL mode, which `cipher::open_encrypted` configures)
    /// serializes cross-process writers via its own file locks. Callers
    /// don't need to acquire anything to mutate.
    #[must_use]
    pub const fn connection(&self) -> &Connection {
        &self.conn
    }
}
