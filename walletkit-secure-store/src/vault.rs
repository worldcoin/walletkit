//! Encrypted `SQLCipher` database opener.
//!
//! [`Vault`] handles the three things every consumer needs to do correctly
//! when opening an encrypted local database: open with the intermediate
//! key, run the consumer's schema callback (idempotent `CREATE TABLE IF NOT
//! EXISTS …`), and run an integrity check. Consumers wrap [`Vault`] in
//! their own typed facade and add domain-specific queries.

use std::path::Path;

use secrecy::SecretBox;
use walletkit_db::{cipher, Connection, Transaction};

use crate::error::{StoreError, StoreResult};
use crate::lock::LockGuard;

/// Encrypted database wrapper produced by [`Vault::open`].
///
/// Wraps a [`walletkit_db::Connection`] and exposes the underlying connection
/// + transaction APIs for consumer-defined queries.
#[derive(Debug)]
pub struct Vault {
    conn: Connection,
}

impl Vault {
    /// Opens (or creates) an encrypted `SQLCipher` database at `path`,
    /// runs `ensure_schema`, then runs an integrity check.
    ///
    /// `ensure_schema` is invoked exactly once per call and must be
    /// idempotent (use `CREATE TABLE IF NOT EXISTS …` etc.). The integrity
    /// check runs after `ensure_schema` so any schema-time failures surface
    /// before integrity issues do.
    ///
    /// # Errors
    ///
    /// Returns an error if the database cannot be opened, keyed,
    /// schema-initialised, or if the integrity check fails.
    pub fn open<F>(
        path: &Path,
        k_intermediate: &SecretBox<[u8; 32]>,
        _lock: &LockGuard,
        ensure_schema: F,
    ) -> StoreResult<Self>
    where
        F: FnOnce(&Connection) -> StoreResult<()>,
    {
        let conn = cipher::open_encrypted(path, k_intermediate, false)
            .map_err(StoreError::from)?;
        ensure_schema(&conn)?;
        let vault = Self { conn };
        if !vault.check_integrity()? {
            return Err(StoreError::IntegrityCheckFailed(
                "integrity_check failed".to_string(),
            ));
        }
        Ok(vault)
    }

    /// Borrows the underlying connection for read-only queries.
    #[must_use]
    pub const fn connection(&self) -> &Connection {
        &self.conn
    }

    /// Begins a new transaction.
    ///
    /// # Errors
    ///
    /// Returns an error if the transaction cannot be started.
    pub fn transaction(&mut self) -> StoreResult<Transaction<'_>> {
        self.conn.transaction().map_err(StoreError::from)
    }

    /// Runs the `SQLCipher` integrity check.
    ///
    /// # Errors
    ///
    /// Returns an error if the check cannot be executed.
    pub fn check_integrity(&self) -> StoreResult<bool> {
        cipher::integrity_check(&self.conn).map_err(StoreError::from)
    }

    /// Exports a plaintext (unencrypted) copy of the database to `dest`.
    ///
    /// Stale copies at `dest` are removed first. The caller is responsible
    /// for deleting the exported file after use.
    ///
    /// # Errors
    ///
    /// Returns an error if the export fails.
    pub fn export_plaintext(
        &self,
        dest: &Path,
        _lock: &LockGuard,
    ) -> StoreResult<()> {
        if dest.exists() {
            std::fs::remove_file(dest).map_err(|e| {
                StoreError::Db(format!("failed to remove stale backup: {e}"))
            })?;
        }
        cipher::export_plaintext_copy(&self.conn, dest).map_err(StoreError::from)
    }

    /// Imports rows from a plaintext (unencrypted) database backup at
    /// `source` into this (empty) vault.
    ///
    /// # Errors
    ///
    /// Returns an error if the import fails.
    pub fn import_plaintext(
        &self,
        source: &Path,
        _lock: &LockGuard,
    ) -> StoreResult<()> {
        cipher::import_plaintext_copy(&self.conn, source).map_err(StoreError::from)
    }
}
