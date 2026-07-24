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
    #[must_use]
    pub const fn connection(&self) -> &Connection {
        &self.conn
    }
}

#[cfg(test)]
mod tests {
    use super::Vault;
    use crate::blobs;
    use crate::error::StoreError;
    use crate::test_utils::init_sqlite;
    use secrecy::SecretBox;

    #[test]
    #[cfg(not(target_arch = "wasm32"))]
    fn test_vault_open_runs_schema_callback() {
        init_sqlite();
        let dir = tempfile::tempdir().expect("create temp dir");
        let db_path = dir.path().join("vault.sqlite");
        let key = SecretBox::init_with(|| [0x42u8; 32]);

        let vault = Vault::open(&db_path, &key, |conn| {
            blobs::ensure_schema(conn)?;
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS items (id INTEGER PRIMARY KEY);",
            )
        })
        .expect("open vault");

        let cid = blobs::put(vault.connection(), 7, b"payload", 1000).expect("put");
        let bytes = blobs::get(vault.connection(), &cid)
            .expect("get")
            .expect("present");
        assert_eq!(bytes, b"payload");
    }

    #[test]
    #[cfg(not(target_arch = "wasm32"))]
    fn test_vault_open_rejects_wrong_key() {
        init_sqlite();
        let dir = tempfile::tempdir().expect("create temp dir");
        let db_path = dir.path().join("vault.sqlite");
        let key = SecretBox::init_with(|| [0x11u8; 32]);
        let _ =
            Vault::open(&db_path, &key, blobs::ensure_schema).expect("create vault");
        let wrong = SecretBox::init_with(|| [0x22u8; 32]);
        let err = Vault::open(&db_path, &wrong, |_| Ok(())).expect_err("wrong key");
        assert!(matches!(err, StoreError::Db(_)));
    }
}
