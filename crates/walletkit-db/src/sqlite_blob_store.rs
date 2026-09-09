//! Atomic storage for sealed blobs. Each operation owns a short-lived connection.

use crate::{AtomicBlobStore, StoreResult};
use std::path::PathBuf;
use walletkit_sqlite::{params, plaintext::open_plaintext, Connection};

/// Stores opaque blobs in a separate, unencrypted `SQLite` database.
///
/// Callers must seal secrets before writing them. The store retains only a path;
/// statements and connections are dropped before each operation returns.
pub struct SqliteBlobStore {
    path: PathBuf,
}

impl SqliteBlobStore {
    /// Creates the blob table. On WASM, initialize the OPFS pool first.
    ///
    /// # Errors
    /// Returns an error if opening or creating the database fails.
    pub fn new(path: PathBuf) -> StoreResult<Self> {
        let store = Self { path };
        store.connect()?.execute_batch("CREATE TABLE IF NOT EXISTS atomic_blobs (path TEXT PRIMARY KEY NOT NULL, bytes BLOB NOT NULL) WITHOUT ROWID;")?;
        Ok(store)
    }

    fn connect(&self) -> StoreResult<Connection> {
        Ok(open_plaintext(&self.path, false)?)
    }
}

impl AtomicBlobStore for SqliteBlobStore {
    fn read(&self, path: String) -> StoreResult<Option<Vec<u8>>> {
        Ok(self.connect()?.query_row_optional(
            "SELECT bytes FROM atomic_blobs WHERE path=?1",
            params![path],
            |row| Ok(row.column_blob(0)),
        )?)
    }

    fn write_atomic(&self, path: String, bytes: Vec<u8>) -> StoreResult<()> {
        // A single autocommit statement is one atomic SQLite transaction.
        self.connect()?.execute("INSERT INTO atomic_blobs(path, bytes) VALUES (?1, ?2) ON CONFLICT(path) DO UPDATE SET bytes=excluded.bytes", params![path, bytes])?;
        Ok(())
    }

    fn delete(&self, path: String) -> StoreResult<()> {
        self.connect()?
            .execute("DELETE FROM atomic_blobs WHERE path=?1", params![path])?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reopens_replaces_and_deletes_without_retaining_a_connection() {
        walletkit_sqlite::test_utils::init_sqlite();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("envelopes.sqlite");
        let store = SqliteBlobStore::new(path.clone()).unwrap();
        assert_eq!(store.read("key".into()).unwrap(), None);
        store.write_atomic("key".into(), vec![0, 1, 255]).unwrap();
        let reopened = SqliteBlobStore::new(path.clone()).unwrap();
        assert_eq!(reopened.read("key".into()).unwrap(), Some(vec![0, 1, 255]));
        reopened.write_atomic("key".into(), vec![]).unwrap();
        assert_eq!(store.read("key".into()).unwrap(), Some(vec![]));
        store.delete("key".into()).unwrap();
        store.delete("key".into()).unwrap();
        assert_eq!(reopened.read("key".into()).unwrap(), None);
        // An exclusive connection can operate while both store objects exist.
        let conn = Connection::open(&path, false).unwrap();
        let schema = conn
            .query_row(
                "SELECT sql FROM sqlite_master WHERE name='atomic_blobs'",
                &[],
                |row| Ok(row.column_text(0)),
            )
            .unwrap();
        assert_eq!(schema, "CREATE TABLE atomic_blobs (path TEXT PRIMARY KEY NOT NULL, bytes BLOB NOT NULL) WITHOUT ROWID");
        conn.execute_batch("PRAGMA locking_mode=EXCLUSIVE; BEGIN EXCLUSIVE; COMMIT;")
            .unwrap();
    }
}
