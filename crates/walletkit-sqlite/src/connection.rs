//! Safe wrapper around a `SQLite` database connection.
//!
//! This file contains **no `unsafe` code**. All FFI interaction is delegated to
//! [`ffi::RawDb`] which encapsulates the raw pointers and C type conversions.

use std::path::Path;

use super::error::{DbResult, Error};
use super::ffi::{self, RawDb};
use super::statement::{Row, Statement, StepResult};
use super::transaction::Transaction;
use super::value::Value;

/// A `SQLite` database connection.
///
/// Closed when dropped. Not `Sync` -- all access must happen from a single
/// thread (matches the WASM single-thread constraint and the native
/// `Mutex`-guarded usage in `CredentialStoreInner`).
pub struct Connection {
    db: RawDb,
}

impl Connection {
    /// Opens (or creates) a database at `path`.
    ///
    /// # Errors
    ///
    /// Returns `Error` if `SQLite` cannot open the file.
    pub fn open(path: impl AsRef<Path>, read_only: bool) -> DbResult<Self> {
        Self::open_with_vfs(path.as_ref(), read_only, None)
    }

    #[cfg(target_arch = "wasm32")]
    pub(crate) fn open_with_opfs_vfs(path: &Path, read_only: bool) -> DbResult<Self> {
        if !crate::opfs::is_installed() {
            return Err(Error::new(
                -1,
                "persistent OPFS storage must be installed before opening a database",
            ));
        }

        Self::open_with_vfs(path, read_only, Some(crate::opfs::ENCRYPTED_VFS_NAME))
    }

    /// Opens (or creates) a database using an explicitly selected VFS.
    fn open_with_vfs(
        path: &Path,
        read_only: bool,
        vfs: Option<&str>,
    ) -> DbResult<Self> {
        let path_str = path.to_string_lossy();
        let flags = if read_only {
            ffi::SQLITE_OPEN_READONLY | ffi::SQLITE_OPEN_FULLMUTEX
        } else {
            ffi::SQLITE_OPEN_READWRITE
                | ffi::SQLITE_OPEN_CREATE
                | ffi::SQLITE_OPEN_FULLMUTEX
        };
        let db = RawDb::open(&path_str, flags, vfs)?;
        Ok(Self { db })
    }

    /// Keeps temporary tables and indices in memory.
    ///
    /// `sqlite3mc` does not encrypt temporary databases, so allowing temporary
    /// storage to spill to a filesystem could expose plaintext at rest.
    ///
    /// # Errors
    /// Returns an error if the setting cannot be applied or verified.
    pub fn ensure_temp_store_memory(&self) -> DbResult<()> {
        const TEMP_STORE_MEMORY: i64 = 2;
        self.execute_batch("PRAGMA temp_store = MEMORY;")?;
        let actual =
            self.query_row("PRAGMA temp_store;", &[], |row| Ok(row.column_i64(0)))?;
        if actual == TEMP_STORE_MEMORY {
            Ok(())
        } else {
            Err(Error::new(
                -1,
                format!(
                    "could not ensure PRAGMA temp_store = MEMORY: expected {TEMP_STORE_MEMORY}, got {actual}"
                ),
            ))
        }
    }

    /// Replaces an existing schema with a read-only in-memory database image.
    ///
    /// Copies `bytes` into SQLite-owned memory, freed when the schema is detached
    /// or the connection closes. The input can be dropped immediately afterward.
    /// Use a disposable connection for untrusted images: malformed schemas can
    /// prevent further operations on that connection, including detaching them.
    /// The image must be a complete plaintext database in rollback-journal mode;
    /// WAL sidecars are not loaded. SQLite validates database contents when queried.
    ///
    /// # Errors
    /// Returns an error if the schema is unavailable or busy, the image is empty,
    /// or allocating or deserializing it fails.
    pub fn deserialize_readonly(&self, schema: &str, bytes: &[u8]) -> DbResult<()> {
        self.db.deserialize_readonly(schema, bytes)
    }

    /// Executes one or more SQL statements separated by semicolons.
    ///
    /// No result rows are returned. Suitable for DDL, PRAGMAs, and
    /// multi-statement scripts.
    ///
    /// # Errors
    ///
    /// Returns `Error` if any statement fails.
    pub fn execute_batch(&self, sql: &str) -> DbResult<()> {
        self.db.exec(sql)
    }

    /// Like [`execute_batch`](Self::execute_batch) but zeroizes the internal
    /// C string buffer after execution. Use for SQL containing sensitive
    /// material (e.g. `PRAGMA key`).
    ///
    /// # Errors
    ///
    /// Returns `Error` if the statement fails.
    pub fn execute_batch_zeroized(&self, sql: &str) -> DbResult<()> {
        self.db.exec_zeroized(sql)
    }

    /// Prepares a single SQL statement.
    ///
    /// # Errors
    ///
    /// Returns `Error` if the SQL is invalid.
    pub fn prepare(&self, sql: &str) -> DbResult<Statement<'_>> {
        let raw_stmt = self.db.prepare(sql)?;
        Ok(Statement::new(raw_stmt))
    }

    /// Prepares and executes a single SQL statement with the given parameters.
    ///
    /// Returns the number of rows changed.
    ///
    /// # Errors
    ///
    /// Returns `Error` if preparation or execution fails.
    pub fn execute(&self, sql: &str, params: &[Value]) -> DbResult<usize> {
        let mut stmt = self.prepare(sql)?;
        stmt.bind_values(params)?;
        stmt.step()?;
        Ok(usize::try_from(self.db.changes()).unwrap_or(0))
    }

    /// Prepares and executes a statement, mapping exactly one result row.
    ///
    /// Returns an error if no row is returned.
    ///
    /// # Errors
    ///
    /// Returns `Error` if preparation, execution, or the mapper fails,
    /// or if the query returns no rows.
    pub fn query_row<T>(
        &self,
        sql: &str,
        params: &[Value],
        mapper: impl FnOnce(&Row<'_, '_>) -> DbResult<T>,
    ) -> DbResult<T> {
        let mut stmt = self.prepare(sql)?;
        stmt.bind_values(params)?;
        match stmt.step()? {
            StepResult::Row(row) => mapper(&row),
            StepResult::Done => {
                Err(Error::new(ffi::SQLITE_DONE, "query returned no rows"))
            }
        }
    }

    /// Like [`query_row`](Self::query_row) but returns `Ok(None)` when no row
    /// is returned.
    ///
    /// # Errors
    ///
    /// Returns `Error` if preparation, execution, or the mapper fails.
    pub fn query_row_optional<T>(
        &self,
        sql: &str,
        params: &[Value],
        mapper: impl FnOnce(&Row<'_, '_>) -> DbResult<T>,
    ) -> DbResult<Option<T>> {
        let mut stmt = self.prepare(sql)?;
        stmt.bind_values(params)?;
        match stmt.step()? {
            StepResult::Row(row) => mapper(&row).map(Some),
            StepResult::Done => Ok(None),
        }
    }

    /// Begins a deferred transaction.
    ///
    /// # Errors
    ///
    /// Returns `Error` if `BEGIN DEFERRED` fails.
    pub fn transaction(&self) -> DbResult<Transaction<'_>> {
        Transaction::begin(self, false)
    }

    /// Begins an immediate transaction (acquires a RESERVED lock right away).
    ///
    /// # Errors
    ///
    /// Returns `Error` if `BEGIN IMMEDIATE` fails.
    pub fn transaction_immediate(&self) -> DbResult<Transaction<'_>> {
        Transaction::begin(self, true)
    }

    /// Returns the rowid of the most recent successful INSERT.
    #[allow(dead_code)]
    #[must_use]
    pub fn last_insert_rowid(&self) -> i64 {
        self.db.last_insert_rowid()
    }

    /// Returns the number of rows changed by the most recent statement.
    #[allow(dead_code)]
    #[must_use]
    pub fn changes(&self) -> usize {
        usize::try_from(self.db.changes()).unwrap_or(0)
    }
}

impl std::fmt::Debug for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connection").finish_non_exhaustive()
    }
}

#[cfg(test)]
impl Connection {
    /// Opens an in-memory database.
    ///
    /// # Errors
    ///
    /// Returns `Error` if the in-memory database cannot be opened.
    pub fn open_in_memory() -> DbResult<Self> {
        Self::open(":memory:", false)
    }
}

#[cfg(test)]
mod tests {
    use super::Connection;
    use crate::params;
    use crate::test_utils::init_sqlite;
    use crate::Value;

    #[test]
    fn test_open_in_memory() {
        init_sqlite();
        let conn = Connection::open_in_memory().expect("open in-memory db");
        conn.execute_batch("CREATE TABLE t (id INTEGER PRIMARY KEY, val TEXT);")
            .expect("create table");
        conn.execute(
            "INSERT INTO t (id, val) VALUES (?1, ?2)",
            params![1_i64, "hello"],
        )
        .expect("insert");
        let result = conn
            .query_row("SELECT val FROM t WHERE id = ?1", params![1_i64], |stmt| {
                Ok(stmt.column_text(0))
            })
            .expect("query");
        assert_eq!(result, "hello");
    }

    #[test]
    fn test_temp_store_memory_overrides_file_storage() {
        init_sqlite();
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA temp_store = FILE;").unwrap();
        conn.ensure_temp_store_memory().unwrap();
        let temp_store = conn
            .query_row("PRAGMA temp_store;", &[], |row| Ok(row.column_i64(0)))
            .unwrap();
        assert_eq!(temp_store, 2);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn test_deserialize_readonly_owns_image_and_preserves_main() {
        init_sqlite();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("source.sqlite");
        {
            let source = Connection::open(&path, false).unwrap();
            source
                .execute_batch(
                    "CREATE TABLE t(value TEXT); INSERT INTO t VALUES ('backup');",
                )
                .unwrap();
        }
        let mut image = std::fs::read(&path).unwrap();
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE local(value TEXT); ATTACH DATABASE ':memory:' AS incoming KEY '';")
            .unwrap();
        conn.deserialize_readonly("incoming", &image).unwrap();
        image.fill(0);
        drop(image);

        let source_value = conn
            .query_row("SELECT value FROM incoming.t", &[], |row| {
                Ok(row.column_text(0))
            })
            .unwrap();
        assert_eq!(source_value, "backup");
        assert!(conn
            .execute_batch("INSERT INTO incoming.t VALUES ('changed');")
            .is_err());
        conn.execute_batch("INSERT INTO local SELECT value FROM incoming.t;")
            .unwrap();
        conn.execute_batch("DETACH DATABASE incoming;").unwrap();
        let destination_value = conn
            .query_row("SELECT value FROM local", &[], |row| Ok(row.column_text(0)))
            .unwrap();
        assert_eq!(destination_value, "backup");

        let image = std::fs::read(&path).unwrap();
        assert!(conn.deserialize_readonly("missing", &image).is_err());
        assert!(conn.deserialize_readonly("temp", &image).is_err());
        conn.execute_batch("ATTACH DATABASE ':memory:' AS incoming KEY '';")
            .unwrap();
        conn.deserialize_readonly("incoming", &image).unwrap();
        let reloaded_count = conn
            .query_row("SELECT COUNT(*) FROM incoming.t", &[], |row| {
                Ok(row.column_i64(0))
            })
            .unwrap();
        assert_eq!(reloaded_count, 1);
        conn.execute_batch("DETACH DATABASE incoming;").unwrap();
    }

    #[test]
    fn test_query_row_optional_none() {
        init_sqlite();
        let conn = Connection::open_in_memory().expect("open in-memory db");
        conn.execute_batch("CREATE TABLE t (id INTEGER PRIMARY KEY);")
            .expect("create table");
        let result = conn
            .query_row_optional("SELECT id FROM t WHERE id = 999", &[], |stmt| {
                Ok(stmt.column_i64(0))
            })
            .expect("query");
        assert!(result.is_none());
    }

    #[test]
    fn test_blob_round_trip() {
        init_sqlite();
        let conn = Connection::open_in_memory().expect("open in-memory db");
        conn.execute_batch("CREATE TABLE t (id INTEGER PRIMARY KEY, data BLOB);")
            .expect("create table");
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        conn.execute(
            "INSERT INTO t (id, data) VALUES (?1, ?2)",
            params![1_i64, data.as_slice()],
        )
        .expect("insert");
        let result = conn
            .query_row("SELECT data FROM t WHERE id = 1", &[], |stmt| {
                Ok(stmt.column_blob(0))
            })
            .expect("query");
        assert_eq!(result, data);
    }

    #[test]
    fn test_null_handling() {
        init_sqlite();
        let conn = Connection::open_in_memory().expect("open in-memory db");
        conn.execute_batch("CREATE TABLE t (id INTEGER PRIMARY KEY, val TEXT);")
            .expect("create table");
        conn.execute(
            "INSERT INTO t (id, val) VALUES (?1, ?2)",
            params![1_i64, Value::Null],
        )
        .expect("insert");
        let result = conn
            .query_row("SELECT val FROM t WHERE id = 1", &[], |stmt| {
                Ok(stmt.is_column_null(0))
            })
            .expect("query");
        assert!(result);
    }
}
