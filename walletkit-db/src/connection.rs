//! Safe wrapper around a `SQLite` database connection.
//!
//! This file contains **no `unsafe` code**. All FFI interaction is delegated to
//! [`ffi::RawDb`] which encapsulates the raw pointers and C type conversions.

use std::path::Path;

use super::error::{DbError, DbResult};
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
    /// Returns `DbError` if `SQLite` cannot open the file.
    pub fn open(path: &Path, read_only: bool) -> DbResult<Self> {
        let path_str = path.to_string_lossy();
        let flags = if read_only {
            ffi::SQLITE_OPEN_READONLY | ffi::SQLITE_OPEN_FULLMUTEX
        } else {
            ffi::SQLITE_OPEN_READWRITE
                | ffi::SQLITE_OPEN_CREATE
                | ffi::SQLITE_OPEN_FULLMUTEX
        };
        let db = RawDb::open(&path_str, flags)?;
        Ok(Self { db })
    }

    /// Executes one or more SQL statements separated by semicolons.
    ///
    /// No result rows are returned. Suitable for DDL, PRAGMAs, and
    /// multi-statement scripts.
    ///
    /// # Errors
    ///
    /// Returns `DbError` if any statement fails.
    pub fn execute_batch(&self, sql: &str) -> DbResult<()> {
        self.db.exec(sql)
    }

    /// Like [`execute_batch`](Self::execute_batch) but zeroizes the internal
    /// C string buffer after execution. Use for SQL containing sensitive
    /// material (e.g. `PRAGMA key`).
    ///
    /// # Errors
    ///
    /// Returns `DbError` if the statement fails.
    pub fn execute_batch_zeroized(&self, sql: &str) -> DbResult<()> {
        self.db.exec_zeroized(sql)
    }

    /// Prepares a single SQL statement.
    ///
    /// # Errors
    ///
    /// Returns `DbError` if the SQL is invalid.
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
    /// Returns `DbError` if preparation or execution fails.
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
    /// Returns `DbError` if preparation, execution, or the mapper fails,
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
                Err(DbError::new(ffi::SQLITE_DONE, "query returned no rows"))
            }
        }
    }

    /// Like [`query_row`](Self::query_row) but returns `Ok(None)` when no row
    /// is returned.
    ///
    /// # Errors
    ///
    /// Returns `DbError` if preparation, execution, or the mapper fails.
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
    /// Returns `DbError` if `BEGIN DEFERRED` fails.
    pub fn transaction(&self) -> DbResult<Transaction<'_>> {
        Transaction::begin(self, false)
    }

    /// Begins an immediate transaction (acquires a RESERVED lock right away).
    ///
    /// # Errors
    ///
    /// Returns `DbError` if `BEGIN IMMEDIATE` fails.
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
    /// Returns `DbError` if the in-memory database cannot be opened.
    pub fn open_in_memory() -> DbResult<Self> {
        Self::open(Path::new(":memory:"), false)
    }
}
