//! Safe wrapper around a `SQLite` database connection.
//!
//! This file contains **no `unsafe` code**. All FFI interaction is delegated to
//! [`ffi::RawDb`] which encapsulates the raw pointers and C type conversions.

use std::path::Path;

use super::error::{Error, Result};
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
    pub fn open(path: &Path, read_only: bool) -> Result<Self> {
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
    /// Returns `Error` if any statement fails.
    pub fn execute_batch(&self, sql: &str) -> Result<()> {
        self.db.exec(sql)
    }

    /// Like [`execute_batch`](Self::execute_batch) but zeroizes the internal
    /// C string buffer after execution. Use for SQL containing sensitive
    /// material (e.g. `PRAGMA key`).
    ///
    /// # Errors
    ///
    /// Returns `Error` if the statement fails.
    pub fn execute_batch_zeroized(&self, sql: &str) -> Result<()> {
        self.db.exec_zeroized(sql)
    }

    /// Prepares a single SQL statement.
    ///
    /// # Errors
    ///
    /// Returns `Error` if the SQL is invalid.
    pub fn prepare(&self, sql: &str) -> Result<Statement<'_>> {
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
    pub fn execute(&self, sql: &str, params: &[Value]) -> Result<usize> {
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
        mapper: impl FnOnce(&Row<'_, '_>) -> Result<T>,
    ) -> Result<T> {
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
        mapper: impl FnOnce(&Row<'_, '_>) -> Result<T>,
    ) -> Result<Option<T>> {
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
    pub fn transaction(&self) -> Result<Transaction<'_>> {
        Transaction::begin(self, false)
    }

    /// Begins an immediate transaction (acquires a RESERVED lock right away).
    ///
    /// # Errors
    ///
    /// Returns `Error` if `BEGIN IMMEDIATE` fails.
    pub fn transaction_immediate(&self) -> Result<Transaction<'_>> {
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
    pub fn open_in_memory() -> Result<Self> {
        Self::open(Path::new(":memory:"), false)
    }
}
