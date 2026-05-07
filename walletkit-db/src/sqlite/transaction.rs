//! Safe wrapper around a `SQLite` transaction.
//!
//! Automatically rolls back on drop unless explicitly committed.

use super::connection::Connection;
use super::error::Result;
use super::statement::{Row, Statement};
use super::value::Value;

/// An open database transaction.
///
/// Created via [`Connection::transaction`] or [`Connection::transaction_immediate`].
/// If the `Transaction` is dropped without calling [`commit`](Self::commit),
/// the transaction is rolled back automatically.
pub struct Transaction<'conn> {
    conn: &'conn Connection,
    committed: bool,
}

impl<'conn> Transaction<'conn> {
    /// Begins a new transaction on `conn`.
    ///
    /// When `immediate` is true, the transaction acquires a RESERVED lock
    /// immediately (`BEGIN IMMEDIATE`) rather than deferring it.
    pub(super) fn begin(conn: &'conn Connection, immediate: bool) -> Result<Self> {
        let sql = if immediate {
            "BEGIN IMMEDIATE"
        } else {
            "BEGIN DEFERRED"
        };
        conn.execute_batch(sql)?;
        Ok(Self {
            conn,
            committed: false,
        })
    }

    /// Commits the transaction.
    ///
    /// # Errors
    ///
    /// Returns `Error` if the COMMIT statement fails.
    pub fn commit(mut self) -> Result<()> {
        self.conn.execute_batch("COMMIT")?;
        self.committed = true;
        Ok(())
    }

    // -- Delegated Connection methods -----------------------------------------

    /// See [`Connection::execute_batch`].
    ///
    /// # Errors
    ///
    /// Returns `Error` if any statement fails.
    #[allow(dead_code)]
    pub fn execute_batch(&self, sql: &str) -> Result<()> {
        self.conn.execute_batch(sql)
    }

    /// See [`Connection::execute`].
    ///
    /// # Errors
    ///
    /// Returns `Error` if preparation or execution fails.
    pub fn execute(&self, sql: &str, params: &[Value]) -> Result<usize> {
        self.conn.execute(sql, params)
    }

    /// See [`Connection::query_row`].
    ///
    /// # Errors
    ///
    /// Returns `Error` if preparation, execution, or the mapper fails.
    pub fn query_row<T>(
        &self,
        sql: &str,
        params: &[Value],
        mapper: impl FnOnce(&Row<'_, '_>) -> Result<T>,
    ) -> Result<T> {
        self.conn.query_row(sql, params, mapper)
    }

    /// See [`Connection::prepare`].
    ///
    /// # Errors
    ///
    /// Returns `Error` if the SQL is invalid.
    pub fn prepare(&self, sql: &str) -> Result<Statement<'_>> {
        self.conn.prepare(sql)
    }
}

impl Drop for Transaction<'_> {
    fn drop(&mut self) {
        if !self.committed {
            let _ = self.conn.execute_batch("ROLLBACK");
        }
    }
}
