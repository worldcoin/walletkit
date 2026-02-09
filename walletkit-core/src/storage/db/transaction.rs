//! Safe wrapper around a SQLite transaction.

use super::connection::Connection;
use super::error::DbResult;
use super::statement::Statement;
use super::value::Value;

/// Transaction isolation / locking behaviour.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionBehavior {
    /// `BEGIN DEFERRED` (the default).
    Deferred,
    /// `BEGIN IMMEDIATE` – acquires a RESERVED lock immediately.
    Immediate,
}

/// An open database transaction.
///
/// Automatically rolls back on drop unless explicitly committed.
pub struct Transaction<'conn> {
    conn: &'conn Connection,
    committed: bool,
}

impl<'conn> Transaction<'conn> {
    /// Begins a new transaction on `conn`.
    pub(super) fn begin(
        conn: &'conn Connection,
        behavior: TransactionBehavior,
    ) -> DbResult<Self> {
        let sql = match behavior {
            TransactionBehavior::Deferred => "BEGIN DEFERRED",
            TransactionBehavior::Immediate => "BEGIN IMMEDIATE",
        };
        conn.execute_batch(sql)?;
        Ok(Self {
            conn,
            committed: false,
        })
    }

    /// Commits the transaction.
    pub fn commit(mut self) -> DbResult<()> {
        self.conn.execute_batch("COMMIT")?;
        self.committed = true;
        Ok(())
    }

    // ── Delegated Connection methods ────────────────────────────────────

    /// See [`Connection::execute_batch`].
    pub fn execute_batch(&self, sql: &str) -> DbResult<()> {
        self.conn.execute_batch(sql)
    }

    /// See [`Connection::execute`].
    pub fn execute(&self, sql: &str, params: &[Value]) -> DbResult<usize> {
        self.conn.execute(sql, params)
    }

    /// See [`Connection::query_row`].
    pub fn query_row<T>(
        &self,
        sql: &str,
        params: &[Value],
        mapper: impl FnOnce(&Statement) -> DbResult<T>,
    ) -> DbResult<T> {
        self.conn.query_row(sql, params, mapper)
    }

    /// See [`Connection::query_row_optional`].
    pub fn query_row_optional<T>(
        &self,
        sql: &str,
        params: &[Value],
        mapper: impl FnOnce(&Statement) -> DbResult<T>,
    ) -> DbResult<T> {
        // Note: we unwrap the Option since Transaction callers always expect
        // a value or should use Connection directly.  Provide the full
        // optional version through the connection reference.
        self.conn
            .query_row_optional(sql, params, mapper)?
            .ok_or_else(|| {
                super::error::DbError::new(
                    super::ffi::SQLITE_DONE,
                    "query returned no rows",
                )
            })
    }

    /// See [`Connection::prepare`].
    pub fn prepare(&self, sql: &str) -> DbResult<Statement> {
        self.conn.prepare(sql)
    }

    /// See [`Connection::last_insert_rowid`].
    pub fn last_insert_rowid(&self) -> i64 {
        self.conn.last_insert_rowid()
    }

    /// See [`Connection::changes`].
    pub fn changes(&self) -> usize {
        self.conn.changes()
    }
}

impl Drop for Transaction<'_> {
    fn drop(&mut self) {
        if !self.committed {
            // Best-effort rollback.
            let _ = self.conn.execute_batch("ROLLBACK");
        }
    }
}
