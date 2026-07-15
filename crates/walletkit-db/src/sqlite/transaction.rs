//! Safe wrapper around a `SQLite` transaction.
//!
//! Automatically rolls back on drop unless explicitly committed.

use super::connection::Connection;
use super::error::DbResult;
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
    pub(super) fn begin(conn: &'conn Connection, immediate: bool) -> DbResult<Self> {
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
    pub fn commit(mut self) -> DbResult<()> {
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
    pub fn execute_batch(&self, sql: &str) -> DbResult<()> {
        self.conn.execute_batch(sql)
    }

    /// See [`Connection::execute`].
    ///
    /// # Errors
    ///
    /// Returns `Error` if preparation or execution fails.
    pub fn execute(&self, sql: &str, params: &[Value]) -> DbResult<usize> {
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
        mapper: impl FnOnce(&Row<'_, '_>) -> DbResult<T>,
    ) -> DbResult<T> {
        self.conn.query_row(sql, params, mapper)
    }

    /// See [`Connection::prepare`].
    ///
    /// # Errors
    ///
    /// Returns `Error` if the SQL is invalid.
    pub fn prepare(&self, sql: &str) -> DbResult<Statement<'_>> {
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

#[cfg(test)]
mod tests {
    use super::Connection;
    use crate::params;
    use crate::test_utils::init_sqlite;

    #[test]
    fn test_transaction_commit() {
        init_sqlite();
        let conn = Connection::open_in_memory().expect("open in-memory db");
        conn.execute_batch("CREATE TABLE t (id INTEGER PRIMARY KEY);")
            .expect("create table");
        {
            let tx = conn.transaction().expect("begin tx");
            tx.execute("INSERT INTO t (id) VALUES (?1)", params![42_i64])
                .expect("insert");
            tx.commit().expect("commit");
        }
        let result = conn
            .query_row("SELECT id FROM t WHERE id = 42", &[], |stmt| {
                Ok(stmt.column_i64(0))
            })
            .expect("query");
        assert_eq!(result, 42);
    }

    #[test]
    fn test_transaction_rollback_on_drop() {
        init_sqlite();
        let conn = Connection::open_in_memory().expect("open in-memory db");
        conn.execute_batch("CREATE TABLE t (id INTEGER PRIMARY KEY);")
            .expect("create table");
        {
            let tx = conn.transaction().expect("begin tx");
            tx.execute("INSERT INTO t (id) VALUES (?1)", params![99_i64])
                .expect("insert");
            // Drop without commit -> rollback
        }
        let result = conn
            .query_row_optional("SELECT id FROM t WHERE id = 99", &[], |stmt| {
                Ok(stmt.column_i64(0))
            })
            .expect("query");
        assert!(result.is_none());
    }
}
