//! Safe wrapper around a SQLite database connection.

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void};
use std::path::Path;

use super::error::{DbError, DbResult};
use super::ffi;
use super::statement::{Statement, StepResult};
use super::transaction::{Transaction, TransactionBehavior};
use super::value::Value;

/// A SQLite database connection.
///
/// The connection is closed when dropped.  It is **not** `Sync` – all access
/// must happen from a single thread (which matches the WASM single-thread
/// constraint and the native `Mutex`-guarded usage pattern).
pub struct Connection {
    /// Raw `sqlite3*` handle.
    db: *mut c_void,
}

// Safety: Connection is not Sync but is Send – it can be moved to another
// thread as long as only one thread accesses it at a time (enforced by the
// Mutex in CredentialStoreInner).
unsafe impl Send for Connection {}

impl Connection {
    /// Opens (or creates) a database at `path`.
    ///
    /// Pass `read_only = true` for read-only access.
    pub fn open(path: &Path, read_only: bool) -> DbResult<Self> {
        let path_str = path.to_string_lossy();
        let c_path = CString::new(path_str.as_bytes()).map_err(|e| {
            DbError::new(ffi::SQLITE_ERROR, format!("invalid path: {e}"))
        })?;

        let flags = if read_only {
            ffi::SQLITE_OPEN_READONLY | ffi::SQLITE_OPEN_FULLMUTEX
        } else {
            ffi::SQLITE_OPEN_READWRITE
                | ffi::SQLITE_OPEN_CREATE
                | ffi::SQLITE_OPEN_FULLMUTEX
        };

        let mut db: *mut c_void = std::ptr::null_mut();
        let rc = unsafe {
            ffi::sqlite3_open_v2(
                c_path.as_ptr(),
                &mut db,
                flags,
                std::ptr::null(),
            )
        };
        if rc != ffi::SQLITE_OK {
            // If open failed but we got a handle, extract the error and close.
            let msg = if !db.is_null() {
                let m = Self::errmsg_raw(db);
                unsafe { ffi::sqlite3_close_v2(db); }
                m
            } else {
                format!("sqlite3_open_v2 returned {rc}")
            };
            return Err(DbError::new(rc, msg));
        }
        Ok(Self { db })
    }

    /// Opens an in-memory database (useful for tests).
    pub fn open_in_memory() -> DbResult<Self> {
        Self::open(Path::new(":memory:"), false)
    }

    /// Returns the raw database handle (for use in [`Statement`] etc.).
    pub(super) fn raw(&self) -> *mut c_void {
        self.db
    }

    // ── execute_batch ───────────────────────────────────────────────────

    /// Executes one or more SQL statements separated by semicolons.
    ///
    /// No result rows are returned.  This is suitable for DDL, PRAGMAs, and
    /// multi-statement scripts.
    pub fn execute_batch(&self, sql: &str) -> DbResult<()> {
        let c_sql = CString::new(sql).map_err(|e| {
            DbError::new(ffi::SQLITE_ERROR, format!("nul in SQL: {e}"))
        })?;
        let mut errmsg: *mut c_char = std::ptr::null_mut();
        let rc = unsafe {
            ffi::sqlite3_exec(
                self.db,
                c_sql.as_ptr(),
                std::ptr::null(),
                std::ptr::null_mut(),
                &mut errmsg,
            )
        };
        if rc != ffi::SQLITE_OK {
            let msg = if !errmsg.is_null() {
                let s = unsafe { CStr::from_ptr(errmsg) }
                    .to_string_lossy()
                    .into_owned();
                unsafe { ffi::sqlite3_free(errmsg.cast()); }
                s
            } else {
                self.errmsg()
            };
            return Err(DbError::new(rc, msg));
        }
        Ok(())
    }

    // ── prepare ─────────────────────────────────────────────────────────

    /// Prepares a single SQL statement.
    pub fn prepare(&self, sql: &str) -> DbResult<Statement> {
        let c_sql = CString::new(sql).map_err(|e| {
            DbError::new(ffi::SQLITE_ERROR, format!("nul in SQL: {e}"))
        })?;
        let mut stmt: *mut c_void = std::ptr::null_mut();
        let rc = unsafe {
            ffi::sqlite3_prepare_v2(
                self.db,
                c_sql.as_ptr(),
                -1,
                &mut stmt,
                std::ptr::null_mut(),
            )
        };
        if rc != ffi::SQLITE_OK || stmt.is_null() {
            return Err(DbError::new(rc, self.errmsg()));
        }
        Ok(unsafe { Statement::from_raw(stmt, self.db) })
    }

    // ── execute (single statement) ──────────────────────────────────────

    /// Prepares and executes a single SQL statement with the given parameters.
    ///
    /// Returns the number of rows changed.
    pub fn execute(&self, sql: &str, params: &[Value]) -> DbResult<usize> {
        let mut stmt = self.prepare(sql)?;
        stmt.bind_values(params)?;
        stmt.step()?;
        Ok(unsafe { ffi::sqlite3_changes(self.db) as usize })
    }

    // ── query_row ───────────────────────────────────────────────────────

    /// Prepares and executes a statement, mapping exactly one result row.
    ///
    /// Returns an error if no row is returned.
    pub fn query_row<T>(
        &self,
        sql: &str,
        params: &[Value],
        mapper: impl FnOnce(&Statement) -> DbResult<T>,
    ) -> DbResult<T> {
        let mut stmt = self.prepare(sql)?;
        stmt.bind_values(params)?;
        match stmt.step()? {
            StepResult::Row => mapper(&stmt),
            StepResult::Done => Err(DbError::new(
                ffi::SQLITE_DONE,
                "query returned no rows",
            )),
        }
    }

    /// Like [`query_row`](Self::query_row) but returns `Ok(None)` when no row
    /// is returned.
    pub fn query_row_optional<T>(
        &self,
        sql: &str,
        params: &[Value],
        mapper: impl FnOnce(&Statement) -> DbResult<T>,
    ) -> DbResult<Option<T>> {
        let mut stmt = self.prepare(sql)?;
        stmt.bind_values(params)?;
        match stmt.step()? {
            StepResult::Row => mapper(&stmt).map(Some),
            StepResult::Done => Ok(None),
        }
    }

    // ── Rows iteration ──────────────────────────────────────────────────

    /// Prepares a statement and collects all matching rows.
    pub fn query_map<T>(
        &self,
        sql: &str,
        params: &[Value],
        mapper: impl Fn(&Statement) -> DbResult<T>,
    ) -> DbResult<Vec<T>> {
        let mut stmt = self.prepare(sql)?;
        stmt.bind_values(params)?;
        let mut results = Vec::new();
        loop {
            match stmt.step()? {
                StepResult::Row => results.push(mapper(&stmt)?),
                StepResult::Done => break,
            }
        }
        Ok(results)
    }

    // ── Transactions ─────────────────────────────────────────────────────

    /// Begins a deferred transaction.
    pub fn transaction(&self) -> DbResult<Transaction<'_>> {
        Transaction::begin(self, TransactionBehavior::Deferred)
    }

    /// Begins an immediate transaction (acquires RESERVED lock).
    pub fn transaction_immediate(&self) -> DbResult<Transaction<'_>> {
        Transaction::begin(self, TransactionBehavior::Immediate)
    }

    // ── last_insert_rowid ───────────────────────────────────────────────

    /// Returns the rowid of the most recent successful INSERT.
    pub fn last_insert_rowid(&self) -> i64 {
        unsafe { ffi::sqlite3_last_insert_rowid(self.db) }
    }

    // ── changes ─────────────────────────────────────────────────────────

    /// Returns the number of rows changed by the most recent statement.
    pub fn changes(&self) -> usize {
        unsafe { ffi::sqlite3_changes(self.db) as usize }
    }

    // ── Error helpers ───────────────────────────────────────────────────

    fn errmsg(&self) -> String {
        Self::errmsg_raw(self.db)
    }

    fn errmsg_raw(db: *mut c_void) -> String {
        unsafe {
            let ptr = ffi::sqlite3_errmsg(db);
            if ptr.is_null() {
                "unknown error".to_string()
            } else {
                CStr::from_ptr(ptr as *const c_char)
                    .to_string_lossy()
                    .into_owned()
            }
        }
    }
}

impl std::fmt::Debug for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connection")
            .field("db", &self.db)
            .finish()
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        if !self.db.is_null() {
            unsafe {
                ffi::sqlite3_close_v2(self.db);
            }
            self.db = std::ptr::null_mut();
        }
    }
}
