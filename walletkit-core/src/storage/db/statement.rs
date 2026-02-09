//! Safe wrapper around a SQLite prepared statement.

use std::ffi::CStr;
use std::os::raw::{c_char, c_int, c_void};

use super::error::{DbError, DbResult};
use super::ffi;
use super::value::Value;

/// Result of a single `sqlite3_step` call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepResult {
    /// A result row is available (SQLITE_ROW).
    Row,
    /// The statement has finished executing (SQLITE_DONE).
    Done,
}

/// A prepared SQLite statement.
///
/// Statements are created via [`Connection::prepare`](super::Connection::prepare)
/// and finalized when dropped.
pub struct Statement {
    /// Raw `sqlite3_stmt*` handle. Null only after explicit finalization.
    stmt: *mut c_void,
    /// Raw `sqlite3*` handle – kept for error messages.
    db: *mut c_void,
}

// Safety: the wrapper enforces single-owner semantics; the raw pointers are not
// shared across threads.  On WASM (single-threaded) this is always safe.
// On native, `Connection` is not `Sync` so statements won't cross threads.
unsafe impl Send for Statement {}

impl Statement {
    /// Creates a new `Statement` wrapping a raw pointer pair.
    ///
    /// # Safety
    ///
    /// `stmt` must be a valid, non-null `sqlite3_stmt*`.
    /// `db` must be the owning `sqlite3*` handle.
    pub(super) unsafe fn from_raw(stmt: *mut c_void, db: *mut c_void) -> Self {
        debug_assert!(!stmt.is_null());
        Self { stmt, db }
    }

    // ── Binding ─────────────────────────────────────────────────────────

    /// Binds a slice of [`Value`]s to the statement parameters (1-indexed).
    pub fn bind_values(&mut self, values: &[Value]) -> DbResult<()> {
        for (i, val) in values.iter().enumerate() {
            let idx = (i + 1) as c_int;
            let rc = match val {
                Value::Integer(v) => unsafe {
                    ffi::sqlite3_bind_int64(self.stmt, idx, *v)
                },
                Value::Blob(v) => unsafe {
                    ffi::sqlite3_bind_blob(
                        self.stmt,
                        idx,
                        v.as_ptr().cast(),
                        v.len() as c_int,
                        ffi::SQLITE_TRANSIENT,
                    )
                },
                Value::Text(v) => unsafe {
                    ffi::sqlite3_bind_text(
                        self.stmt,
                        idx,
                        v.as_ptr().cast(),
                        v.len() as c_int,
                        ffi::SQLITE_TRANSIENT,
                    )
                },
                Value::Null => unsafe { ffi::sqlite3_bind_null(self.stmt, idx) },
            };
            if rc != ffi::SQLITE_OK {
                return Err(self.last_error(rc));
            }
        }
        Ok(())
    }

    // ── Stepping ────────────────────────────────────────────────────────

    /// Executes a single step.
    pub fn step(&mut self) -> DbResult<StepResult> {
        let rc = unsafe { ffi::sqlite3_step(self.stmt) };
        match rc {
            ffi::SQLITE_ROW => Ok(StepResult::Row),
            ffi::SQLITE_DONE => Ok(StepResult::Done),
            _ => Err(self.last_error(rc)),
        }
    }

    /// Resets the statement so it can be stepped again.
    pub fn reset(&mut self) -> DbResult<()> {
        let rc = unsafe { ffi::sqlite3_reset(self.stmt) };
        if rc != ffi::SQLITE_OK {
            return Err(self.last_error(rc));
        }
        Ok(())
    }

    // ── Column reading ──────────────────────────────────────────────────

    /// Returns the number of columns in the result set.
    pub fn column_count(&self) -> usize {
        unsafe { ffi::sqlite3_column_count(self.stmt) as usize }
    }

    /// Reads a column as `i64`.
    pub fn column_i64(&self, idx: usize) -> i64 {
        unsafe { ffi::sqlite3_column_int64(self.stmt, idx as c_int) }
    }

    /// Reads a column as a blob (byte slice).  Returns an empty slice for NULL.
    pub fn column_blob(&self, idx: usize) -> Vec<u8> {
        unsafe {
            let ptr = ffi::sqlite3_column_blob(self.stmt, idx as c_int);
            let len = ffi::sqlite3_column_bytes(self.stmt, idx as c_int);
            if ptr.is_null() || len <= 0 {
                return Vec::new();
            }
            std::slice::from_raw_parts(ptr.cast::<u8>(), len as usize).to_vec()
        }
    }

    /// Reads a column as a UTF-8 string.  Returns an empty string for NULL.
    pub fn column_text(&self, idx: usize) -> String {
        unsafe {
            let ptr = ffi::sqlite3_column_text(self.stmt, idx as c_int);
            if ptr.is_null() {
                return String::new();
            }
            CStr::from_ptr(ptr).to_string_lossy().into_owned()
        }
    }

    /// Returns the storage class of column `idx`.
    pub fn column_type(&self, idx: usize) -> c_int {
        unsafe { ffi::sqlite3_column_type(self.stmt, idx as c_int) }
    }

    /// Returns `true` if the column is SQL NULL.
    pub fn is_column_null(&self, idx: usize) -> bool {
        self.column_type(idx) == ffi::SQLITE_NULL
    }

    /// Reads a column as an optional `i64` (returns `None` for NULL).
    pub fn column_optional_i64(&self, idx: usize) -> Option<i64> {
        if self.is_column_null(idx) {
            None
        } else {
            Some(self.column_i64(idx))
        }
    }

    /// Reads a column as an optional blob (returns `None` for NULL).
    pub fn column_optional_blob(&self, idx: usize) -> Option<Vec<u8>> {
        if self.is_column_null(idx) {
            None
        } else {
            Some(self.column_blob(idx))
        }
    }

    // ── Helpers ─────────────────────────────────────────────────────────

    fn last_error(&self, code: c_int) -> DbError {
        let msg = unsafe {
            let ptr = ffi::sqlite3_errmsg(self.db);
            if ptr.is_null() {
                "unknown error".to_string()
            } else {
                CStr::from_ptr(ptr as *const c_char)
                    .to_string_lossy()
                    .into_owned()
            }
        };
        DbError::new(code, msg)
    }
}

impl Drop for Statement {
    fn drop(&mut self) {
        if !self.stmt.is_null() {
            unsafe {
                ffi::sqlite3_finalize(self.stmt);
            }
            self.stmt = std::ptr::null_mut();
        }
    }
}
