//! Raw FFI bindings to SQLite, resolved at compile time via `cfg`.
//!
//! This module is the **only** place in the codebase that contains `unsafe` code
//! or C types (`*mut c_void`, `CString`, etc.). It exposes two safe handle types
//! -- [`RawDb`] and [`RawStmt`] -- whose methods perform the underlying FFI calls
//! and translate results into idiomatic Rust (`DbResult`, `String`, `Vec<u8>`).
//!
//! Why `unsafe` is required: SQLite is a C library. Calling any C function from
//! Rust is `unsafe` by definition because the Rust compiler cannot verify memory
//! safety across the FFI boundary. Each `unsafe` block below upholds the
//! following invariants:
//!
//! - Pointers passed to SQLite are either non-null (checked by the caller) or
//!   explicitly documented as nullable (e.g. `sqlite3_exec` callback).
//! - Strings are null-terminated via `CString` before being handed to C.
//! - Pointer lifetimes are tracked by `RawDb` / `RawStmt` ownership: a handle
//!   is valid from construction until `Drop`.
//! - `SQLITE_TRANSIENT` tells SQLite to copy bound data immediately, so Rust
//!   can safely free the source buffer after the call returns.
//!
//! On native targets the symbols come from the sqlite3mc static library compiled
//! by `build.rs`. On `wasm32` targets they come from `sqlite-wasm-rs`.

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void};

use super::error::{DbError, DbResult};

// -- SQLite constants (plain i32, no C types leaked to callers) ---------------

pub const SQLITE_OK: i32 = 0;
pub const SQLITE_ROW: i32 = 100;
pub const SQLITE_DONE: i32 = 101;
pub const SQLITE_NULL: i32 = 5;

pub const SQLITE_OPEN_READONLY: i32 = 0x0000_0001;
pub const SQLITE_OPEN_READWRITE: i32 = 0x0000_0002;
pub const SQLITE_OPEN_CREATE: i32 = 0x0000_0004;
pub const SQLITE_OPEN_FULLMUTEX: i32 = 0x0001_0000;

const SQLITE_TRANSIENT: isize = -1;
const SQLITE_ERROR: i32 = 1;

// -- Safe handle types --------------------------------------------------------

/// Opaque handle to an open `sqlite3` database.
///
/// All methods perform the underlying FFI call and convert the result to safe
/// Rust types. The database is closed when the handle is dropped.
pub(super) struct RawDb {
    ptr: *mut c_void,
}

/// Opaque handle to a prepared `sqlite3_stmt`.
///
/// The statement is finalized when the handle is dropped.
pub(super) struct RawStmt {
    ptr: *mut c_void,
    /// Kept to extract error messages via `sqlite3_errmsg`.
    db: *mut c_void,
}

// Safety: the handles represent single-owner resources. They are not `Sync`
// (no concurrent access) but can be moved between threads (`Send`), which the
// outer `Mutex<CredentialStoreInner>` guarantees.
unsafe impl Send for RawDb {}
unsafe impl Send for RawStmt {}

// -- RawDb implementation -----------------------------------------------------

impl RawDb {
    /// Opens (or creates) a database at the given `path`.
    pub fn open(path: &str, flags: i32) -> DbResult<Self> {
        let c_path = to_cstring(path)?;
        let mut ptr: *mut c_void = std::ptr::null_mut();

        // Safety: `c_path` is a valid null-terminated string. `ptr` is a local
        // out-pointer that SQLite writes to. VFS is null (use default).
        let rc = unsafe {
            raw::sqlite3_open_v2(c_path.as_ptr(), &mut ptr, flags as c_int, std::ptr::null())
        };

        if rc != SQLITE_OK as c_int {
            let msg = if !ptr.is_null() {
                let m = errmsg_from_ptr(ptr);
                // Safety: ptr was successfully allocated by sqlite3_open_v2 even
                // on error; we must close it.
                unsafe { raw::sqlite3_close_v2(ptr); }
                m
            } else {
                format!("sqlite3_open_v2 returned {rc}")
            };
            return Err(DbError::new(rc, msg));
        }

        Ok(Self { ptr })
    }

    /// Executes one or more semicolon-separated SQL statements. No results.
    pub fn exec(&self, sql: &str) -> DbResult<()> {
        let c_sql = to_cstring(sql)?;
        let mut errmsg: *mut c_char = std::ptr::null_mut();

        // Safety: self.ptr is valid for the lifetime of RawDb. c_sql is null-
        // terminated. Callback and arg are null (no result rows needed).
        let rc = unsafe {
            raw::sqlite3_exec(self.ptr, c_sql.as_ptr(), std::ptr::null(), std::ptr::null_mut(), &mut errmsg)
        };

        if rc != SQLITE_OK as c_int {
            let msg = if !errmsg.is_null() {
                // Safety: errmsg points to a C string allocated by SQLite.
                let s = unsafe { CStr::from_ptr(errmsg) }.to_string_lossy().into_owned();
                unsafe { raw::sqlite3_free(errmsg.cast()); }
                s
            } else {
                self.errmsg()
            };
            return Err(DbError::new(rc, msg));
        }

        Ok(())
    }

    /// Prepares a single SQL statement for execution.
    pub fn prepare(&self, sql: &str) -> DbResult<RawStmt> {
        let c_sql = to_cstring(sql)?;
        let mut stmt_ptr: *mut c_void = std::ptr::null_mut();

        // Safety: self.ptr is valid. c_sql is null-terminated. -1 tells SQLite
        // to read until the null terminator. tail pointer is unused.
        let rc = unsafe {
            raw::sqlite3_prepare_v2(self.ptr, c_sql.as_ptr(), -1, &mut stmt_ptr, std::ptr::null_mut())
        };

        if rc != SQLITE_OK as c_int || stmt_ptr.is_null() {
            return Err(DbError::new(rc, self.errmsg()));
        }

        Ok(RawStmt { ptr: stmt_ptr, db: self.ptr })
    }

    /// Returns the number of rows changed by the most recent statement.
    pub fn changes(&self) -> i32 {
        // Safety: self.ptr is valid.
        unsafe { raw::sqlite3_changes(self.ptr) }
    }

    /// Returns the rowid of the most recent successful INSERT.
    pub fn last_insert_rowid(&self) -> i64 {
        // Safety: self.ptr is valid.
        unsafe { raw::sqlite3_last_insert_rowid(self.ptr) }
    }

    /// Returns the most recent error message from SQLite.
    pub fn errmsg(&self) -> String {
        errmsg_from_ptr(self.ptr)
    }
}

impl Drop for RawDb {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            // Safety: self.ptr was obtained from sqlite3_open_v2 and is valid.
            unsafe { raw::sqlite3_close_v2(self.ptr); }
        }
    }
}

impl std::fmt::Debug for RawDb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RawDb").finish_non_exhaustive()
    }
}

// -- RawStmt implementation ---------------------------------------------------

impl RawStmt {
    /// Executes a single step. Returns `SQLITE_ROW` or `SQLITE_DONE`.
    pub fn step(&self) -> DbResult<i32> {
        // Safety: self.ptr is a valid prepared statement.
        let rc = unsafe { raw::sqlite3_step(self.ptr) };
        match rc {
            rc if rc == SQLITE_ROW as c_int => Ok(SQLITE_ROW),
            rc if rc == SQLITE_DONE as c_int => Ok(SQLITE_DONE),
            _ => Err(DbError::new(rc, self.errmsg())),
        }
    }

    /// Resets the statement so it can be stepped again.
    #[allow(dead_code)]
    pub fn reset(&self) -> DbResult<()> {
        // Safety: self.ptr is valid.
        let rc = unsafe { raw::sqlite3_reset(self.ptr) };
        if rc != SQLITE_OK as c_int {
            return Err(DbError::new(rc, self.errmsg()));
        }
        Ok(())
    }

    // -- Binding --------------------------------------------------------------

    pub fn bind_i64(&self, idx: i32, value: i64) -> DbResult<()> {
        // Safety: self.ptr is valid; idx is a 1-based parameter index.
        let rc = unsafe { raw::sqlite3_bind_int64(self.ptr, idx as c_int, value) };
        check(rc, self)
    }

    pub fn bind_blob(&self, idx: i32, value: &[u8]) -> DbResult<()> {
        // Safety: value.as_ptr() is valid for value.len() bytes.
        // SQLITE_TRANSIENT tells SQLite to copy the data immediately.
        let rc = unsafe {
            raw::sqlite3_bind_blob(
                self.ptr,
                idx as c_int,
                value.as_ptr().cast(),
                value.len() as c_int,
                SQLITE_TRANSIENT,
            )
        };
        check(rc, self)
    }

    pub fn bind_text(&self, idx: i32, value: &str) -> DbResult<()> {
        // Safety: value.as_ptr() is valid for value.len() bytes.
        // SQLITE_TRANSIENT tells SQLite to copy the data immediately.
        let rc = unsafe {
            raw::sqlite3_bind_text(
                self.ptr,
                idx as c_int,
                value.as_ptr().cast(),
                value.len() as c_int,
                SQLITE_TRANSIENT,
            )
        };
        check(rc, self)
    }

    pub fn bind_null(&self, idx: i32) -> DbResult<()> {
        // Safety: self.ptr is valid.
        let rc = unsafe { raw::sqlite3_bind_null(self.ptr, idx as c_int) };
        check(rc, self)
    }

    // -- Column reading -------------------------------------------------------

    pub fn column_i64(&self, col: i32) -> i64 {
        // Safety: self.ptr is valid; col is a 0-based column index.
        unsafe { raw::sqlite3_column_int64(self.ptr, col as c_int) }
    }

    pub fn column_blob(&self, col: i32) -> Vec<u8> {
        // Safety: blob pointer is valid until the next step/reset/finalize.
        // We copy immediately into a Vec.
        unsafe {
            let ptr = raw::sqlite3_column_blob(self.ptr, col as c_int);
            let len = raw::sqlite3_column_bytes(self.ptr, col as c_int);
            if ptr.is_null() || len <= 0 {
                Vec::new()
            } else {
                std::slice::from_raw_parts(ptr.cast::<u8>(), len as usize).to_vec()
            }
        }
    }

    pub fn column_text(&self, col: i32) -> String {
        // Safety: text pointer is valid until the next step/reset/finalize.
        // We copy immediately into a String.
        unsafe {
            let ptr = raw::sqlite3_column_text(self.ptr, col as c_int);
            if ptr.is_null() {
                String::new()
            } else {
                CStr::from_ptr(ptr).to_string_lossy().into_owned()
            }
        }
    }

    pub fn column_type(&self, col: i32) -> i32 {
        // Safety: self.ptr is valid.
        unsafe { raw::sqlite3_column_type(self.ptr, col as c_int) }
    }

    #[allow(dead_code)]
    pub fn column_count(&self) -> i32 {
        // Safety: self.ptr is valid.
        unsafe { raw::sqlite3_column_count(self.ptr) }
    }

    fn errmsg(&self) -> String {
        errmsg_from_ptr(self.db)
    }
}

impl Drop for RawStmt {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            // Safety: self.ptr was obtained from sqlite3_prepare_v2 and is valid.
            unsafe { raw::sqlite3_finalize(self.ptr); }
        }
    }
}

// -- Helpers (private) --------------------------------------------------------

fn to_cstring(s: &str) -> DbResult<CString> {
    CString::new(s).map_err(|e| DbError::new(SQLITE_ERROR, format!("nul byte in string: {e}")))
}

fn errmsg_from_ptr(db: *mut c_void) -> String {
    // Safety: db is a valid sqlite3 handle (or null, which we check).
    unsafe {
        let ptr = raw::sqlite3_errmsg(db);
        if ptr.is_null() {
            "unknown error".to_string()
        } else {
            CStr::from_ptr(ptr).to_string_lossy().into_owned()
        }
    }
}

fn check(rc: c_int, stmt: &RawStmt) -> DbResult<()> {
    if rc != SQLITE_OK as c_int {
        Err(DbError::new(rc, stmt.errmsg()))
    } else {
        Ok(())
    }
}

// -- Raw extern declarations (private, never exposed) -------------------------
//
// These are the actual C function signatures. On native they link against our
// compiled sqlite3mc static library. On WASM they delegate to sqlite-wasm-rs.

#[cfg(not(target_arch = "wasm32"))]
mod raw {
    use std::os::raw::{c_char, c_int, c_void};

    #[allow(dead_code, non_camel_case_types)]
    type sqlite3 = c_void;
    #[allow(dead_code, non_camel_case_types)]
    type sqlite3_stmt = c_void;

    extern "C" {
        pub fn sqlite3_open_v2(filename: *const c_char, pp_db: *mut *mut sqlite3, flags: c_int, z_vfs: *const c_char) -> c_int;
        pub fn sqlite3_close_v2(db: *mut sqlite3) -> c_int;
        pub fn sqlite3_exec(db: *mut sqlite3, sql: *const c_char, callback: *const c_void, arg: *mut c_void, errmsg: *mut *mut c_char) -> c_int;
        pub fn sqlite3_free(ptr: *mut c_void);
        pub fn sqlite3_prepare_v2(db: *mut sqlite3, z_sql: *const c_char, n_byte: c_int, pp_stmt: *mut *mut sqlite3_stmt, pz_tail: *mut *const c_char) -> c_int;
        pub fn sqlite3_step(stmt: *mut sqlite3_stmt) -> c_int;
        pub fn sqlite3_reset(stmt: *mut sqlite3_stmt) -> c_int;
        pub fn sqlite3_finalize(stmt: *mut sqlite3_stmt) -> c_int;
        pub fn sqlite3_bind_int64(stmt: *mut sqlite3_stmt, index: c_int, value: i64) -> c_int;
        pub fn sqlite3_bind_blob(stmt: *mut sqlite3_stmt, index: c_int, value: *const c_void, n: c_int, destructor: isize) -> c_int;
        pub fn sqlite3_bind_text(stmt: *mut sqlite3_stmt, index: c_int, value: *const c_char, n: c_int, destructor: isize) -> c_int;
        pub fn sqlite3_bind_null(stmt: *mut sqlite3_stmt, index: c_int) -> c_int;
        pub fn sqlite3_column_int64(stmt: *mut sqlite3_stmt, i_col: c_int) -> i64;
        pub fn sqlite3_column_blob(stmt: *mut sqlite3_stmt, i_col: c_int) -> *const c_void;
        pub fn sqlite3_column_bytes(stmt: *mut sqlite3_stmt, i_col: c_int) -> c_int;
        pub fn sqlite3_column_text(stmt: *mut sqlite3_stmt, i_col: c_int) -> *const c_char;
        pub fn sqlite3_column_type(stmt: *mut sqlite3_stmt, i_col: c_int) -> c_int;
        pub fn sqlite3_column_count(stmt: *mut sqlite3_stmt) -> c_int;
        pub fn sqlite3_errmsg(db: *mut sqlite3) -> *const c_char;
        pub fn sqlite3_changes(db: *mut sqlite3) -> c_int;
        pub fn sqlite3_last_insert_rowid(db: *mut sqlite3) -> i64;
    }
}

#[cfg(target_arch = "wasm32")]
mod raw {
    use std::os::raw::{c_char, c_int, c_void};
    use sqlite_wasm_rs as wasm;

    pub unsafe fn sqlite3_open_v2(filename: *const c_char, pp_db: *mut *mut c_void, flags: c_int, z_vfs: *const c_char) -> c_int {
        wasm::sqlite3_open_v2(filename.cast(), pp_db.cast(), flags, z_vfs.cast())
    }
    pub unsafe fn sqlite3_close_v2(db: *mut c_void) -> c_int { wasm::sqlite3_close_v2(db.cast()) }
    pub unsafe fn sqlite3_exec(db: *mut c_void, sql: *const c_char, callback: *const c_void, arg: *mut c_void, errmsg: *mut *mut c_char) -> c_int {
        wasm::sqlite3_exec(db.cast(), sql.cast(), std::mem::transmute(callback), arg, errmsg.cast())
    }
    pub unsafe fn sqlite3_free(ptr: *mut c_void) { wasm::sqlite3_free(ptr); }
    pub unsafe fn sqlite3_prepare_v2(db: *mut c_void, z_sql: *const c_char, n_byte: c_int, pp_stmt: *mut *mut c_void, pz_tail: *mut *const c_char) -> c_int {
        wasm::sqlite3_prepare_v2(db.cast(), z_sql.cast(), n_byte, pp_stmt.cast(), pz_tail.cast())
    }
    pub unsafe fn sqlite3_step(stmt: *mut c_void) -> c_int { wasm::sqlite3_step(stmt.cast()) }
    pub unsafe fn sqlite3_reset(stmt: *mut c_void) -> c_int { wasm::sqlite3_reset(stmt.cast()) }
    pub unsafe fn sqlite3_finalize(stmt: *mut c_void) -> c_int { wasm::sqlite3_finalize(stmt.cast()) }
    pub unsafe fn sqlite3_bind_int64(stmt: *mut c_void, index: c_int, value: i64) -> c_int { wasm::sqlite3_bind_int64(stmt.cast(), index, value) }
    pub unsafe fn sqlite3_bind_blob(stmt: *mut c_void, index: c_int, value: *const c_void, n: c_int, destructor: isize) -> c_int {
        wasm::sqlite3_bind_blob(stmt.cast(), index, value, n, destructor)
    }
    pub unsafe fn sqlite3_bind_text(stmt: *mut c_void, index: c_int, value: *const c_char, n: c_int, destructor: isize) -> c_int {
        wasm::sqlite3_bind_text(stmt.cast(), index, value.cast(), n, destructor)
    }
    pub unsafe fn sqlite3_bind_null(stmt: *mut c_void, index: c_int) -> c_int { wasm::sqlite3_bind_null(stmt.cast(), index) }
    pub unsafe fn sqlite3_column_int64(stmt: *mut c_void, i_col: c_int) -> i64 { wasm::sqlite3_column_int64(stmt.cast(), i_col) }
    pub unsafe fn sqlite3_column_blob(stmt: *mut c_void, i_col: c_int) -> *const c_void { wasm::sqlite3_column_blob(stmt.cast(), i_col) }
    pub unsafe fn sqlite3_column_bytes(stmt: *mut c_void, i_col: c_int) -> c_int { wasm::sqlite3_column_bytes(stmt.cast(), i_col) }
    pub unsafe fn sqlite3_column_text(stmt: *mut c_void, i_col: c_int) -> *const c_char { wasm::sqlite3_column_text(stmt.cast(), i_col).cast() }
    pub unsafe fn sqlite3_column_type(stmt: *mut c_void, i_col: c_int) -> c_int { wasm::sqlite3_column_type(stmt.cast(), i_col) }
    pub unsafe fn sqlite3_column_count(stmt: *mut c_void) -> c_int { wasm::sqlite3_column_count(stmt.cast()) }
    pub unsafe fn sqlite3_errmsg(db: *mut c_void) -> *const c_char { wasm::sqlite3_errmsg(db.cast()).cast() }
    pub unsafe fn sqlite3_changes(db: *mut c_void) -> c_int { wasm::sqlite3_changes(db.cast()) }
    pub unsafe fn sqlite3_last_insert_rowid(db: *mut c_void) -> i64 { wasm::sqlite3_last_insert_rowid(db.cast()) }
}
