//! Raw FFI bindings to SQLite, resolved at compile time via `cfg`.
//!
//! On native targets the symbols come from the sqlite3mc static library
//! compiled by `build.rs`.  On `wasm32` targets they come from
//! `sqlite-wasm-rs` which ships its own WASM-compiled sqlite3mc.
//!
//! All pointer types use `*mut c_void` so that the two backend crate types
//! (`sqlite3`, `sqlite3_stmt`, etc.) do not leak into the rest of the code.

#![allow(non_camel_case_types, dead_code)]

use std::os::raw::{c_char, c_int, c_void};

// ── SQLite constants ────────────────────────────────────────────────────

pub const SQLITE_OK: c_int = 0;
pub const SQLITE_ERROR: c_int = 1;
pub const SQLITE_BUSY: c_int = 5;
pub const SQLITE_ROW: c_int = 100;
pub const SQLITE_DONE: c_int = 101;
pub const SQLITE_MISUSE: c_int = 21;

// Column type constants
pub const SQLITE_INTEGER: c_int = 1;
pub const SQLITE_FLOAT: c_int = 2;
pub const SQLITE_TEXT: c_int = 3;
pub const SQLITE_BLOB: c_int = 4;
pub const SQLITE_NULL: c_int = 5;

// Open flags
pub const SQLITE_OPEN_READONLY: c_int = 0x0000_0001;
pub const SQLITE_OPEN_READWRITE: c_int = 0x0000_0002;
pub const SQLITE_OPEN_CREATE: c_int = 0x0000_0004;
pub const SQLITE_OPEN_FULLMUTEX: c_int = 0x0001_0000;

// Destructor type aliases (transient = -1 means SQLite copies the data)
pub const SQLITE_TRANSIENT: isize = -1;

// ── Native backend ──────────────────────────────────────────────────────

#[cfg(not(target_arch = "wasm32"))]
mod imp {
    use super::*;

    type sqlite3 = c_void;
    type sqlite3_stmt = c_void;

    extern "C" {
        // Connection lifecycle
        pub fn sqlite3_open_v2(
            filename: *const c_char,
            pp_db: *mut *mut sqlite3,
            flags: c_int,
            z_vfs: *const c_char,
        ) -> c_int;

        pub fn sqlite3_close_v2(db: *mut sqlite3) -> c_int;

        // Execution
        pub fn sqlite3_exec(
            db: *mut sqlite3,
            sql: *const c_char,
            callback: *const c_void,
            arg: *mut c_void,
            errmsg: *mut *mut c_char,
        ) -> c_int;

        pub fn sqlite3_free(ptr: *mut c_void);

        // Prepared statements
        pub fn sqlite3_prepare_v2(
            db: *mut sqlite3,
            z_sql: *const c_char,
            n_byte: c_int,
            pp_stmt: *mut *mut sqlite3_stmt,
            pz_tail: *mut *const c_char,
        ) -> c_int;

        pub fn sqlite3_step(stmt: *mut sqlite3_stmt) -> c_int;
        pub fn sqlite3_reset(stmt: *mut sqlite3_stmt) -> c_int;
        pub fn sqlite3_finalize(stmt: *mut sqlite3_stmt) -> c_int;

        // Parameter binding
        pub fn sqlite3_bind_int64(
            stmt: *mut sqlite3_stmt,
            index: c_int,
            value: i64,
        ) -> c_int;

        pub fn sqlite3_bind_blob(
            stmt: *mut sqlite3_stmt,
            index: c_int,
            value: *const c_void,
            n: c_int,
            destructor: isize,
        ) -> c_int;

        pub fn sqlite3_bind_text(
            stmt: *mut sqlite3_stmt,
            index: c_int,
            value: *const c_char,
            n: c_int,
            destructor: isize,
        ) -> c_int;

        pub fn sqlite3_bind_null(
            stmt: *mut sqlite3_stmt,
            index: c_int,
        ) -> c_int;

        pub fn sqlite3_bind_parameter_count(
            stmt: *mut sqlite3_stmt,
        ) -> c_int;

        // Column reading
        pub fn sqlite3_column_int64(
            stmt: *mut sqlite3_stmt,
            i_col: c_int,
        ) -> i64;

        pub fn sqlite3_column_blob(
            stmt: *mut sqlite3_stmt,
            i_col: c_int,
        ) -> *const c_void;

        pub fn sqlite3_column_bytes(
            stmt: *mut sqlite3_stmt,
            i_col: c_int,
        ) -> c_int;

        pub fn sqlite3_column_text(
            stmt: *mut sqlite3_stmt,
            i_col: c_int,
        ) -> *const c_char;

        pub fn sqlite3_column_type(
            stmt: *mut sqlite3_stmt,
            i_col: c_int,
        ) -> c_int;

        pub fn sqlite3_column_count(
            stmt: *mut sqlite3_stmt,
        ) -> c_int;

        // Error reporting
        pub fn sqlite3_errmsg(db: *mut sqlite3) -> *const c_char;
        pub fn sqlite3_errcode(db: *mut sqlite3) -> c_int;

        // Changes
        pub fn sqlite3_changes(db: *mut sqlite3) -> c_int;

        pub fn sqlite3_last_insert_rowid(db: *mut sqlite3) -> i64;
    }
}

// ── WASM backend ────────────────────────────────────────────────────────

#[cfg(target_arch = "wasm32")]
mod imp {
    //! Thin wrappers around `sqlite_wasm_rs` that normalise pointer types
    //! to `*mut c_void` so callers are backend-agnostic.

    use super::*;

    // Re-use the upstream WASM crate.
    use sqlite_wasm_rs as wasm;

    // ── Connection lifecycle ────────────────────────────────────────────

    pub unsafe fn sqlite3_open_v2(
        filename: *const c_char,
        pp_db: *mut *mut c_void,
        flags: c_int,
        z_vfs: *const c_char,
    ) -> c_int {
        // sqlite-wasm-rs expects its own opaque pointer type; cast through.
        let pp = pp_db.cast::<*mut wasm::sqlite3>();
        wasm::sqlite3_open_v2(filename.cast(), pp, flags, z_vfs.cast())
    }

    pub unsafe fn sqlite3_close_v2(db: *mut c_void) -> c_int {
        wasm::sqlite3_close_v2(db.cast())
    }

    pub unsafe fn sqlite3_exec(
        db: *mut c_void,
        sql: *const c_char,
        callback: *const c_void,
        arg: *mut c_void,
        errmsg: *mut *mut c_char,
        ) -> c_int {
        wasm::sqlite3_exec(
            db.cast(),
            sql.cast(),
            std::mem::transmute(callback),
            arg,
            errmsg.cast(),
        )
    }

    pub unsafe fn sqlite3_free(ptr: *mut c_void) {
        wasm::sqlite3_free(ptr);
    }

    // ── Prepared statements ─────────────────────────────────────────────

    pub unsafe fn sqlite3_prepare_v2(
        db: *mut c_void,
        z_sql: *const c_char,
        n_byte: c_int,
        pp_stmt: *mut *mut c_void,
        pz_tail: *mut *const c_char,
    ) -> c_int {
        let pp = pp_stmt.cast::<*mut wasm::sqlite3_stmt>();
        wasm::sqlite3_prepare_v2(db.cast(), z_sql.cast(), n_byte, pp, pz_tail.cast())
    }

    pub unsafe fn sqlite3_step(stmt: *mut c_void) -> c_int {
        wasm::sqlite3_step(stmt.cast())
    }

    pub unsafe fn sqlite3_reset(stmt: *mut c_void) -> c_int {
        wasm::sqlite3_reset(stmt.cast())
    }

    pub unsafe fn sqlite3_finalize(stmt: *mut c_void) -> c_int {
        wasm::sqlite3_finalize(stmt.cast())
    }

    // ── Parameter binding ───────────────────────────────────────────────

    pub unsafe fn sqlite3_bind_int64(
        stmt: *mut c_void,
        index: c_int,
        value: i64,
    ) -> c_int {
        wasm::sqlite3_bind_int64(stmt.cast(), index, value)
    }

    pub unsafe fn sqlite3_bind_blob(
        stmt: *mut c_void,
        index: c_int,
        value: *const c_void,
        n: c_int,
        destructor: isize,
    ) -> c_int {
        wasm::sqlite3_bind_blob(stmt.cast(), index, value, n, destructor)
    }

    pub unsafe fn sqlite3_bind_text(
        stmt: *mut c_void,
        index: c_int,
        value: *const c_char,
        n: c_int,
        destructor: isize,
    ) -> c_int {
        wasm::sqlite3_bind_text(stmt.cast(), index, value.cast(), n, destructor)
    }

    pub unsafe fn sqlite3_bind_null(
        stmt: *mut c_void,
        index: c_int,
    ) -> c_int {
        wasm::sqlite3_bind_null(stmt.cast(), index)
    }

    pub unsafe fn sqlite3_bind_parameter_count(
        stmt: *mut c_void,
    ) -> c_int {
        wasm::sqlite3_bind_parameter_count(stmt.cast())
    }

    // ── Column reading ──────────────────────────────────────────────────

    pub unsafe fn sqlite3_column_int64(
        stmt: *mut c_void,
        i_col: c_int,
    ) -> i64 {
        wasm::sqlite3_column_int64(stmt.cast(), i_col)
    }

    pub unsafe fn sqlite3_column_blob(
        stmt: *mut c_void,
        i_col: c_int,
    ) -> *const c_void {
        wasm::sqlite3_column_blob(stmt.cast(), i_col)
    }

    pub unsafe fn sqlite3_column_bytes(
        stmt: *mut c_void,
        i_col: c_int,
    ) -> c_int {
        wasm::sqlite3_column_bytes(stmt.cast(), i_col)
    }

    pub unsafe fn sqlite3_column_text(
        stmt: *mut c_void,
        i_col: c_int,
    ) -> *const c_char {
        wasm::sqlite3_column_text(stmt.cast(), i_col).cast()
    }

    pub unsafe fn sqlite3_column_type(
        stmt: *mut c_void,
        i_col: c_int,
    ) -> c_int {
        wasm::sqlite3_column_type(stmt.cast(), i_col)
    }

    pub unsafe fn sqlite3_column_count(
        stmt: *mut c_void,
    ) -> c_int {
        wasm::sqlite3_column_count(stmt.cast())
    }

    // ── Error reporting ─────────────────────────────────────────────────

    pub unsafe fn sqlite3_errmsg(db: *mut c_void) -> *const c_char {
        wasm::sqlite3_errmsg(db.cast()).cast()
    }

    pub unsafe fn sqlite3_errcode(db: *mut c_void) -> c_int {
        wasm::sqlite3_errcode(db.cast())
    }

    // ── Changes ─────────────────────────────────────────────────────────

    pub unsafe fn sqlite3_changes(db: *mut c_void) -> c_int {
        wasm::sqlite3_changes(db.cast())
    }

    pub unsafe fn sqlite3_last_insert_rowid(db: *mut c_void) -> i64 {
        wasm::sqlite3_last_insert_rowid(db.cast())
    }
}

// ── Public re-exports ───────────────────────────────────────────────────

pub(crate) use imp::*;
