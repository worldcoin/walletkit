//! Safe wrapper around a `SQLite` prepared statement.
//!
//! This file contains **no `unsafe` code**. All FFI interaction is delegated to
//! [`ffi::RawStmt`] which encapsulates the raw pointers and C type conversions.

use super::error::DbResult;
use super::ffi::{self, RawStmt};
use super::value::Value;

/// Result of a single `sqlite3_step` call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepResult {
    /// A result row is available.
    Row,
    /// The statement has finished executing.
    Done,
}

/// A prepared `SQLite` statement.
///
/// Created via [`Connection::prepare`](super::Connection::prepare).
/// Tied to the lifetime of the connection that created it.
/// Finalized when dropped.
pub struct Statement<'conn> {
    raw: RawStmt<'conn>,
}

impl<'conn> Statement<'conn> {
    /// Wraps a raw statement handle.
    pub(super) const fn new(raw: RawStmt<'conn>) -> Self {
        Self { raw }
    }

    /// Binds a slice of [`Value`]s to the statement parameters (1-indexed).
    pub fn bind_values(&self, values: &[Value]) -> DbResult<()> {
        for (i, val) in values.iter().enumerate() {
            let idx = i32::try_from(i + 1).expect("parameter index overflow");
            match val {
                Value::Integer(v) => self.raw.bind_i64(idx, *v)?,
                Value::Blob(v) => self.raw.bind_blob(idx, v)?,
                Value::Text(v) => self.raw.bind_text(idx, v)?,
                Value::Null => self.raw.bind_null(idx)?,
            }
        }
        Ok(())
    }

    /// Executes a single step.
    pub fn step(&self) -> DbResult<StepResult> {
        let rc = self.raw.step()?;
        if rc == ffi::SQLITE_ROW {
            Ok(StepResult::Row)
        } else {
            Ok(StepResult::Done)
        }
    }

    /// Reads a column as `i64`.
    pub fn column_i64(&self, idx: usize) -> i64 {
        self.raw
            .column_i64(i32::try_from(idx).expect("column index overflow"))
    }

    /// Reads a column as a blob. Returns an empty `Vec` for NULL.
    pub fn column_blob(&self, idx: usize) -> Vec<u8> {
        self.raw
            .column_blob(i32::try_from(idx).expect("column index overflow"))
    }

    /// Reads a column as a UTF-8 string. Returns an empty string for NULL.
    pub fn column_text(&self, idx: usize) -> String {
        self.raw
            .column_text(i32::try_from(idx).expect("column index overflow"))
    }

    /// Returns `true` if the column is SQL NULL.
    #[allow(dead_code)]
    pub fn is_column_null(&self, idx: usize) -> bool {
        self.raw
            .column_type(i32::try_from(idx).expect("column index overflow"))
            == ffi::SQLITE_NULL
    }
}
