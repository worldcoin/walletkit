//! Minimal safe SQLite wrapper backed by sqlite3mc.
//!
//! This module provides a small, safe Rust API over the SQLite C FFI.
//! The raw symbols are resolved at compile time:
//!
//! * **Native** (`not(wasm32)`): linked against the sqlite3mc static library
//!   compiled from the vendored amalgamation by `build.rs`.
//! * **WASM** (`wasm32`): delegated to `sqlite-wasm-rs` (with the `sqlite3mc`
//!   feature) which ships its own WASM-compiled sqlite3mc.
//!
//! Consumer code (vault, cache, cipher config) uses only the safe types
//! defined here and never touches raw FFI directly.

pub(crate) mod ffi;

mod connection;
pub(crate) mod error;
mod statement;
mod transaction;
pub(crate) mod value;

pub(crate) mod cipher;

pub(crate) use connection::Connection;
pub(crate) use error::{DbError, DbResult};
pub(crate) use statement::{Statement, StepResult};
pub(crate) use transaction::{Transaction, TransactionBehavior};
pub(crate) use value::{params, Value};
