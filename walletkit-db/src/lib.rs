//! Minimal safe `SQLite` wrapper backed by `sqlite3mc`.
//!
//! This crate provides a small, safe Rust API over the `SQLite` C FFI.
//! The raw symbols are resolved at compile time:
//!
//! * **Native** (`not(wasm32)`): linked against the `sqlite3mc` static library
//!   compiled from the downloaded amalgamation by `build.rs`.
//! * **WASM** (`wasm32`): delegated to `sqlite-wasm-rs` (with the `sqlite3mc`
//!   feature) which ships its own WASM-compiled `sqlite3mc`.
//!
//! Consumer code (vault, cache, cipher config) uses only the safe types
//! defined here and never touches raw FFI directly. The `ffi` module is the
//! **only** file that contains `unsafe` code or C types.

mod ffi;

mod connection;
pub mod error;
mod statement;
mod transaction;
pub mod value;

pub mod cipher;

pub use connection::Connection;
pub use error::DbError;
pub use statement::{Statement, StepResult};
pub use transaction::Transaction;
pub use value::Value;

#[cfg(test)]
mod tests;
