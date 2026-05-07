//! Low-level `SQLCipher` (`sqlite3mc`) wrapper.
//!
//! Safe Rust types over the `SQLite` `C` FFI. Raw symbols are resolved at
//! compile time:
//!
//! - **Native** (`not(wasm32)`): linked against the `sqlite3mc` static library
//!   compiled from the downloaded amalgamation by `build.rs`.
//! - **WASM** (`wasm32`): delegated to `sqlite-wasm-rs` (with the
//!   `sqlite3mc` feature) which ships its own `WASM`-compiled `sqlite3mc`.
//!
//! The internal `ffi` module is the only file in this crate that contains
//! `unsafe` code or `C` types.

mod ffi;

pub mod cipher;
pub mod error;

mod connection;
mod statement;
mod transaction;
mod value;

pub use connection::Connection;
pub use error::{Error, Result};
pub use statement::{Row, Statement, StepResult};
pub use transaction::Transaction;
pub use value::Value;
