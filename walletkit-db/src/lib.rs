//! Generic encrypted `SQLite` (`sqlite3mc`) wrapper.
//!
//! The public API:
//!
//! - safe Rust connection / transaction / statement types
//! - encrypted open helpers and integrity checks
//! - plaintext export / import helpers parameterized by caller-owned tables
//!
//! Raw FFI lives behind the [`sqlite`] module; consumer crates own their own
//! schema, queries, and higher-level storage policy.

pub mod sqlite;

pub use sqlite::{
    cipher, Connection, Error as DbError, Result as DbResult, Row, Statement,
    StepResult, Transaction, Value,
};

#[cfg(test)]
mod tests;
