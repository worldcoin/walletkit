//! Generic encrypted `SQLite` (`sqlite3mc`) wrapper.
//!
//! The public API is exposed through [`sqlite`]:
//!
//! - safe Rust connection / transaction / statement types
//! - encrypted open helpers and integrity checks
//! - plaintext export / import helpers parameterized by caller-owned tables
//!
//! Raw FFI lives behind the `sqlite` module; consumer crates own their own
//! schema, queries, and higher-level storage policy.

pub mod sqlite;

#[cfg(test)]
mod tests;
