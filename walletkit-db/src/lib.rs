//! Encrypted on-device storage primitives for `WalletKit`.
//!
//! The crate provides building blocks shared by `walletkit-core::storage` and
//! sibling SDKs (e.g. `OrbKit`'s `OrbPcpStore`):
//!
//! - [`sqlite`] — encrypted `SQLite` (`sqlite3mc`) wrapper with safe Rust
//!   connection / transaction / statement types.
//! - [`Vault`] — encrypted-database opener with caller-supplied schema.
//! - [`Blobs`], [`ContentId`], [`compute_content_id`] — content-addressed
//!   blob storage shared across consumer schemas.
//! - [`KeyEnvelope`] + [`init_or_open_envelope_key`] — sealed intermediate
//!   key persisted via [`AtomicBlobStore`].
//! - [`Lock`] / [`LockGuard`] — cross-process exclusive lock (`flock` /
//!   `LockFileEx` native, no-op on WASM).
//! - [`Keystore`] / [`AtomicBlobStore`] — plain-Rust trait surface for
//!   consumer-supplied platform integrations. Consumers that need FFI define
//!   their own annotated traits and adapt to these.
//!
//! Consumers own their schemas, FFI surfaces, and storage policy on top of
//! these primitives.

pub mod sqlite;

mod blobs;
mod envelope;
mod error;
mod lock;
mod traits;
mod vault;

pub use blobs::{compute_content_id, Blobs, ContentId};
pub use envelope::{init_or_open_envelope_key, KeyEnvelope};
pub use error::{StoreError, StoreResult};
pub use lock::{Lock, LockGuard};
pub use sqlite::{
    cipher, Connection, Error as DbError, Result as DbResult, Row, Statement,
    StepResult, Transaction, Value,
};
pub use traits::{AtomicBlobStore, Keystore};
pub use vault::Vault;

#[cfg(test)]
mod tests;
