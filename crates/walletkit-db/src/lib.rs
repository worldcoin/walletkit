//! Encrypted on-device storage primitives for `WalletKit`.
//!
//! The crate provides building blocks shared by `walletkit-core::storage` and
//! sibling SDKs (e.g. `OrbKit`'s `OrbPcpStore`):
//!
//! - [`Vault`] — encrypted-database wrapper around a caller-supplied schema,
//!   exposing the underlying [`walletkit_sqlite::Connection`].
//! - [`blobs`] — content-addressed blob storage (`ensure_schema`, `put`,
//!   `get`), [`ContentId`], and [`compute_content_id`].
//! - [`init_or_open_envelope_key`] — sealed intermediate key persisted via
//!   [`AtomicBlobStore`].
//! - [`Lock`] / [`LockGuard`] — cross-process exclusive lock (`flock` /
//!   `LockFileEx` native, no-op on WASM).
//! - [`Keystore`] / [`AtomicBlobStore`] — plain-Rust trait surface for
//!   consumer-supplied platform integrations. Consumers that need FFI define
//!   their own annotated traits and adapt to these.
//!
//! Consumers own their schemas, FFI surfaces, and storage policy on top of
//! these primitives.

pub mod blobs;

mod envelope;
mod error;
mod lock;
mod traits;
mod vault;

pub use blobs::{compute_content_id, ContentId};
pub use envelope::init_or_open_envelope_key;
pub use error::{StoreError, StoreResult};
pub use lock::{Lock, LockGuard};
pub use traits::{AtomicBlobStore, Keystore};
pub use vault::Vault;

#[cfg(test)]
mod test_utils;
