//! Encrypted on-device storage primitives shared across `WalletKit` consumers.
//!
//! This crate exposes the building blocks that any consumer needs to maintain
//! an encrypted, integrity-checked, content-addressed local store:
//!
//! - [`Vault`] — opens an `SQLCipher` database with a caller-provided schema
//!   callback and runs an integrity check.
//! - [`Blobs`] — content-addressed blob table with `put`/`get` helpers.
//!   Consumers use it to deduplicate and reference encrypted payloads.
//! - [`KeyEnvelope`] + [`init_or_open_envelope_key`] — `DeviceKeystore`-sealed
//!   envelope holding a 32-byte intermediate key, persisted via an
//!   [`AtomicBlobStore`].
//! - [`Lock`] — cross-process exclusive lock (file-backed on native targets,
//!   no-op on `wasm32`).
//!
//! Consumers (e.g. `walletkit-core`'s `CredentialStore`, `OrbKit`'s
//! `OrbPcpStore`) own their own SQL schemas and FFI surface; this crate only
//! provides the primitives. It is plain Rust and does not depend on
//! `uniffi`.

#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod blobs;
pub mod content_id;
pub mod envelope;
pub mod error;
pub mod key_init;
pub mod lock;
pub mod traits;
pub mod vault;

pub use blobs::Blobs;
pub use content_id::{compute_content_id, ContentId, CONTENT_ID_LEN};
pub use envelope::KeyEnvelope;
pub use error::{StoreError, StoreResult};
pub use key_init::init_or_open_envelope_key;
pub use lock::{Lock, LockGuard};
pub use traits::{AtomicBlobStore, Keystore};
pub use vault::Vault;
