//! # Credential Store
//!
//! On-device, consistent, encrypted storage for World ID credentials.
//!
//! The storage layer handles structured storage of all credentials and their
//! associated data (only storage, the semantics of the associated data is the
//! Issuer's responsibility). In addition the storage layer handles encryption
//! and clean up after expiration.
//!
//! ## Components
//!
//! [`crate::storage::CredentialStore`] is the facade exposed to hosts (via `UniFFI`).
//! It owns the account key envelope and two databases:
//!
//! 1. **Vault database (`account.vault.sqlite`)** — authoritative storage for
//!    credentials, associated data blobs, issuer subject blinding factors, and the account
//!    leaf index. Corruption is a hard failure. See [`crate::storage::CredentialVault`].
//! 2. **Cache database (`account.cache.sqlite`)** — non-authoritative, regenerable
//!    entries: Merkle inclusion proof cache, per-account session seed, and nullifier
//!    replay guards. Subject to TTL pruning and can be rebuilt at any time without
//!    correctness loss. See [`crate::storage::CacheDb`].
//!
//! The encrypted-storage primitives beneath these — the sealed key envelope, the
//! `K_device` → `K_intermediate` key hierarchy, sqlite3mc encryption, the
//! cross-process lock, content-addressed blobs, and the threat model are owned by
//! the [`walletkit-db`](https://docs.rs/crate/walletkit-db/latest) crate.
//!
//! ## Keys
//!
//! Both databases are opened with the single `K_intermediate` managed by
//! `walletkit-db`.
//!
//! ## On-disk layout
//!
//! All artifacts live under `<root>/worldid/`; see [`crate::storage::StoragePaths`]
//! for the full file layout.
//!
//! ## Security and privacy properties
//!
//! Encryption, the sealed-envelope threat model, and integrity checks are covered by
//! the `walletkit-db` README. Specific to credential storage:
//!
//! - No filesystem paths encode `leaf_index`, RP identifiers, issuer names, or action
//!   name. See [`crate::storage::StoragePaths`].
//! - The vault (authoritative) holds the `leaf_index`, credentials, and blobs; the
//!   cache DB holds only regenerable, TTL-bounded entries.

pub mod cache;
pub mod credential_storage;
pub mod credential_vault;
pub mod error;
#[cfg(all(not(target_arch = "wasm32"), feature = "embed-zkeys"))]
pub mod groth16_cache;
pub mod keys;
pub mod paths;
pub mod traits;
pub mod types;

pub use cache::CacheDb;
pub use credential_storage::CredentialStore;
pub use credential_vault::CredentialVault;
pub use error::{StorageError, StorageResult};
#[cfg(all(not(target_arch = "wasm32"), feature = "embed-zkeys"))]
pub use groth16_cache::cache_embedded_groth16_material;
pub use keys::StorageKeys;
pub use paths::StoragePaths;
pub use traits::{
    AtomicBlobStore, DeviceKeystore, StorageProvider, VaultChangedListener,
};
pub use types::{
    BlobKind, ContentId, CredentialRecord, Nullifier, ReplayGuardKind,
    ReplayGuardResult, RequestId,
};
pub use walletkit_db::{Lock as StorageLock, LockGuard as StorageLockGuard};

pub(crate) const ACCOUNT_KEYS_FILENAME: &str = "account_keys.bin";
pub(crate) const ACCOUNT_KEY_ENVELOPE_AD: &[u8] = b"worldid:account-key-envelope";

#[cfg(test)]
pub(crate) mod tests_utils;
