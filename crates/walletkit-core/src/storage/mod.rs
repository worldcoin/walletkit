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
//! The vault, cache, and lock live under `<root>/worldid/` — see
//! [`crate::storage::StoragePaths`]. The account key envelope (`account_keys.bin`) is
//! written separately through the host's [`crate::storage::AtomicBlobStore`] and its
//! location is host-determined (not necessarily under `worldid/`); backup and
//! deletion must include it.
//!
//! ## Security and privacy properties
//!
//! Encryption, the sealed-envelope threat model, and integrity checks are covered by
//! the `walletkit-db` README.

pub mod cache;
pub mod credential_activity;
pub mod credential_storage;
pub mod credential_vault;
pub mod error;
pub mod keys;
pub mod paths;
pub mod traits;
pub mod types;

pub use cache::CacheDb;
pub use credential_activity::CredentialActivityStore;
pub use credential_storage::CredentialStore;
pub use credential_vault::CredentialVault;
pub use error::{StorageError, StorageResult};
pub use keys::{IntermediateKeyHandle, StorageKeys};
pub use paths::StoragePaths;
pub use traits::{
    AtomicBlobStore, CredentialActivityChangedListener,
    CredentialActivitySchemaMigratedListener, DeviceKeystore, StorageProvider,
    VaultChangedListener,
};
pub use types::{
    BlobKind, ContentId, CredentialActivityCredential,
    CredentialActivityCredentialSource, CredentialActivityCredentialType,
    CredentialActivityEntry, CredentialActivityFailureReason,
    CredentialActivityFinalization, CredentialActivityMetadata,
    CredentialActivityOutcome, CredentialActivityProofKind, CredentialActivityProtocol,
    CredentialActivityQuery, CredentialRecord, NewCredentialActivityEntry, Nullifier,
    ReplayGuardKind, ReplayGuardResult, RequestId,
};
pub use walletkit_db::{Lock as StorageLock, LockGuard as StorageLockGuard};

pub(crate) const ACCOUNT_KEYS_FILENAME: &str = "account_keys.bin";
pub(crate) const ACCOUNT_KEY_ENVELOPE_AD: &[u8] = b"worldid:account-key-envelope";

/// Removes a `SQLite` database file and its WAL/SHM sidecar files.
/// Best-effort: missing files are silently ignored, other errors are logged.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn remove_db_files(db_path: &std::path::Path) {
    for ext in &["sqlite", "sqlite-wal", "sqlite-shm"] {
        let path = db_path.with_extension(ext);
        if let Err(e) = std::fs::remove_file(&path) {
            if e.kind() != std::io::ErrorKind::NotFound {
                tracing::error!("Failed to delete {}: {e}", path.display());
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests_utils;
