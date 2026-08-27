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
pub mod credential_storage;
pub mod credential_vault;
#[cfg(any(test, all(target_arch = "wasm32", feature = "uniffi-wasm")))]
mod ephemeral;
pub mod error;
pub mod keys;
pub mod paths;
pub mod traits;
pub mod types;

pub use cache::CacheDb;
pub use credential_storage::CredentialStore;
pub use credential_vault::CredentialVault;
pub use error::{StorageError, StorageResult};
pub use keys::StorageKeys;
pub use paths::StoragePaths;
pub use traits::{
    ActivityChangedListener, AtomicBlobStore, DeviceKeystore, StorageProvider,
    VaultChangedListener,
};
pub use types::{
    ActivityEntry, ActivityFailureReason, ActivityMetadata, ActivityOutcome,
    ActivityQuery, BlobKind, ContentId, CredentialRecord, Nullifier, ProtocolVersion,
    ReplayGuardKind, ReplayGuardResult, RequestId,
};
pub use walletkit_db::{Lock as StorageLock, LockGuard as StorageLockGuard};

/// Deletes a closed `SQLite` database and its journal sidecars.
///
/// Best effort - logs failed operations but does not return an error.
pub(crate) fn delete_database_files(path: &std::path::Path) {
    for path in [
        path.to_path_buf(),
        path.with_extension("sqlite-journal"),
        path.with_extension("sqlite-wal"),
        path.with_extension("sqlite-shm"),
    ] {
        if let Err(err) = delete_database_file(&path) {
            tracing::error!("Failed to delete database file {}: {err}", path.display());
        }
    }
}

#[cfg(target_arch = "wasm32")]
fn delete_database_file(path: &std::path::Path) -> Result<(), String> {
    walletkit_sqlite::opfs::delete_file(path).map_err(|err| err.to_string())
}

#[cfg(not(target_arch = "wasm32"))]
fn delete_database_file(path: &std::path::Path) -> Result<(), String> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err.to_string()),
    }
}

/// Installs persistent encrypted browser storage in the current Web Worker.
///
/// This must be awaited once before initializing a [`CredentialStore`] on
/// WASM. The function fails when called outside a supported dedicated worker
/// or when another browsing context owns the same OPFS SAH pool.
///
/// # Errors
///
/// Returns [`StorageError::PersistentStorage`] when OPFS setup fails.
#[cfg(target_arch = "wasm32")]
#[uniffi::export]
pub async fn initialize_persistent_storage() -> StorageResult<()> {
    walletkit_sqlite::opfs::install()
        .await
        .map_err(|err| StorageError::PersistentStorage(err.to_string()))
}

pub(crate) const ACCOUNT_KEYS_FILENAME: &str = "account_keys.bin";
pub(crate) const ACCOUNT_KEY_ENVELOPE_AD: &[u8] = b"worldid:account-key-envelope";

#[cfg(test)]
pub(crate) mod tests_utils;
