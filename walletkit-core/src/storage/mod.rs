//! Credential storage primitives: key envelope and key hierarchy helpers.

pub mod cache;
pub mod credential_storage;
pub mod envelope;
pub mod error;
#[cfg(not(target_arch = "wasm32"))]
pub mod groth16_cache;
pub mod keys;
pub mod lock;
pub mod paths;
pub mod traits;
pub mod types;
pub mod vault;

pub use cache::CacheDb;
pub use credential_storage::CredentialStore;
pub use error::{StorageError, StorageResult};
#[cfg(not(target_arch = "wasm32"))]
pub use groth16_cache::cache_embedded_groth16_material;
pub use keys::StorageKeys;
pub use lock::{StorageLock, StorageLockGuard};
pub use paths::StoragePaths;
pub use traits::{
    AtomicBlobStore, DeviceKeystore, StorageProvider, VaultChangedListener,
};
pub use types::{
    BlobKind, ContentId, CredentialRecord, Nullifier, ReplayGuardKind,
    ReplayGuardResult, RequestId,
};
pub use vault::VaultDb;

pub(crate) const ACCOUNT_KEYS_FILENAME: &str = "account_keys.bin";
pub(crate) const ACCOUNT_KEY_ENVELOPE_AD: &[u8] = b"worldid:account-key-envelope";

#[cfg(test)]
pub(crate) mod tests_utils;
