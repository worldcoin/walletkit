//! Credential storage primitives: key envelope and key hierarchy helpers.

pub mod envelope;
pub mod error;
pub mod credential_storage;
pub mod paths;
pub mod keys;
pub mod lock;
pub mod types;
pub mod traits;
pub mod vault;
pub mod cache;
pub(crate) mod sqlcipher;

pub use error::{StorageError, StorageResult};
pub use credential_storage::{CredentialStorage, CredentialStore};
pub use paths::StoragePaths;
pub use keys::StorageKeys;
pub use lock::{StorageLock, StorageLockGuard};
pub use types::{
    BlobKind, ContentId, CredentialId, CredentialRecord, CredentialRecordFfi,
    CredentialStatus, Nullifier, ProofDisclosureKind, ProofDisclosureResult,
    ProofDisclosureResultFfi, RequestId,
};
pub use traits::{AtomicBlobStore, DeviceKeystore, StorageProvider};
pub use vault::VaultDb;
pub use cache::CacheDb;

pub(crate) const ACCOUNT_KEYS_FILENAME: &str = "account_keys.bin";
pub(crate) const ACCOUNT_KEY_ENVELOPE_AD: &[u8] = b"worldid:account-key-envelope";

#[cfg(test)]
pub(crate) mod tests_utils;
