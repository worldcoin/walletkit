//! Credential storage primitives: key envelope and key hierarchy helpers.

pub mod envelope;
pub mod error;
pub mod keys;
pub mod types;
pub mod traits;
pub mod vault;
pub mod cache;
pub(crate) mod sqlcipher;

pub use error::{StorageError, StorageResult};
pub use keys::StorageKeys;
pub use types::{BlobKind, ContentId, CredentialId, CredentialRecord, CredentialStatus};
pub use traits::{AtomicBlobStore, DeviceKeystore};
pub use vault::VaultDb;
pub use cache::CacheDb;

pub(crate) const ACCOUNT_KEYS_FILENAME: &str = "account_keys.bin";
pub(crate) const ACCOUNT_KEY_ENVELOPE_AD: &[u8] = b"worldid:account-key-envelope";

#[cfg(test)]
pub(crate) mod tests_utils;
