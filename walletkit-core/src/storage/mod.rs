//! Credential storage primitives: key envelope and key hierarchy helpers.

pub mod envelope;
pub mod error;
pub mod keys;
pub mod traits;

pub use error::{StorageError, StorageResult};
pub use keys::StorageKeys;
pub use traits::{AtomicBlobStore, DeviceKeystore};

pub(crate) const ACCOUNT_KEYS_FILENAME: &str = "account_keys.bin";
pub(crate) const ACCOUNT_KEY_ENVELOPE_AD: &[u8] = b"worldid:account-key-envelope";
pub(crate) const VAULT_KEY_AD: &[u8] = b"worldid:vault-key";
pub(crate) const CACHE_SALT: &[u8] = b"worldid:account-cache:salt";
pub(crate) const CACHE_INFO: &[u8] = b"worldid:account-cache";

#[cfg(test)]
pub(crate) mod tests_utils;
