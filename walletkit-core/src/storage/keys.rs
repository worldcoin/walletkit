//! Key hierarchy management for credential storage.
//!
//! Delegates the actual envelope load/create logic to
//! [`walletkit_secure_store::init_or_open_envelope_key`], passing the
//! credential-store-specific envelope filename and associated data so the
//! intermediate key is bound to this consumer's vault.

use secrecy::SecretBox;
use walletkit_secure_store::init_or_open_envelope_key;
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{
    error::StorageResult,
    lock::StorageLockGuard,
    traits::{
        AtomicBlobStore, AtomicBlobStoreAdapter, DeviceKeystore, DeviceKeystoreAdapter,
    },
    ACCOUNT_KEYS_FILENAME, ACCOUNT_KEY_ENVELOPE_AD,
};

/// In-memory account keys derived from the account key envelope.
///
/// Keys are held in memory for the lifetime of the storage handle.
#[derive(Zeroize, ZeroizeOnDrop)]
#[allow(clippy::struct_field_names)]
pub struct StorageKeys {
    intermediate_key: SecretBox<[u8; 32]>,
}

impl StorageKeys {
    /// Initializes storage keys by opening or creating the account key envelope.
    ///
    /// # Errors
    ///
    /// Returns an error if the envelope cannot be read, decrypted, or parsed,
    /// or if persistence to the blob store fails.
    pub fn init(
        keystore: &dyn DeviceKeystore,
        blob_store: &dyn AtomicBlobStore,
        lock: &StorageLockGuard,
        now: u64,
    ) -> StorageResult<Self> {
        let keystore_adapter = DeviceKeystoreAdapter::new(keystore);
        let blob_store_adapter = AtomicBlobStoreAdapter::new(blob_store);
        let intermediate_key = init_or_open_envelope_key(
            &keystore_adapter,
            &blob_store_adapter,
            ACCOUNT_KEYS_FILENAME,
            ACCOUNT_KEY_ENVELOPE_AD,
            lock,
            now,
        )?;
        Ok(Self { intermediate_key })
    }

    /// Returns a reference to the intermediate key's [`SecretBox`].
    #[must_use]
    pub const fn intermediate_key(&self) -> &SecretBox<[u8; 32]> {
        &self.intermediate_key
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::lock::StorageLock;
    use crate::storage::tests_utils::{InMemoryBlobStore, InMemoryKeystore};
    use crate::storage::error::StorageError;
    use secrecy::ExposeSecret;
    use uuid::Uuid;

    fn temp_lock_path() -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!("walletkit-keys-lock-{}.lock", Uuid::new_v4()));
        path
    }

    #[test]
    fn test_storage_keys_round_trip() {
        let keystore = InMemoryKeystore::new();
        let blob_store = InMemoryBlobStore::new();
        let lock_path = temp_lock_path();
        let lock = StorageLock::open(&lock_path).expect("open lock");
        let guard = lock.lock().expect("lock");
        let keys_first =
            StorageKeys::init(&keystore, &blob_store, &guard, 100).expect("init");
        let keys_second =
            StorageKeys::init(&keystore, &blob_store, &guard, 200).expect("init");

        assert_eq!(
            keys_first.intermediate_key.expose_secret(),
            keys_second.intermediate_key.expose_secret()
        );
        let _ = std::fs::remove_file(lock_path);
    }

    #[test]
    fn test_storage_keys_keystore_mismatch_fails() {
        let keystore = InMemoryKeystore::new();
        let blob_store = InMemoryBlobStore::new();
        let lock_path = temp_lock_path();
        let lock = StorageLock::open(&lock_path).expect("open lock");
        let guard = lock.lock().expect("lock");
        StorageKeys::init(&keystore, &blob_store, &guard, 123).expect("init");

        let other_keystore = InMemoryKeystore::new();
        match StorageKeys::init(&other_keystore, &blob_store, &guard, 456) {
            Err(
                StorageError::Crypto(_)
                | StorageError::InvalidEnvelope(_)
                | StorageError::Keystore(_),
            ) => {}
            Err(err) => panic!("unexpected error: {err}"),
            Ok(_) => panic!("expected error"),
        }
        let _ = std::fs::remove_file(lock_path);
    }

    #[test]
    fn test_storage_keys_tampered_envelope_fails() {
        let keystore = InMemoryKeystore::new();
        let blob_store = InMemoryBlobStore::new();
        let lock_path = temp_lock_path();
        let lock = StorageLock::open(&lock_path).expect("open lock");
        let guard = lock.lock().expect("lock");
        StorageKeys::init(&keystore, &blob_store, &guard, 123).expect("init");

        let mut bytes = blob_store
            .read(ACCOUNT_KEYS_FILENAME.to_string())
            .expect("read")
            .expect("present");
        bytes[0] ^= 0xFF;
        blob_store
            .write_atomic(ACCOUNT_KEYS_FILENAME.to_string(), bytes)
            .expect("write");

        match StorageKeys::init(&keystore, &blob_store, &guard, 456) {
            Err(
                StorageError::Serialization(_)
                | StorageError::Crypto(_)
                | StorageError::UnsupportedEnvelopeVersion(_),
            ) => {}
            Err(err) => panic!("unexpected error: {err}"),
            Ok(_) => panic!("expected error"),
        }
        let _ = std::fs::remove_file(lock_path);
    }
}
