//! Key hierarchy management for credential storage.
//!
//! ## Key structure
//!
//! - `K_device`: device-bound root key managed by `DeviceKeystore`.
//! - `account_keys.bin`: account key envelope stored via `AtomicBlobStore` and
//!   containing `DeviceKeystore::seal` of `K_intermediate` with associated data
//!   `worldid:account-key-envelope`.
//! - `K_intermediate`: 32-byte per-account key unsealed at init and kept in
//!   memory for the lifetime of the storage handle.
//! - `SQLCipher` databases: `account.vault.sqlite` (authoritative) and
//!   `account.cache.sqlite` (non-authoritative) are opened with `K_intermediate`.
//! - Derived keys: per relying-party session keys may be derived from
//!   `K_intermediate` and cached in `account.cache.sqlite` for performance.

use secrecy::SecretBox;
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{
    error::StorageResult,
    traits::{AtomicBlobStore, DeviceKeystore},
    ACCOUNT_KEYS_FILENAME, ACCOUNT_KEY_ENVELOPE_AD,
};
use walletkit_db::LockGuard;

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
        lock: &LockGuard,
        now: u64,
    ) -> StorageResult<Self> {
        let intermediate_key = walletkit_db::init_or_open_envelope_key(
            &KeystoreAdapter { inner: keystore },
            &BlobStoreAdapter { inner: blob_store },
            lock,
            ACCOUNT_KEYS_FILENAME,
            ACCOUNT_KEY_ENVELOPE_AD,
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

struct KeystoreAdapter<'a> {
    inner: &'a dyn DeviceKeystore,
}

impl walletkit_db::Keystore for KeystoreAdapter<'_> {
    fn seal(
        &self,
        associated_data: &[u8],
        plaintext: &[u8],
    ) -> walletkit_db::StoreResult<Vec<u8>> {
        self.inner
            .seal(associated_data.to_vec(), plaintext.to_vec())
            .map_err(|err| walletkit_db::StoreError::Keystore(err.to_string()))
    }

    fn open_sealed(
        &self,
        associated_data: &[u8],
        ciphertext: &[u8],
    ) -> walletkit_db::StoreResult<Vec<u8>> {
        self.inner
            .open_sealed(associated_data.to_vec(), ciphertext.to_vec())
            .map_err(|err| walletkit_db::StoreError::Keystore(err.to_string()))
    }
}

struct BlobStoreAdapter<'a> {
    inner: &'a dyn AtomicBlobStore,
}

impl walletkit_db::AtomicBlobStore for BlobStoreAdapter<'_> {
    fn read(&self, path: &str) -> walletkit_db::StoreResult<Option<Vec<u8>>> {
        self.inner
            .read(path.to_string())
            .map_err(|err| walletkit_db::StoreError::BlobStore(err.to_string()))
    }

    fn write_atomic(&self, path: &str, bytes: &[u8]) -> walletkit_db::StoreResult<()> {
        self.inner
            .write_atomic(path.to_string(), bytes.to_vec())
            .map_err(|err| walletkit_db::StoreError::BlobStore(err.to_string()))
    }

    fn delete(&self, path: &str) -> walletkit_db::StoreResult<()> {
        self.inner
            .delete(path.to_string())
            .map_err(|err| walletkit_db::StoreError::BlobStore(err.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::error::StorageError;
    use crate::storage::tests_utils::{InMemoryBlobStore, InMemoryKeystore};
    use secrecy::ExposeSecret;
    use uuid::Uuid;
    use walletkit_db::Lock;

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
        let lock = Lock::open(&lock_path).expect("open lock");
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
        let lock = Lock::open(&lock_path).expect("open lock");
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
        let lock = Lock::open(&lock_path).expect("open lock");
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
