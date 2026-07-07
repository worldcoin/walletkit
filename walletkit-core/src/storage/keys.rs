//! Key management for credential storage.
//!
//! [`StorageKeys`] opens (or creates on first use) the account key envelope via
//! `walletkit-db` and holds the resulting `K_intermediate` in memory for the lifetime
//! of the storage handle; both databases are opened with it. The `K_device` →
//! `K_intermediate` hierarchy, envelope sealing, and encryption are described in the
//! `walletkit-db` README.

use secrecy::SecretBox;
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{
    error::StorageResult,
    traits::{AtomicBlobStore, DeviceKeystore},
    ACCOUNT_KEYS_FILENAME, ACCOUNT_KEY_ENVELOPE_AD,
};
use walletkit_db::Lock;

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
        lock: &Lock,
        now: u64,
    ) -> StorageResult<Self> {
        let intermediate_key = walletkit_db::init_or_open_envelope_key(
            &Ks(keystore),
            &Bs(blob_store),
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

// Trait-object bridge from walletkit-core's uniffi-annotated traits onto
// walletkit-db's plain-Rust trait surface. Required because Rust's orphan
// rule prevents a blanket impl across crates; the wrappers are pure
// delegation since both trait shapes already use `Vec<u8>` / `String`.

struct Ks<'a>(&'a dyn DeviceKeystore);
impl walletkit_db::Keystore for Ks<'_> {
    fn seal(&self, aad: Vec<u8>, pt: Vec<u8>) -> walletkit_db::StoreResult<Vec<u8>> {
        self.0
            .seal(aad, pt)
            .map_err(|e| walletkit_db::StoreError::Keystore(e.to_string()))
    }
    fn open_sealed(
        &self,
        aad: Vec<u8>,
        ct: Vec<u8>,
    ) -> walletkit_db::StoreResult<Vec<u8>> {
        self.0
            .open_sealed(aad, ct)
            .map_err(|e| walletkit_db::StoreError::Keystore(e.to_string()))
    }
}

struct Bs<'a>(&'a dyn AtomicBlobStore);
impl walletkit_db::AtomicBlobStore for Bs<'_> {
    fn read(&self, path: String) -> walletkit_db::StoreResult<Option<Vec<u8>>> {
        self.0
            .read(path)
            .map_err(|e| walletkit_db::StoreError::BlobStore(e.to_string()))
    }
    fn write_atomic(
        &self,
        path: String,
        bytes: Vec<u8>,
    ) -> walletkit_db::StoreResult<()> {
        self.0
            .write_atomic(path, bytes)
            .map_err(|e| walletkit_db::StoreError::BlobStore(e.to_string()))
    }
    fn delete(&self, path: String) -> walletkit_db::StoreResult<()> {
        self.0
            .delete(path)
            .map_err(|e| walletkit_db::StoreError::BlobStore(e.to_string()))
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
        let keys_first =
            StorageKeys::init(&keystore, &blob_store, &lock, 100).expect("init");
        let keys_second =
            StorageKeys::init(&keystore, &blob_store, &lock, 200).expect("init");

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
        StorageKeys::init(&keystore, &blob_store, &lock, 123).expect("init");

        let other_keystore = InMemoryKeystore::new();
        match StorageKeys::init(&other_keystore, &blob_store, &lock, 456) {
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
        StorageKeys::init(&keystore, &blob_store, &lock, 123).expect("init");

        let mut bytes = blob_store
            .read(ACCOUNT_KEYS_FILENAME.to_string())
            .expect("read")
            .expect("present");
        bytes[0] ^= 0xFF;
        blob_store
            .write_atomic(ACCOUNT_KEYS_FILENAME.to_string(), bytes)
            .expect("write");

        match StorageKeys::init(&keystore, &blob_store, &lock, 456) {
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
