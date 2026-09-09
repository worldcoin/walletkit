//! Resolved database keys and explicit envelope lifecycle helpers.
//!
//! `StorageKeys` holds `K_intermediate` regardless of its source. Hosts resolve
//! it from a sealed envelope or supply it directly before constructing storage.

use secrecy::SecretBox;
use std::sync::Arc;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::{
    error::{StorageError, StorageResult},
    traits::{AtomicBlobStore, DeviceKeystore},
    StoragePaths, StorageProvider, ACCOUNT_KEYS_FILENAME, ACCOUNT_KEY_ENVELOPE_AD,
};
use walletkit_db::Lock;

/// Resolved in-memory database keys, independent of their source.
///
/// Keys are zeroized when the last owner drops this object.
#[derive(Zeroize, ZeroizeOnDrop, uniffi::Object)]
#[allow(clippy::struct_field_names)]
pub struct StorageKeys {
    intermediate_key: SecretBox<[u8; 32]>,
}

#[uniffi::export]
impl StorageKeys {
    /// Takes a resolved 32-byte database key, for example derived from a passkey PRF.
    ///
    /// # Errors
    /// Returns an error if the key is not exactly 32 bytes.
    #[uniffi::constructor]
    pub fn from_bytes(database_key: Vec<u8>) -> StorageResult<Self> {
        let database_key = Zeroizing::new(database_key);
        if database_key.len() != 32 {
            return Err(StorageError::InvalidInput(
                "expected a 32-byte database key".into(),
            ));
        }
        let intermediate_key = SecretBox::init_with(|| {
            let mut key = [0; 32];
            key.copy_from_slice(&database_key);
            key
        });
        Ok(Self { intermediate_key })
    }

    /// Resolves the database key from a device-sealed envelope, creating it if absent.
    /// The platform integrations are used only during this call and are not retained.
    ///
    /// # Errors
    /// Returns an error if locking, envelope access, or key unsealing fails.
    #[uniffi::constructor]
    #[expect(
        clippy::needless_pass_by_value,
        reason = "UniFFI parameters require owned Arc handles"
    )]
    pub fn from_envelope(
        paths: Arc<StoragePaths>,
        keystore: Arc<dyn DeviceKeystore>,
        blob_store: Arc<dyn AtomicBlobStore>,
        now: u64,
    ) -> StorageResult<Self> {
        let lock = Lock::open(&paths.lock_path())?;
        Self::init(keystore.as_ref(), blob_store.as_ref(), &lock, now)
    }
}

/// Deletes the host-owned key envelope after closing/destroying its credential store.
/// This does not invalidate keys already held in memory by other owners.
///
/// # Errors
/// Returns an error if locking or envelope deletion fails.
#[uniffi::export]
#[expect(
    clippy::needless_pass_by_value,
    reason = "UniFFI parameters require owned Arc handles"
)]
pub fn delete_storage_key_envelope(
    paths: Arc<StoragePaths>,
    blob_store: Arc<dyn AtomicBlobStore>,
) -> StorageResult<()> {
    let lock = Lock::open(&paths.lock_path())?;
    let _guard = lock.lock()?;
    blob_store.delete(ACCOUNT_KEYS_FILENAME.to_string())
}

impl StorageKeys {
    /// Resolves an envelope key using a native host's platform provider.
    ///
    /// # Errors
    /// Returns an error if the envelope cannot be opened or created.
    pub fn from_provider(
        provider: &dyn StorageProvider,
        now: u64,
    ) -> StorageResult<Self> {
        Self::from_envelope(
            provider.paths(),
            provider.keystore(),
            provider.blob_store(),
            now,
        )
    }

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
// rule prevents a blanket impl across crates. `Keystore::seal` borrows its
// plaintext (see walletkit-db/src/traits.rs); `Ks::seal` is the single
// point where the secret is copied into an owned `Vec<u8>`, because
// `DeviceKeystore` is a uniffi callback interface and those only support
// pass-by-value parameters (no `&[u8]`). That copy — and any further copy
// the foreign (Swift/Kotlin/etc.) implementation makes on its own side — is
// outside Rust's control; this is an accepted uniffi limitation, not a bug.

struct Ks<'a>(&'a dyn DeviceKeystore);
impl walletkit_db::Keystore for Ks<'_> {
    fn seal(&self, aad: &[u8], pt: &[u8]) -> walletkit_db::StoreResult<Vec<u8>> {
        self.0
            .seal(aad.to_vec(), pt.to_vec())
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
    fn direct_key_requires_exactly_32_bytes() {
        for length in [0, 31, 33] {
            assert!(matches!(
                StorageKeys::from_bytes(vec![7; length]),
                Err(StorageError::InvalidInput(_))
            ));
        }
        let keys = StorageKeys::from_bytes(vec![7; 32]).expect("direct key");
        assert_eq!(keys.intermediate_key().expose_secret(), &[7; 32]);
    }

    #[test]
    fn envelope_resolution_does_not_retain_platform_components() {
        let root = tempfile::tempdir().expect("temp dir");
        let paths = Arc::new(StoragePaths::new(root.path()));
        let keystore = Arc::new(InMemoryKeystore::new());
        let blobs = Arc::new(InMemoryBlobStore::new());
        let weak_keystore = Arc::downgrade(&keystore);
        let weak_blobs = Arc::downgrade(&blobs);
        let _keys = StorageKeys::from_envelope(paths, keystore, blobs, 1000)
            .expect("resolve envelope");
        assert!(weak_keystore.upgrade().is_none());
        assert!(weak_blobs.upgrade().is_none());
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
