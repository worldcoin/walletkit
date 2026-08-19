//! Key management for credential storage.
//!
//! [`StorageKeys`] opens (or creates on first use) the account key envelope via
//! `walletkit-db` and holds the resulting `K_intermediate` in memory for the lifetime
//! of the storage handle; both databases are opened with it. The `K_device` →
//! `K_intermediate` hierarchy, envelope sealing, and encryption are described in the
//! `walletkit-db` README.

use std::sync::{Arc, Mutex, MutexGuard};

use secrecy::SecretBox;

use super::{
    error::{StorageError, StorageResult},
    traits::{AtomicBlobStore, DeviceKeystore},
    ACCOUNT_KEYS_FILENAME, ACCOUNT_KEY_ENVELOPE_AD,
};
use walletkit_db::Lock;

/// The intermediate key, shared (via `Arc`) between [`StorageKeys`] and any
/// [`IntermediateKeyHandle`]s handed out from it. Wrapped in a `Mutex` rather
/// than exposed as a bare `Arc<SecretBox<_>>` so [`StorageKeys::destroy`] can
/// eagerly zeroize the key in place — setting the slot to `None` drops (and
/// so zeroizes, via `SecretBox`'s `ZeroizeOnDrop`) the key immediately, even
/// while other `Arc` clones (e.g. a `IntermediateKeyHandle` a host app kept
/// past logout) are still alive. Without this, zeroization would only occur
/// once the *last* `Arc` clone dropped, which a lingering host-held handle
/// could delay indefinitely.
type SharedIntermediateKey = Arc<Mutex<Option<SecretBox<[u8; 32]>>>>;

/// In-memory account keys derived from the account key envelope.
///
/// Keys are held in memory for the lifetime of the storage handle.
#[allow(clippy::struct_field_names)]
pub struct StorageKeys {
    intermediate_key: SharedIntermediateKey,
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

        Ok(Self {
            intermediate_key: Arc::new(Mutex::new(Some(intermediate_key))),
        })
    }

    /// Locks and returns a guard exposing the intermediate key's [`SecretBox`]
    /// via [`KeyGuard::as_secret`].
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::Lock`] if the mutex is poisoned.
    pub fn intermediate_key(&self) -> StorageResult<KeyGuard<'_>> {
        KeyGuard::lock(&self.intermediate_key)
    }

    /// Returns a cheaply-cloned, reference-counted pointer to the same shared
    /// key cell [`intermediate_key`](Self::intermediate_key) reads from — for
    /// constructing an [`IntermediateKeyHandle`] without copying the key
    /// bytes into a second `SecretBox`.
    #[must_use]
    pub fn intermediate_key_shared(&self) -> SharedIntermediateKey {
        Arc::clone(&self.intermediate_key)
    }

    /// Eagerly zeroizes the intermediate key, regardless of whether any
    /// [`IntermediateKeyHandle`] clones of it are still alive elsewhere.
    /// Subsequent [`intermediate_key`](Self::intermediate_key) or
    /// `IntermediateKeyHandle::with_exposed` calls return
    /// [`StorageError::NotInitialized`].
    ///
    /// Best-effort on a poisoned mutex: the key is likely unreachable in that
    /// case too (a panic while held means no live `MutexGuard` could still
    /// be exposing it), but zeroization can't be guaranteed to have run.
    pub fn destroy(&self) {
        if let Ok(mut guard) = self.intermediate_key.lock() {
            *guard = None;
        }
    }
}

/// Guard returned by [`StorageKeys::intermediate_key`], exposing the locked
/// [`SecretBox`] for as long as the guard is alive.
pub struct KeyGuard<'a>(MutexGuard<'a, Option<SecretBox<[u8; 32]>>>);

impl KeyGuard<'_> {
    fn lock(cell: &SharedIntermediateKey) -> StorageResult<KeyGuard<'_>> {
        cell.lock().map(KeyGuard).map_err(|_| {
            StorageError::Lock("intermediate key mutex poisoned".to_string())
        })
    }

    /// Returns a reference to the locked [`SecretBox`].
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::NotInitialized`] if the key has already been
    /// destroyed via [`StorageKeys::destroy`].
    pub fn as_secret(&self) -> StorageResult<&SecretBox<[u8; 32]>> {
        self.0.as_ref().ok_or(StorageError::NotInitialized)
    }
}

/// Opaque handle to the account's derived `K_intermediate`.
///
/// For opening a sibling storage object (e.g. `CredentialActivityStore`)
/// keyed by the same account key without exposing the raw bytes over the
/// FFI boundary. Shares the same underlying key cell as [`StorageKeys`] via
/// `Arc` rather than holding an independent copy of the key bytes — see
/// `SharedIntermediateKey` for why that cell is a `Mutex`, not a bare
/// `SecretBox`.
#[derive(uniffi::Object)]
pub struct IntermediateKeyHandle(SharedIntermediateKey);

impl IntermediateKeyHandle {
    pub(crate) const fn from_shared(key: SharedIntermediateKey) -> Self {
        Self(key)
    }

    /// Calls `f` with the locked intermediate key.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::Lock`] if the mutex is poisoned,
    /// [`StorageError::NotInitialized`] if the underlying
    /// [`StorageKeys`](super::StorageKeys) has since been destroyed (e.g. the
    /// host app called `CredentialStore::destroy_storage` while still
    /// holding this handle), or whatever error `f` itself returns.
    pub(crate) fn with_exposed<T>(
        &self,
        f: impl FnOnce(&SecretBox<[u8; 32]>) -> StorageResult<T>,
    ) -> StorageResult<T> {
        f(KeyGuard::lock(&self.0)?.as_secret()?)
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
            keys_first
                .intermediate_key()
                .unwrap()
                .as_secret()
                .unwrap()
                .expose_secret(),
            keys_second
                .intermediate_key()
                .unwrap()
                .as_secret()
                .unwrap()
                .expose_secret()
        );

        let _ = std::fs::remove_file(lock_path);
    }

    #[test]
    fn test_destroy_zeroizes_key_even_with_outstanding_handle() {
        let keystore = InMemoryKeystore::new();
        let blob_store = InMemoryBlobStore::new();
        let lock_path = temp_lock_path();
        let lock = Lock::open(&lock_path).expect("open lock");
        let keys = StorageKeys::init(&keystore, &blob_store, &lock, 100).expect("init");

        // Simulate a host app that opened a sibling `CredentialActivityStore`
        // and is still holding the handle past logout.
        let handle = IntermediateKeyHandle::from_shared(keys.intermediate_key_shared());

        keys.destroy();

        assert!(matches!(
            keys.intermediate_key()
                .expect("lock still acquirable after destroy")
                .as_secret(),
            Err(StorageError::NotInitialized)
        ));

        assert!(matches!(
            handle.with_exposed(|_| Ok(())),
            Err(StorageError::NotInitialized)
        ));

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
