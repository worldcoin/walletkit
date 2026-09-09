//! Explicit host-owned credential key envelope lifecycle.

use std::sync::Arc;
use walletkit_db::Lock;

use super::{
    AtomicBlobStore, DeviceKeystore, StorageKeys, StoragePaths, StorageResult,
};

pub(super) const ACCOUNT_KEYS_FILENAME: &str = "account_keys.bin";
const ACCOUNT_KEY_ENVELOPE_AD: &[u8] = b"worldid:account-key-envelope";

/// Opens the device-sealed key envelope, or generates and persists one if absent.
///
/// Call this before constructing a credential store. Platform components are
/// used only during this call and are not retained.
///
/// `now` is Unix time in seconds, used only for a new envelope's creation and
/// update timestamps. It is ignored when opening an existing envelope.
///
/// # Errors
/// Returns an error if locking, envelope access, key generation, sealing, or
/// unsealing fails.
#[uniffi::export]
#[expect(
    clippy::needless_pass_by_value,
    reason = "UniFFI parameters require owned Arc handles"
)]
pub fn open_or_create_storage_keys(
    paths: Arc<StoragePaths>,
    keystore: Arc<dyn DeviceKeystore>,
    blob_store: Arc<dyn AtomicBlobStore>,
    now: u64,
) -> StorageResult<Arc<StorageKeys>> {
    let lock = Lock::open(&paths.lock_path())?;
    let intermediate_key = walletkit_db::init_or_open_envelope_key(
        &Ks(keystore.as_ref()),
        &Bs(blob_store.as_ref()),
        &lock,
        ACCOUNT_KEYS_FILENAME,
        ACCOUNT_KEY_ENVELOPE_AD,
        now,
    )?;
    Ok(Arc::new(StorageKeys::from_secret(intermediate_key)))
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
    use crate::storage::tests_utils::{InMemoryBlobStore, InMemoryKeystore};
    use crate::storage::StorageError;
    use secrecy::ExposeSecret;

    #[test]
    fn envelope_resolution_does_not_retain_platform_components() {
        let root = tempfile::tempdir().expect("temp dir");
        let paths = Arc::new(StoragePaths::new(root.path()));
        let keystore = Arc::new(InMemoryKeystore::new());
        let blobs = Arc::new(InMemoryBlobStore::new());
        let weak_keystore = Arc::downgrade(&keystore);
        let weak_blobs = Arc::downgrade(&blobs);
        let _keys = open_or_create_storage_keys(paths, keystore, blobs, 1000)
            .expect("resolve envelope");
        assert!(weak_keystore.upgrade().is_none());
        assert!(weak_blobs.upgrade().is_none());
    }

    #[test]
    fn test_storage_keys_round_trip() {
        let keystore = Arc::new(InMemoryKeystore::new());
        let blob_store = Arc::new(InMemoryBlobStore::new());
        let root = tempfile::tempdir().expect("temp dir");
        let paths = Arc::new(StoragePaths::new(root.path()));
        let keys_first = open_or_create_storage_keys(
            Arc::clone(&paths),
            keystore.clone(),
            blob_store.clone(),
            100,
        )
        .expect("init");
        let envelope_before = blob_store
            .read(ACCOUNT_KEYS_FILENAME.to_string())
            .expect("read envelope")
            .expect("envelope exists");
        let metadata: ciborium::Value =
            ciborium::de::from_reader(envelope_before.as_slice()).expect("CBOR");
        let fields = metadata.as_map().expect("envelope map");
        for name in ["created_at", "updated_at"] {
            let timestamp = fields
                .iter()
                .find(|(key, _)| key.as_text() == Some(name))
                .expect("timestamp field");
            assert_eq!(timestamp.1, ciborium::Value::Integer(100.into()));
        }
        let keys_second = open_or_create_storage_keys(
            Arc::clone(&paths),
            keystore,
            blob_store.clone(),
            200,
        )
        .expect("init");

        assert_eq!(
            keys_first.intermediate_key().expose_secret(),
            keys_second.intermediate_key().expose_secret()
        );
        assert_eq!(
            blob_store
                .read(ACCOUNT_KEYS_FILENAME.to_string())
                .expect("read envelope")
                .expect("envelope exists"),
            envelope_before,
            "reopening with a different timestamp must preserve the envelope"
        );
    }

    #[test]
    fn test_storage_keys_keystore_mismatch_fails() {
        let keystore = Arc::new(InMemoryKeystore::new());
        let blob_store = Arc::new(InMemoryBlobStore::new());
        let root = tempfile::tempdir().expect("temp dir");
        let paths = Arc::new(StoragePaths::new(root.path()));
        open_or_create_storage_keys(
            Arc::clone(&paths),
            keystore,
            blob_store.clone(),
            123,
        )
        .expect("init");

        let other_keystore = Arc::new(InMemoryKeystore::new());
        match open_or_create_storage_keys(
            Arc::clone(&paths),
            other_keystore,
            blob_store,
            456,
        ) {
            Err(
                StorageError::Crypto(_)
                | StorageError::InvalidEnvelope(_)
                | StorageError::Keystore(_),
            ) => {}
            Err(err) => panic!("unexpected error: {err}"),
            Ok(_) => panic!("expected error"),
        }
    }

    #[test]
    fn test_storage_keys_tampered_envelope_fails() {
        let keystore = Arc::new(InMemoryKeystore::new());
        let blob_store = Arc::new(InMemoryBlobStore::new());
        let root = tempfile::tempdir().expect("temp dir");
        let paths = Arc::new(StoragePaths::new(root.path()));
        open_or_create_storage_keys(
            Arc::clone(&paths),
            keystore.clone(),
            blob_store.clone(),
            123,
        )
        .expect("init");

        let mut bytes = blob_store
            .read(ACCOUNT_KEYS_FILENAME.to_string())
            .expect("read")
            .expect("present");
        bytes[0] ^= 0xFF;
        blob_store
            .write_atomic(ACCOUNT_KEYS_FILENAME.to_string(), bytes)
            .expect("write");

        match open_or_create_storage_keys(Arc::clone(&paths), keystore, blob_store, 456)
        {
            Err(
                StorageError::Serialization(_)
                | StorageError::Crypto(_)
                | StorageError::UnsupportedEnvelopeVersion(_),
            ) => {}
            Err(err) => panic!("unexpected error: {err}"),
            Ok(_) => panic!("expected error"),
        }
    }
}
