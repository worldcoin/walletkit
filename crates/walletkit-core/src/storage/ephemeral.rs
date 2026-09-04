//! Process-local storage components for browser demos and tests.

#[cfg(all(target_arch = "wasm32", feature = "uniffi-wasm"))]
use std::sync::Arc;
use std::{collections::HashMap, sync::Mutex};

use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;

use super::{AtomicBlobStore, DeviceKeystore, StorageError, StorageResult};
#[cfg(all(target_arch = "wasm32", feature = "uniffi-wasm"))]
use super::{StoragePaths, StorageProvider};

const ASSOCIATED_DATA_DIGEST_LENGTH: usize = 32;

struct EphemeralKeystore;

impl DeviceKeystore for EphemeralKeystore {
    fn seal(
        &self,
        associated_data: Vec<u8>,
        plaintext: Vec<u8>,
    ) -> StorageResult<Vec<u8>> {
        let mut sealed =
            Vec::with_capacity(ASSOCIATED_DATA_DIGEST_LENGTH + plaintext.len());
        sealed.extend_from_slice(&Sha256::digest(associated_data));
        sealed.extend_from_slice(&plaintext);
        Ok(sealed)
    }

    fn open_sealed(
        &self,
        associated_data: Vec<u8>,
        sealed: Vec<u8>,
    ) -> StorageResult<Vec<u8>> {
        let Some((stored_digest, plaintext)) =
            sealed.split_at_checked(ASSOCIATED_DATA_DIGEST_LENGTH)
        else {
            return Err(StorageError::InvalidEnvelope(
                "ephemeral keystore payload is too short".to_string(),
            ));
        };
        let expected_digest = Sha256::digest(associated_data);
        if !bool::from(stored_digest.ct_eq(expected_digest.as_slice())) {
            return Err(StorageError::InvalidEnvelope(
                "ephemeral keystore associated data mismatch".to_string(),
            ));
        }
        Ok(plaintext.to_vec())
    }
}

#[derive(Default)]
struct EphemeralBlobStore {
    blobs: Mutex<HashMap<String, Vec<u8>>>,
}

impl AtomicBlobStore for EphemeralBlobStore {
    fn read(&self, path: String) -> StorageResult<Option<Vec<u8>>> {
        Ok(self
            .blobs
            .lock()
            .map_err(|_| StorageError::BlobStore("mutex poisoned".to_string()))?
            .get(&path)
            .cloned())
    }

    fn write_atomic(&self, path: String, bytes: Vec<u8>) -> StorageResult<()> {
        self.blobs
            .lock()
            .map_err(|_| StorageError::BlobStore("mutex poisoned".to_string()))?
            .insert(path, bytes);
        Ok(())
    }

    fn delete(&self, path: String) -> StorageResult<()> {
        self.blobs
            .lock()
            .map_err(|_| StorageError::BlobStore("mutex poisoned".to_string()))?
            .remove(&path);
        Ok(())
    }
}

#[cfg(all(target_arch = "wasm32", feature = "uniffi-wasm"))]
pub(super) struct EphemeralStorageProvider {
    keystore: Arc<EphemeralKeystore>,
    blob_store: Arc<EphemeralBlobStore>,
    paths: Arc<StoragePaths>,
}

#[cfg(all(target_arch = "wasm32", feature = "uniffi-wasm"))]
impl EphemeralStorageProvider {
    pub(super) fn new() -> Self {
        Self {
            keystore: Arc::new(EphemeralKeystore),
            blob_store: Arc::new(EphemeralBlobStore::default()),
            paths: Arc::new(StoragePaths::new(format!(
                "walletkit-ephemeral-{}",
                uuid::Uuid::new_v4()
            ))),
        }
    }
}

#[cfg(all(target_arch = "wasm32", feature = "uniffi-wasm"))]
impl StorageProvider for EphemeralStorageProvider {
    fn keystore(&self) -> Arc<dyn DeviceKeystore> {
        self.keystore.clone()
    }

    fn blob_store(&self) -> Arc<dyn AtomicBlobStore> {
        self.blob_store.clone()
    }

    fn paths(&self) -> Arc<StoragePaths> {
        self.paths.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ephemeral_keystore_checks_associated_data() {
        let keystore = EphemeralKeystore;
        let sealed = keystore
            .seal(b"expected".to_vec(), b"secret".to_vec())
            .expect("seal");

        assert_eq!(
            keystore
                .open_sealed(b"expected".to_vec(), sealed.clone())
                .expect("open"),
            b"secret"
        );
        assert!(keystore.open_sealed(b"wrong".to_vec(), sealed).is_err());
    }

    #[test]
    fn ephemeral_blob_store_roundtrips_and_deletes() {
        let store = EphemeralBlobStore::default();
        store
            .write_atomic("key".to_string(), b"value".to_vec())
            .expect("write");
        assert_eq!(
            store.read("key".to_string()).expect("read"),
            Some(b"value".to_vec())
        );
        store.delete("key".to_string()).expect("delete");
        assert_eq!(store.read("key".to_string()).expect("read"), None);
    }
}
