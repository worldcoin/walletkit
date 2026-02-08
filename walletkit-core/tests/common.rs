#![cfg(feature = "storage")]

//! Common test utilities shared across integration tests.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    Key, XChaCha20Poly1305, XNonce,
};
use rand::{rngs::OsRng, RngCore};
use uuid::Uuid;
use walletkit_core::storage::{
    AtomicBlobStore, CredentialStore, DeviceKeystore, StorageError, StoragePaths,
    StorageProvider,
};

pub struct InMemoryKeystore {
    key: [u8; 32],
}

impl InMemoryKeystore {
    pub fn new() -> Self {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        Self { key }
    }
}

impl Default for InMemoryKeystore {
    fn default() -> Self {
        Self::new()
    }
}

impl DeviceKeystore for InMemoryKeystore {
    fn seal(
        &self,
        associated_data: Vec<u8>,
        plaintext: Vec<u8>,
    ) -> Result<Vec<u8>, StorageError> {
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&self.key));
        let mut nonce_bytes = [0u8; 24];
        OsRng.fill_bytes(&mut nonce_bytes);
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce_bytes),
                Payload {
                    msg: &plaintext,
                    aad: &associated_data,
                },
            )
            .map_err(|err| StorageError::Crypto(err.to_string()))?;
        let mut out = Vec::with_capacity(nonce_bytes.len() + ciphertext.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    fn open_sealed(
        &self,
        associated_data: Vec<u8>,
        ciphertext: Vec<u8>,
    ) -> Result<Vec<u8>, StorageError> {
        if ciphertext.len() < 24 {
            return Err(StorageError::InvalidEnvelope(
                "keystore ciphertext too short".to_string(),
            ));
        }
        let (nonce_bytes, payload) = ciphertext.split_at(24);
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&self.key));
        cipher
            .decrypt(
                XNonce::from_slice(nonce_bytes),
                Payload {
                    msg: payload,
                    aad: &associated_data,
                },
            )
            .map_err(|err| StorageError::Crypto(err.to_string()))
    }
}

pub struct InMemoryBlobStore {
    blobs: Mutex<HashMap<String, Vec<u8>>>,
}

impl InMemoryBlobStore {
    pub fn new() -> Self {
        Self {
            blobs: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for InMemoryBlobStore {
    fn default() -> Self {
        Self::new()
    }
}

impl AtomicBlobStore for InMemoryBlobStore {
    fn read(&self, path: String) -> Result<Option<Vec<u8>>, StorageError> {
        let guard = self
            .blobs
            .lock()
            .map_err(|_| StorageError::BlobStore("mutex poisoned".to_string()))?;
        Ok(guard.get(&path).cloned())
    }

    fn write_atomic(&self, path: String, bytes: Vec<u8>) -> Result<(), StorageError> {
        self.blobs
            .lock()
            .map_err(|_| StorageError::BlobStore("mutex poisoned".to_string()))?
            .insert(path, bytes);
        Ok(())
    }

    fn delete(&self, path: String) -> Result<(), StorageError> {
        self.blobs
            .lock()
            .map_err(|_| StorageError::BlobStore("mutex poisoned".to_string()))?
            .remove(&path);
        Ok(())
    }
}

pub struct InMemoryStorageProvider {
    keystore: Arc<InMemoryKeystore>,
    blob_store: Arc<InMemoryBlobStore>,
    paths: Arc<StoragePaths>,
}

impl InMemoryStorageProvider {
    pub fn new(root: impl AsRef<Path>) -> Self {
        Self {
            keystore: Arc::new(InMemoryKeystore::new()),
            blob_store: Arc::new(InMemoryBlobStore::new()),
            paths: Arc::new(StoragePaths::new(root)),
        }
    }
}

impl StorageProvider for InMemoryStorageProvider {
    fn keystore(&self) -> Arc<dyn DeviceKeystore> {
        self.keystore.clone()
    }

    fn blob_store(&self) -> Arc<dyn AtomicBlobStore> {
        self.blob_store.clone()
    }

    fn paths(&self) -> Arc<StoragePaths> {
        Arc::clone(&self.paths)
    }
}

pub fn temp_root() -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!("walletkit-test-{}", Uuid::new_v4()));
    path
}

#[allow(dead_code, reason = "used in tests")]
pub fn create_test_credential_store() -> Arc<CredentialStore> {
    let root = temp_root();
    let provider = InMemoryStorageProvider::new(&root);
    Arc::new(
        CredentialStore::from_provider(&provider).expect("create credential store"),
    )
}

#[allow(dead_code, reason = "used in tests")]
pub fn cleanup_storage(root: &Path) {
    use std::fs;
    let paths = StoragePaths::new(root);
    let vault = paths.vault_db_path();
    let cache = paths.cache_db_path();
    let lock = paths.lock_path();
    let _ = fs::remove_file(&vault);
    let _ = fs::remove_file(vault.with_extension("sqlite-wal"));
    let _ = fs::remove_file(vault.with_extension("sqlite-shm"));
    let _ = fs::remove_file(&cache);
    let _ = fs::remove_file(cache.with_extension("sqlite-wal"));
    let _ = fs::remove_file(cache.with_extension("sqlite-shm"));
    let _ = fs::remove_file(lock);
    let _ = fs::remove_dir_all(paths.worldid_dir());
    let _ = fs::remove_dir_all(paths.root());
}
