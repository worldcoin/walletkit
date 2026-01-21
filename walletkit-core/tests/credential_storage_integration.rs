use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    Key, XChaCha20Poly1305, XNonce,
};
use rand::{rngs::OsRng, RngCore};
use uuid::Uuid;

use walletkit_core::storage::{
    AtomicBlobStore, CredentialStatus, CredentialStorage, CredentialStore,
    DeviceKeystore, ProofDisclosureResult, StoragePaths, StorageProvider,
};

struct InMemoryKeystore {
    key: [u8; 32],
}

impl InMemoryKeystore {
    fn new() -> Self {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        Self { key }
    }
}

impl DeviceKeystore for InMemoryKeystore {
    fn seal(
        &self,
        associated_data: Vec<u8>,
        plaintext: Vec<u8>,
    ) -> Result<Vec<u8>, walletkit_core::storage::StorageError> {
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
            .map_err(|err| {
                walletkit_core::storage::StorageError::Crypto(err.to_string())
            })?;
        let mut out = Vec::with_capacity(nonce_bytes.len() + ciphertext.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    fn open_sealed(
        &self,
        associated_data: Vec<u8>,
        ciphertext: Vec<u8>,
    ) -> Result<Vec<u8>, walletkit_core::storage::StorageError> {
        if ciphertext.len() < 24 {
            return Err(walletkit_core::storage::StorageError::InvalidEnvelope(
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
            .map_err(|err| {
                walletkit_core::storage::StorageError::Crypto(err.to_string())
            })
    }
}

struct InMemoryBlobStore {
    blobs: Mutex<HashMap<String, Vec<u8>>>,
}

impl InMemoryBlobStore {
    fn new() -> Self {
        Self {
            blobs: Mutex::new(HashMap::new()),
        }
    }
}

impl AtomicBlobStore for InMemoryBlobStore {
    fn read(
        &self,
        path: String,
    ) -> Result<Option<Vec<u8>>, walletkit_core::storage::StorageError> {
        let guard = self.blobs.lock().map_err(|_| {
            walletkit_core::storage::StorageError::BlobStore(
                "mutex poisoned".to_string(),
            )
        })?;
        Ok(guard.get(&path).cloned())
    }

    fn write_atomic(
        &self,
        path: String,
        bytes: Vec<u8>,
    ) -> Result<(), walletkit_core::storage::StorageError> {
        self.blobs
            .lock()
            .map_err(|_| {
                walletkit_core::storage::StorageError::BlobStore(
                    "mutex poisoned".to_string(),
                )
            })?
            .insert(path, bytes);
        Ok(())
    }

    fn delete(
        &self,
        path: String,
    ) -> Result<(), walletkit_core::storage::StorageError> {
        self.blobs
            .lock()
            .map_err(|_| {
                walletkit_core::storage::StorageError::BlobStore(
                    "mutex poisoned".to_string(),
                )
            })?
            .remove(&path);
        Ok(())
    }
}

struct InMemoryStorageProvider {
    keystore: Arc<InMemoryKeystore>,
    blob_store: Arc<InMemoryBlobStore>,
    paths: Arc<StoragePaths>,
}

impl InMemoryStorageProvider {
    fn new(root: impl AsRef<Path>) -> Self {
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

fn temp_root() -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!("walletkit-storage-{}", Uuid::new_v4()));
    path
}

fn cleanup_storage(root: &Path) {
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

#[test]
fn test_storage_flow_end_to_end() {
    let root = temp_root();
    let provider = InMemoryStorageProvider::new(&root);
    let mut store = CredentialStore::from_provider(&provider).expect("store");

    store.init(42, 100).expect("init");

    let credential_id = CredentialStorage::store_credential(
        &mut store,
        7,
        CredentialStatus::Active,
        [0x11u8; 32],
        1_700_000_000,
        Some(1_800_000_000),
        vec![1, 2, 3],
        Some(vec![4, 5, 6]),
        100,
    )
    .expect("store credential");

    let records = CredentialStorage::list_credentials(&store, None, 101)
        .expect("list credentials");
    assert_eq!(records.len(), 1);
    let record = &records[0];
    assert_eq!(record.credential_id, credential_id);
    assert_eq!(record.issuer_schema_id, 7);
    assert_eq!(record.subject_blinding_factor, [0x11u8; 32]);
    assert_eq!(record.credential_blob, vec![1, 2, 3]);
    assert_eq!(record.associated_data.as_deref(), Some(&[4, 5, 6][..]));

    let root_bytes = [0xAAu8; 32];
    CredentialStorage::merkle_cache_put(&mut store, 1, root_bytes, vec![9, 9], 100, 10)
        .expect("cache put");
    let hit = CredentialStorage::merkle_cache_get(&store, 1, root_bytes, 105)
        .expect("cache get");
    assert_eq!(hit, Some(vec![9, 9]));
    let miss = CredentialStorage::merkle_cache_get(&store, 1, root_bytes, 111)
        .expect("cache get");
    assert!(miss.is_none());

    let request_id = [0xABu8; 32];
    let nullifier = [0xCDu8; 32];
    let fresh = CredentialStorage::begin_proof_disclosure(
        &mut store,
        request_id,
        nullifier,
        vec![1, 2],
        200,
        50,
    )
    .expect("disclose");
    assert_eq!(fresh, ProofDisclosureResult::Fresh(vec![1, 2]));
    let replay = CredentialStorage::begin_proof_disclosure(
        &mut store,
        request_id,
        nullifier,
        vec![9, 9],
        201,
        50,
    )
    .expect("replay");
    assert_eq!(replay, ProofDisclosureResult::Replay(vec![1, 2]));

    cleanup_storage(&root);
}
