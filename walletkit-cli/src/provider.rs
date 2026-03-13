//! Filesystem-backed storage provider for the CLI.
//!
//! This is a dev-local provider — the device keystore uses XChaCha20-Poly1305
//! with a randomly generated key stored as a plain file alongside the data.
//! This is NOT suitable for production use.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use rand::rngs::OsRng;
use rand::RngCore;
use walletkit_core::storage::{
    AtomicBlobStore, CredentialStore, DeviceKeystore, StorageError, StoragePaths,
    StorageProvider,
};

const KEYSTORE_FILENAME: &str = ".device_key";

/// Filesystem-backed device keystore.
///
/// Stores a 32-byte encryption key in a plain file. Suitable only for
/// development and testing.
pub struct FsDeviceKeystore {
    key: [u8; 32],
}

impl FsDeviceKeystore {
    /// Loads or creates the device key at `root/.device_key`.
    pub fn open(root: &Path) -> eyre::Result<Self> {
        let key_path = root.join(KEYSTORE_FILENAME);
        let key = if key_path.exists() {
            let bytes = fs::read(&key_path)?;
            let key: [u8; 32] = bytes
                .try_into()
                .map_err(|_| eyre::eyre!("corrupt device key file"))?;
            key
        } else {
            let mut key = [0u8; 32];
            OsRng.fill_bytes(&mut key);
            fs::create_dir_all(root)?;
            fs::write(&key_path, key)?;
            key
        };
        Ok(Self { key })
    }
}

impl DeviceKeystore for FsDeviceKeystore {
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
            .map_err(|e| StorageError::Crypto(e.to_string()))?;
        let mut out = Vec::with_capacity(24 + ciphertext.len());
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
                "ciphertext too short".to_string(),
            ));
        }
        let (nonce, payload) = ciphertext.split_at(24);
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&self.key));
        cipher
            .decrypt(
                XNonce::from_slice(nonce),
                Payload {
                    msg: payload,
                    aad: &associated_data,
                },
            )
            .map_err(|e| StorageError::Crypto(e.to_string()))
    }
}

/// Filesystem-backed atomic blob store.
///
/// Stores blobs as files under a base directory with atomic rename-into-place
/// semantics.
pub struct FsAtomicBlobStore {
    base: PathBuf,
}

impl FsAtomicBlobStore {
    /// Creates a new blob store rooted at `base`.
    pub fn new(base: &Path) -> Self {
        Self {
            base: base.to_path_buf(),
        }
    }
}

impl AtomicBlobStore for FsAtomicBlobStore {
    fn read(&self, path: String) -> Result<Option<Vec<u8>>, StorageError> {
        let full = self.base.join(&path);
        match fs::read(&full) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(StorageError::BlobStore(format!(
                "read {}: {e}",
                full.display()
            ))),
        }
    }

    fn write_atomic(&self, path: String, bytes: Vec<u8>) -> Result<(), StorageError> {
        let full = self.base.join(&path);
        if let Some(parent) = full.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                StorageError::BlobStore(format!("mkdir {}: {e}", parent.display()))
            })?;
        }
        let tmp = full.with_extension("tmp");
        fs::write(&tmp, &bytes).map_err(|e| {
            StorageError::BlobStore(format!("write {}: {e}", tmp.display()))
        })?;
        fs::rename(&tmp, &full).map_err(|e| {
            StorageError::BlobStore(format!("rename {}: {e}", full.display()))
        })?;
        Ok(())
    }

    fn delete(&self, path: String) -> Result<(), StorageError> {
        let full = self.base.join(&path);
        match fs::remove_file(&full) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(StorageError::BlobStore(format!(
                "delete {}: {e}",
                full.display()
            ))),
        }
    }
}

/// Filesystem storage provider that ties together all components.
pub struct FsStorageProvider {
    keystore: Arc<FsDeviceKeystore>,
    blob_store: Arc<FsAtomicBlobStore>,
    paths: Arc<StoragePaths>,
}

impl FsStorageProvider {
    /// Creates a new provider rooted at the given directory.
    pub fn open(root: &Path) -> eyre::Result<Self> {
        let keystore = Arc::new(FsDeviceKeystore::open(root)?);
        let blob_store = Arc::new(FsAtomicBlobStore::new(root));
        let paths = Arc::new(StoragePaths::new(root));
        Ok(Self {
            keystore,
            blob_store,
            paths,
        })
    }
}

impl StorageProvider for FsStorageProvider {
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

/// Creates a `CredentialStore` backed by the filesystem at `root`.
pub fn create_fs_credential_store(root: &Path) -> eyre::Result<Arc<CredentialStore>> {
    let provider = FsStorageProvider::open(root)?;
    let store = CredentialStore::from_provider(&provider)?;
    Ok(Arc::new(store))
}
