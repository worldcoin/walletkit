//! Filesystem-backed storage provider for the CLI.
//!
//! This is a dev-local provider — the device keystore is a no-op passthrough
//! since encryption at the keystore layer adds no value for local development.
//! The `SQLCipher` databases are still encrypted with a random `K_intermediate`.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use walletkit_core::storage::{
    AtomicBlobStore, CredentialStore, DeviceKeystore, StorageError, StoragePaths,
    StorageProvider,
};

/// No-op device keystore that passes data through without encryption.
///
/// Suitable only for development and testing. In production, the real
/// `DeviceKeystore` is backed by the platform's secure enclave.
pub struct NoopDeviceKeystore;

impl DeviceKeystore for NoopDeviceKeystore {
    fn seal(
        &self,
        _associated_data: Vec<u8>,
        plaintext: Vec<u8>,
    ) -> Result<Vec<u8>, StorageError> {
        Ok(plaintext)
    }

    fn open_sealed(
        &self,
        _associated_data: Vec<u8>,
        ciphertext: Vec<u8>,
    ) -> Result<Vec<u8>, StorageError> {
        Ok(ciphertext)
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
    keystore: Arc<NoopDeviceKeystore>,
    blob_store: Arc<FsAtomicBlobStore>,
    paths: Arc<StoragePaths>,
}

impl FsStorageProvider {
    /// Creates a new provider rooted at the given directory.
    pub fn open(root: &Path) -> Self {
        let keystore = Arc::new(NoopDeviceKeystore);
        let blob_store = Arc::new(FsAtomicBlobStore::new(root));
        let paths = Arc::new(StoragePaths::new(root));
        Self {
            keystore,
            blob_store,
            paths,
        }
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
    let provider = FsStorageProvider::open(root);
    let store = CredentialStore::from_provider(&provider)?;
    Ok(Arc::new(store))
}
