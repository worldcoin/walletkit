//! Reusable `StorageProvider` implementations for tests.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use uuid::Uuid;
use walletkit_core::storage::{
    AtomicBlobStore, CredentialStore, DeviceKeystore, StorageError, StoragePaths,
    StorageProvider,
};

/// No-op device keystore that passes data through without encryption.
///
/// Suitable only for development and testing. In production the real
/// `DeviceKeystore` is backed by the platform's secure enclave. Used by
/// [`FsStorageProvider`].
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

/// Filesystem-backed [`AtomicBlobStore`].
///
/// Stores blobs as files under a base directory with atomic rename-into-place
/// semantics.
pub struct FsAtomicBlobStore {
    base: PathBuf,
}

impl FsAtomicBlobStore {
    /// Creates a new blob store rooted at `base`.
    #[must_use]
    pub fn new(base: &Path) -> Self {
        Self {
            base: base.to_path_buf(),
        }
    }
}

impl AtomicBlobStore for FsAtomicBlobStore {
    fn read(&self, path: String) -> Result<Option<Vec<u8>>, StorageError> {
        let full = self.base.join(&path);
        match std::fs::read(&full) {
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
            std::fs::create_dir_all(parent).map_err(|e| {
                StorageError::BlobStore(format!("mkdir {}: {e}", parent.display()))
            })?;
        }
        // Unique per target and per write: `with_extension` would map same-stem
        // siblings (e.g. `vault.sqlite` / `vault.sqlite-wal`) to one tmp path.
        let file_name = full.file_name().ok_or_else(|| {
            StorageError::BlobStore(format!("no file name in {}", full.display()))
        })?;
        let tmp = full.with_file_name(format!(
            "{}.{}.tmp",
            file_name.to_string_lossy(),
            Uuid::new_v4()
        ));
        std::fs::write(&tmp, &bytes).map_err(|e| {
            StorageError::BlobStore(format!("write {}: {e}", tmp.display()))
        })?;
        std::fs::rename(&tmp, &full).map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            StorageError::BlobStore(format!("rename {}: {e}", full.display()))
        })?;
        Ok(())
    }

    fn delete(&self, path: String) -> Result<(), StorageError> {
        let full = self.base.join(&path);
        match std::fs::remove_file(&full) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(StorageError::BlobStore(format!(
                "delete {}: {e}",
                full.display()
            ))),
        }
    }
}

/// Filesystem [`StorageProvider`] tying together the no-op keystore, fs blob
/// store, and on-disk paths.
pub struct FsStorageProvider {
    keystore: Arc<NoopDeviceKeystore>,
    blob_store: Arc<FsAtomicBlobStore>,
    paths: Arc<StoragePaths>,
}

impl FsStorageProvider {
    /// Creates a new provider rooted at the given directory.
    #[must_use]
    pub fn open(root: &Path) -> Self {
        Self {
            keystore: Arc::new(NoopDeviceKeystore),
            blob_store: Arc::new(FsAtomicBlobStore::new(root)),
            paths: Arc::new(StoragePaths::new(root)),
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
///
/// # Errors
///
/// Returns an error if the underlying [`CredentialStore`] cannot be initialized.
pub fn create_fs_credential_store(
    root: &Path,
) -> Result<Arc<CredentialStore>, StorageError> {
    let provider = FsStorageProvider::open(root);
    Ok(Arc::new(CredentialStore::from_provider(&provider)?))
}
