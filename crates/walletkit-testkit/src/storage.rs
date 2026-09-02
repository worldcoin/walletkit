//! Reusable `StorageProvider` implementations for tests.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use uuid::Uuid;
use walletkit_core::authenticator::artifacts::caching::CachingZkArtifacts;
use walletkit_core::storage::{
    AtomicBlobStore, CredentialStore, KeySealer, StorageError, StoragePaths,
    StorageProvider,
};

/// No-op key sealer that passes data through without encryption.
///
/// Suitable only for development and testing. In production the real
/// `KeySealer` is backed by platform key protection. Used by
/// [`FsStorageProvider`].
pub struct NoopKeySealer;

#[async_trait::async_trait]
impl KeySealer for NoopKeySealer {
    async fn seal(
        &self,
        _context: Vec<u8>,
        plaintext: Vec<u8>,
    ) -> Result<Vec<u8>, StorageError> {
        Ok(plaintext)
    }

    async fn unseal(
        &self,
        _context: Vec<u8>,
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

#[async_trait::async_trait]
impl AtomicBlobStore for FsAtomicBlobStore {
    async fn read(&self, path: String) -> Result<Option<Vec<u8>>, StorageError> {
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

    async fn write_atomic(
        &self,
        path: String,
        bytes: Vec<u8>,
    ) -> Result<(), StorageError> {
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

    async fn delete(&self, path: String) -> Result<(), StorageError> {
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

/// Filesystem [`StorageProvider`] tying together the no-op key sealer, fs blob
/// store, and on-disk paths.
pub struct FsStorageProvider {
    key_sealer: Arc<NoopKeySealer>,
    blob_store: Arc<FsAtomicBlobStore>,
    paths: Arc<StoragePaths>,
}

impl FsStorageProvider {
    /// Creates a new provider rooted at the given directory.
    #[must_use]
    pub fn open(root: &Path) -> Self {
        Self {
            key_sealer: Arc::new(NoopKeySealer),
            blob_store: Arc::new(FsAtomicBlobStore::new(root)),
            paths: Arc::new(StoragePaths::new(root)),
        }
    }
}

impl StorageProvider for FsStorageProvider {
    fn key_sealer(&self) -> Arc<dyn KeySealer> {
        self.key_sealer.clone()
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

/// Creates a `WalletKitZkArtifactSource` backed by the filesystem at `root`.
#[must_use]
pub fn create_artifact_source(root: &Path) -> Arc<CachingZkArtifacts> {
    let provider = FsStorageProvider::open(root);

    Arc::new(CachingZkArtifacts::new(provider.paths()))
}
