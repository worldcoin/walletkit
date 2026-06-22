//! Reusable [`StorageProvider`] implementations for tests.
//!
//! `walletkit-core` exposes the storage *traits* ([`StorageProvider`],
//! [`DeviceKeystore`], [`AtomicBlobStore`]) but ships no reusable provider
//! *impls*, so every (testing) consumer re-rolls them. This module provides two:
//!
//! - [`InMemoryStorageProvider`] — fully ephemeral; a no-op device keystore
//!   plus an in-memory blob map. Ideal for unit/integration tests that want no
//!   on-disk footprint. Test-only: account keys are not encrypted.
//! - [`FsStorageProvider`] — filesystem-backed with a no-op device keystore.
//!   Important: This is a test-only provider and must not be used in production.
//!   Vault encryption keys are stored in plaintext on disk.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use uuid::Uuid;
use walletkit_core::storage::{
    AtomicBlobStore, CredentialStore, DeviceKeystore, StorageError, StoragePaths,
    StorageProvider,
};

// ---------------------------------------------------------------------------
// Shared test keystore
// ---------------------------------------------------------------------------

/// No-op device keystore that passes data through without encryption.
///
/// Suitable only for development and testing. In production the real
/// `DeviceKeystore` is backed by the platform's secure enclave. Used by both
/// [`InMemoryStorageProvider`] and [`FsStorageProvider`].
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

// ---------------------------------------------------------------------------
// In-memory provider
// ---------------------------------------------------------------------------

/// In-memory [`AtomicBlobStore`] backed by a `HashMap`.
pub struct InMemoryBlobStore {
    blobs: Mutex<HashMap<String, Vec<u8>>>,
}

impl InMemoryBlobStore {
    /// Creates an empty blob store.
    #[must_use]
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

/// [`StorageProvider`] keeping all state in memory.
pub struct InMemoryStorageProvider {
    keystore: Arc<NoopDeviceKeystore>,
    blob_store: Arc<InMemoryBlobStore>,
    paths: Arc<StoragePaths>,
}

impl InMemoryStorageProvider {
    /// Creates a provider rooted at `root` (used only for path derivation; no
    /// files are written by the in-memory blob store).
    #[must_use]
    pub fn new(root: impl AsRef<Path>) -> Self {
        Self {
            keystore: Arc::new(NoopDeviceKeystore),
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

// ---------------------------------------------------------------------------
// Filesystem provider
// ---------------------------------------------------------------------------

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
        let tmp = full.with_extension("tmp");
        std::fs::write(&tmp, &bytes).map_err(|e| {
            StorageError::BlobStore(format!("write {}: {e}", tmp.display()))
        })?;
        std::fs::rename(&tmp, &full).map_err(|e| {
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

// ---------------------------------------------------------------------------
// Store constructors and helpers
// ---------------------------------------------------------------------------

/// Returns a unique, non-existent temp directory path for test storage.
#[must_use]
pub fn temp_root() -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!("walletkit-test-{}", Uuid::new_v4()));
    path
}

/// Creates an ephemeral in-memory [`CredentialStore`] rooted at a fresh temp path.
///
/// # Errors
///
/// Returns an error if the underlying [`CredentialStore`] cannot be initialized.
pub fn create_in_memory_credential_store() -> Result<Arc<CredentialStore>, StorageError>
{
    let root = temp_root();
    let provider = InMemoryStorageProvider::new(&root);
    Ok(Arc::new(CredentialStore::from_provider(&provider)?))
}

/// Creates a [`CredentialStore`] backed by the filesystem at `root`.
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

/// Removes all on-disk artifacts (vault, cache, lock, `WorldID` dir) under `root`.
///
/// Best-effort: missing files are ignored. Use to clean up after
/// [`FsStorageProvider`]-backed tests.
pub fn cleanup_storage(root: &Path) {
    let paths = StoragePaths::new(root);
    let vault = paths.vault_db_path();
    let cache = paths.cache_db_path();
    let lock = paths.lock_path();
    let _ = std::fs::remove_file(&vault);
    let _ = std::fs::remove_file(vault.with_extension("sqlite-wal"));
    let _ = std::fs::remove_file(vault.with_extension("sqlite-shm"));
    let _ = std::fs::remove_file(&cache);
    let _ = std::fs::remove_file(cache.with_extension("sqlite-wal"));
    let _ = std::fs::remove_file(cache.with_extension("sqlite-shm"));
    let _ = std::fs::remove_file(lock);
    let _ = std::fs::remove_dir_all(paths.worldid_dir());
    let _ = std::fs::remove_dir_all(paths.root());
}
