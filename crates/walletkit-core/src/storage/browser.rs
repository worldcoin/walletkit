//! FFI adapters for synchronous Rust platform components.

use super::{AtomicBlobStore, DeviceKeystore, StorageError, StorageResult};
use secrecy::SecretBox;
use std::{path::PathBuf, sync::Arc};
use walletkit_db::{AtomicBlobStore as _, Keystore as _};
use zeroize::Zeroizing;

/// Synchronous software keystore backed by a host-provided secret.
#[derive(uniffi::Object)]
pub struct SecretDeviceKeystore(walletkit_db::SecretKeystore);

#[uniffi::export]
impl SecretDeviceKeystore {
    /// Creates a keystore from a 32-byte host-provided secret.
    /// The host must retain/recover the same secret for subsequent unlocks.
    ///
    /// # Errors
    /// Returns an error if the secret is not exactly 32 bytes.
    #[uniffi::constructor]
    pub fn new(secret: Vec<u8>) -> StorageResult<Self> {
        let secret = Zeroizing::new(secret);
        if secret.len() != 32 {
            return Err(StorageError::Keystore("expected a 32-byte secret".into()));
        }
        let key = SecretBox::init_with(|| {
            let mut key = [0; 32];
            key.copy_from_slice(&secret);
            key
        });
        Ok(Self(walletkit_db::SecretKeystore::new(key)))
    }

    /// Returns this keystore as the platform interface used by credential storage.
    #[must_use]
    pub fn as_device_keystore(self: Arc<Self>) -> Arc<dyn DeviceKeystore> {
        self
    }
}

impl DeviceKeystore for SecretDeviceKeystore {
    fn seal(
        &self,
        associated_data: Vec<u8>,
        plaintext: Vec<u8>,
    ) -> StorageResult<Vec<u8>> {
        let plaintext = Zeroizing::new(plaintext);
        Ok(self.0.seal(&associated_data, &plaintext)?)
    }
    fn open_sealed(
        &self,
        associated_data: Vec<u8>,
        ciphertext: Vec<u8>,
    ) -> StorageResult<Vec<u8>> {
        Ok(self.0.open_sealed(associated_data, ciphertext)?)
    }
}

/// `SQLite`-backed storage for already-sealed blobs.
#[derive(uniffi::Object)]
pub struct SqliteAtomicBlobStore(walletkit_db::SqliteBlobStore);

#[uniffi::export]
impl SqliteAtomicBlobStore {
    /// Creates a `SQLite` blob store with a connection opened and closed per operation.
    ///
    /// Browser callers must await `initialize_persistent_storage` first.
    /// Only sealed data belongs in this unencrypted database.
    ///
    /// # Errors
    /// Returns an error if the database cannot be opened or initialized.
    #[uniffi::constructor]
    pub fn new(path: String) -> StorageResult<Self> {
        Ok(Self(walletkit_db::SqliteBlobStore::new(PathBuf::from(
            path,
        ))?))
    }

    /// Returns this store as the platform interface used by credential storage.
    #[must_use]
    pub fn as_atomic_blob_store(self: Arc<Self>) -> Arc<dyn AtomicBlobStore> {
        self
    }
}

impl AtomicBlobStore for SqliteAtomicBlobStore {
    fn read(&self, path: String) -> StorageResult<Option<Vec<u8>>> {
        Ok(self.0.read(path)?)
    }
    fn write_atomic(&self, path: String, bytes: Vec<u8>) -> StorageResult<()> {
        Ok(self.0.write_atomic(path, bytes)?)
    }
    fn delete(&self, path: String) -> StorageResult<()> {
        Ok(self.0.delete(path)?)
    }
}
