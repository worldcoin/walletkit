//! Platform interfaces for credential storage.

use std::sync::Arc;

use super::error::StorageResult;
use super::paths::StoragePaths;

/// Device keystore interface used to seal and open account keys.
#[uniffi::export(with_foreign)]
pub trait DeviceKeystore: Send + Sync {
    /// Seals plaintext under the device-bound key, authenticating `associated_data`.
    ///
    /// The associated data is not encrypted, but it is integrity-protected as part
    /// of the seal operation. Any mismatch when opening must fail.
    ///
    /// # Errors
    ///
    /// Returns an error if the keystore refuses the operation or the seal fails.
    fn seal(
        &self,
        associated_data: Vec<u8>,
        plaintext: Vec<u8>,
    ) -> StorageResult<Vec<u8>>;

    /// Opens ciphertext under the device-bound key, verifying `associated_data`.
    ///
    /// The same associated data used during sealing must be supplied or the open
    /// operation must fail.
    ///
    /// # Errors
    ///
    /// Returns an error if authentication fails or the keystore cannot open.
    fn open_sealed(
        &self,
        associated_data: Vec<u8>,
        ciphertext: Vec<u8>,
    ) -> StorageResult<Vec<u8>>;
}

/// Atomic blob store for small binary files (e.g., `account_keys.bin`).
#[uniffi::export(with_foreign)]
pub trait AtomicBlobStore: Send + Sync {
    /// Reads the blob at `path`, if present.
    ///
    /// # Errors
    ///
    /// Returns an error if the read fails.
    fn read(&self, path: String) -> StorageResult<Option<Vec<u8>>>;

    /// Writes bytes atomically to `path`.
    ///
    /// # Errors
    ///
    /// Returns an error if the write fails.
    fn write_atomic(&self, path: String, bytes: Vec<u8>) -> StorageResult<()>;

    /// Deletes the blob at `path`.
    ///
    /// # Errors
    ///
    /// Returns an error if the delete fails.
    fn delete(&self, path: String) -> StorageResult<()>;
}

/// Provider responsible for platform-specific storage components and paths.
#[uniffi::export(with_foreign)]
pub trait StorageProvider: Send + Sync {
    /// Returns the device keystore implementation.
    fn keystore(&self) -> Arc<dyn DeviceKeystore>;

    /// Returns the blob store implementation.
    fn blob_store(&self) -> Arc<dyn AtomicBlobStore>;

    /// Returns the storage paths selected by the platform.
    fn paths(&self) -> Arc<StoragePaths>;
}
