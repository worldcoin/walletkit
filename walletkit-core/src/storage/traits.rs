//! Platform interfaces for credential storage.

use super::error::StorageResult;

/// Device keystore interface used to seal and open account keys.
pub trait DeviceKeystore: Send + Sync {
    /// Seals plaintext under the device-bound key, binding `associated_data`.
    ///
    /// # Errors
    ///
    /// Returns an error if the keystore refuses the operation or the seal fails.
    fn seal(&self, associated_data: &[u8], plaintext: &[u8]) -> StorageResult<Vec<u8>>;

    /// Opens ciphertext under the device-bound key, verifying `associated_data`.
    ///
    /// # Errors
    ///
    /// Returns an error if authentication fails or the keystore cannot open.
    fn open(&self, associated_data: &[u8], ciphertext: &[u8])
        -> StorageResult<Vec<u8>>;
}

/// Atomic blob store for small binary files (e.g., `account_keys.bin`).
pub trait AtomicBlobStore: Send + Sync {
    /// Reads the blob at `path`, if present.
    ///
    /// # Errors
    ///
    /// Returns an error if the read fails.
    fn read(&self, path: &str) -> StorageResult<Option<Vec<u8>>>;

    /// Writes bytes atomically to `path`.
    ///
    /// # Errors
    ///
    /// Returns an error if the write fails.
    fn write_atomic(&self, path: &str, bytes: &[u8]) -> StorageResult<()>;

    /// Deletes the blob at `path`.
    ///
    /// # Errors
    ///
    /// Returns an error if the delete fails.
    fn delete(&self, path: &str) -> StorageResult<()>;
}
