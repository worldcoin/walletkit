//! Vault file store trait for random-access file operations.
//!
//! The vault file store provides random-access operations for the
//! `account.vault` container file.

use crate::credential_storage::StorageResult;

/// Random-access file operations for the vault container.
///
/// The `.vault` container is a single logical file (`account.vault`) that requires:
/// - Random-access reads (for superblocks and records)
/// - Writes at specific offsets (for superblock updates)
/// - Append operations (for transaction records)
/// - Durability guarantees (sync/fsync)
///
/// # File Structure
///
/// ```text
/// ┌──────────────────────────────────────────┐
/// │              FileHeader (48 bytes)        │  offset 0
/// ├──────────────────────────────────────────┤
/// │           SuperblockA (53 bytes)         │  offset 48
/// ├──────────────────────────────────────────┤
/// │           SuperblockB (53 bytes)         │  offset 101
/// ├──────────────────────────────────────────┤
/// │                                          │
/// │         Data Region (append-only)        │  offset 154+
/// │                                          │
/// │   - TxnBegin records                     │
/// │   - EncryptedBlobObject records          │
/// │   - EncryptedIndexSnapshot records       │
/// │   - TxnCommit records                    │
/// │                                          │
/// └──────────────────────────────────────────┘
/// ```
///
/// # Durability
///
/// The `sync()` method MUST ensure that after a crash/restart:
/// - A published superblock and its referenced committed transaction remain readable
/// - The file is in a consistent state
///
/// # Platform Specifics
///
/// - **iOS/Android/Node**: Standard file handle with pread/pwrite/fsync
/// - **Browser**: OPFS with `FileSystemSyncAccessHandle`
pub trait VaultFileStore: Send + Sync {
    /// Returns the current file length in bytes.
    ///
    /// # Returns
    ///
    /// The file size, or 0 if the file doesn't exist yet.
    ///
    /// # Errors
    ///
    /// Returns an error if the file length cannot be determined.
    fn len(&self) -> StorageResult<u64>;

    /// Returns `true` if the file is empty or doesn't exist.
    ///
    /// # Errors
    ///
    /// Returns an error if the file length cannot be determined.
    fn is_empty(&self) -> StorageResult<bool> {
        Ok(self.len()? == 0)
    }

    /// Reads bytes from a specific offset.
    ///
    /// # Arguments
    ///
    /// * `offset` - The byte offset to start reading from
    /// * `len` - The number of bytes to read
    ///
    /// # Returns
    ///
    /// A vector containing the requested bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The offset is beyond the end of the file
    /// - Reading fails
    fn read_at(&self, offset: u64, len: u32) -> StorageResult<Vec<u8>>;

    /// Writes bytes at a specific offset.
    ///
    /// This is primarily used for superblock updates (alternating A/B).
    ///
    /// # Arguments
    ///
    /// * `offset` - The byte offset to write at
    /// * `bytes` - The data to write
    ///
    /// # Errors
    ///
    /// Returns an error if writing fails.
    fn write_at(&self, offset: u64, bytes: &[u8]) -> StorageResult<()>;

    /// Appends bytes to the end of the file.
    ///
    /// This is used for transaction records in the data region.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The data to append
    ///
    /// # Returns
    ///
    /// The offset at which the data was written.
    ///
    /// # Errors
    ///
    /// Returns an error if appending fails.
    fn append(&self, bytes: &[u8]) -> StorageResult<u64>;

    /// Ensures all written data is durable.
    ///
    /// This MUST call the platform's sync/fsync equivalent to ensure
    /// data is persisted to stable storage.
    ///
    /// # Durability Guarantee
    ///
    /// After `sync()` returns successfully, a published superblock and its
    /// referenced committed transaction MUST survive a crash/restart.
    ///
    /// # Errors
    ///
    /// Returns an error if the sync operation fails.
    fn sync(&self) -> StorageResult<()>;

    /// Truncates or extends the file to a specific length.
    ///
    /// This is primarily used during initialization to create a file
    /// of the required header size.
    ///
    /// # Arguments
    ///
    /// * `len` - The new file length in bytes
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be truncated or extended.
    fn set_len(&self, len: u64) -> StorageResult<()>;
}
