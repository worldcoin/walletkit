//! Atomic blob store trait for small file operations.
//!
//! The blob store provides atomic operations for small files like
//! `account_state.bin` and `pending_actions.bin`.

use crate::credential_storage::StorageResult;

/// Atomic storage for small files.
///
/// This trait provides atomic read/write operations for small configuration files.
/// Writes MUST be atomic (using rename) to prevent corruption from crashes.
///
/// # Implementation Notes
///
/// ## Atomic Writes
///
/// Implementations MUST use the write-to-temp-then-rename pattern:
/// 1. Write data to a temporary file (e.g., `{name}.tmp`)
/// 2. Sync the temporary file to disk (`fsync`)
/// 3. Atomically rename the temp file to the target name
///
/// This ensures that the target file is either:
/// - The complete old content, or
/// - The complete new content
///
/// Never a partial or corrupted state.
///
/// ## Platform Specifics
///
/// - **iOS/Android/Node**: Standard filesystem with atomic rename
/// - **Browser**: Origin-Private File System (OPFS)
///
/// # Naming Convention
///
/// Files are identified by name within the account directory:
/// - `account_state.bin` — Encrypted account state
/// - `pending_actions.bin` — Encrypted pending action store
pub trait AtomicBlobStore: Send + Sync {
    /// Reads a blob by name.
    ///
    /// # Arguments
    ///
    /// * `name` - The blob name (e.g., `account_state.bin`)
    ///
    /// # Returns
    ///
    /// - `Ok(Some(bytes))` if the blob exists
    /// - `Ok(None)` if the blob does not exist
    ///
    /// # Errors
    ///
    /// Returns an error if reading fails (e.g., I/O error, permission denied).
    fn read(&self, name: &str) -> StorageResult<Option<Vec<u8>>>;

    /// Atomically writes a blob, replacing any existing content.
    ///
    /// # Arguments
    ///
    /// * `name` - The blob name
    /// * `bytes` - The content to write
    ///
    /// # Errors
    ///
    /// Returns an error if the write fails.
    fn write_atomic(&self, name: &str, bytes: &[u8]) -> StorageResult<()>;

    /// Deletes a blob.
    ///
    /// # Arguments
    ///
    /// * `name` - The blob name to delete
    ///
    /// # Errors
    ///
    /// Returns `Ok(())` even if the blob doesn't exist.
    /// Only returns an error for actual I/O failures.
    fn delete(&self, name: &str) -> StorageResult<()>;

    /// Checks if a blob exists.
    ///
    /// # Arguments
    ///
    /// * `name` - The blob name to check
    ///
    /// # Returns
    ///
    /// `true` if the blob exists, `false` otherwise.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying read operation fails.
    fn exists(&self, name: &str) -> StorageResult<bool> {
        Ok(self.read(name)?.is_some())
    }
}
