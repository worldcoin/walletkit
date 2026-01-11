//! Account lock manager trait for serialized mutations.
//!
//! The lock manager ensures that only one writer can modify an account's
//! data at a time, preventing corruption from concurrent access.

use crate::credential_storage::{AccountId, StorageResult};

/// Per-account locking to serialize mutations.
///
/// All writes to an account MUST be serialized (single-writer). This includes:
/// - Mutations of `AccountState` and `PendingActionStore`
/// - Any `.vault` transaction publish (superblock update)
///
/// # Scope
///
/// The lock MUST be held for the entire duration of:
/// - Any `.vault` transaction (from begin to superblock publish)
/// - Any mutation of device-protected blobs (account state, pending actions)
///
/// # Implementation Notes
///
/// ## Cross-Process Locking
///
/// Implementations MUST prevent concurrent access across processes, not just
/// threads within a single process. This is typically achieved with:
/// - File locks (flock/fcntl on Unix, `LockFile` on Windows)
/// - Named mutexes (Windows)
/// - Web Locks API (Browser)
///
/// ## Platform Specifics
///
/// - **iOS/Android/Node**: File lock at `accounts/<account_id>/lock`
/// - **Browser**: Web Locks API keyed by account ID
///
/// # Example
///
/// ```ignore
/// lock_manager.with_account_lock(&account_id, || {
///     // All operations here are serialized
///     vault.with_txn(|txn| {
///         txn.put_blob(BlobKind::CredentialBlob, &data)?;
///         txn.commit()
///     })?;
///     Ok(())
/// })?;
/// ```
pub trait AccountLockManager: Send + Sync {
    /// Executes the closure while holding the account lock.
    ///
    /// The lock is automatically released when the closure returns,
    /// whether it succeeds or fails.
    ///
    /// # Arguments
    ///
    /// * `account_id` - The account to lock
    /// * `f` - The closure to execute while holding the lock
    ///
    /// # Returns
    ///
    /// The result of the closure.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The lock cannot be acquired (e.g., timeout, system error)
    /// - The closure returns an error
    fn with_account_lock<R, F>(&self, account_id: &AccountId, f: F) -> StorageResult<R>
    where
        F: FnOnce() -> StorageResult<R>;

    /// Attempts to acquire the lock without blocking.
    ///
    /// # Arguments
    ///
    /// * `account_id` - The account to lock
    /// * `f` - The closure to execute if the lock is acquired
    ///
    /// # Returns
    ///
    /// - `Ok(Some(result))` if the lock was acquired and the closure executed
    /// - `Ok(None)` if the lock could not be acquired immediately
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - A system error occurs (not just "lock busy")
    /// - The closure returns an error
    fn try_with_account_lock<R, F>(&self, account_id: &AccountId, f: F) -> StorageResult<Option<R>>
    where
        F: FnOnce() -> StorageResult<R>;
}
