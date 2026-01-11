//! iOS file-based lock manager implementation.
//!
//! This module implements `AccountLockManager` using file-based advisory
//! locking via the `fs2` crate, which provides cross-platform file locking.
//!
//! # Locking Strategy
//!
//! Each account has a dedicated lock file (`account.lock`) in its directory.
//! Acquiring the account lock involves:
//!
//! 1. Opening (or creating) the lock file
//! 2. Acquiring an exclusive advisory lock via `flock()`
//! 3. Holding the lock for the duration of the operation
//! 4. Releasing the lock when the operation completes
//!
//! # Cross-Process Safety
//!
//! Advisory locks on Unix are respected by cooperating processes. All World ID
//! operations must acquire the account lock before modifying account data.
//!
//! # Caveats
//!
//! - Advisory locks are NOT enforced by the kernel - they're purely cooperative
//! - NFS and some network file systems may not support proper locking
//! - The lock file should be on the same file system as the account data

use crate::credential_storage::{AccountId, StorageError, StorageResult};
use crate::credential_storage::platform::AccountLockManager;
use fs2::FileExt;
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// Helper to create an IO error from an std::io::Error.
fn io_error<S: Into<String>>(context: S, err: std::io::Error) -> StorageError {
    StorageError::IoError {
        context: context.into(),
        source: err,
    }
}

/// Name of the lock file in each account directory.
const LOCK_FILENAME: &str = "account.lock";

// AccountLock

/// A held account lock.
///
/// The lock is automatically released when this guard is dropped.
#[derive(Debug)]
pub struct AccountLock {
    /// The lock file (locked while this struct exists).
    _file: File,
    /// Account ID (for debugging).
    _account_id: AccountId,
}

impl AccountLock {
    /// Creates a new account lock guard.
    fn new(file: File, account_id: AccountId) -> Self {
        Self {
            _file: file,
            _account_id: account_id,
        }
    }
}

// When AccountLock is dropped, the file is closed and the lock is released.

// IosLockManager

/// iOS file-based implementation of `AccountLockManager`.
///
/// This implementation uses file locking (`flock()`) to serialize access
/// to account data across threads and processes.
///
/// # Example
///
/// ```ignore
/// let manager = IosLockManager::new("/path/to/worldid/data")?;
///
/// // Acquire lock for an account
/// let account_id = AccountId::new([0x42u8; 32]);
/// manager.with_account_lock(&account_id, || {
///     // Perform exclusive operations on the account
///     // Lock is held for the entire closure execution
/// })?;
/// ```
#[derive(Debug)]
pub struct IosLockManager {
    /// Root directory for World ID data.
    root_path: PathBuf,
    /// In-process lock to prevent multiple threads from trying to acquire
    /// the same file lock simultaneously (which could cause issues on some platforms).
    in_process_locks: Mutex<HashMap<AccountId, Arc<Mutex<()>>>>,
}

impl IosLockManager {
    /// Creates a new lock manager.
    ///
    /// # Arguments
    ///
    /// * `root_path` - Root directory for World ID data. Lock files will
    ///   be created in `<root_path>/worldid/accounts/<account_id>/account.lock`.
    pub fn new<P: AsRef<Path>>(root_path: P) -> StorageResult<Self> {
        let root_path = root_path.as_ref().to_path_buf();
        Ok(Self {
            root_path,
            in_process_locks: Mutex::new(HashMap::new()),
        })
    }

    /// Returns the path to the lock file for a given account.
    fn lock_path(&self, account_id: &AccountId) -> PathBuf {
        self.root_path
            .join("worldid")
            .join("accounts")
            .join(account_id.to_string())
            .join(LOCK_FILENAME)
    }

    /// Gets or creates the in-process mutex for an account.
    fn get_in_process_lock(&self, account_id: &AccountId) -> Arc<Mutex<()>> {
        let mut locks = self.in_process_locks.lock().unwrap();
        locks
            .entry(*account_id)
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    /// Opens or creates the lock file for an account.
    fn open_lock_file(&self, account_id: &AccountId) -> StorageResult<File> {
        let lock_path = self.lock_path(account_id);

        // Ensure parent directory exists
        if let Some(parent) = lock_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                io_error(format!("Failed to create account directory '{}'", parent.display()), e)
            })?;
        }

        OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)
            .map_err(|e| {
                io_error(format!("Failed to open lock file '{}'", lock_path.display()), e)
            })
    }

    /// Acquires an exclusive lock on the file.
    fn acquire_exclusive_lock(file: &File) -> StorageResult<()> {
        file.lock_exclusive().map_err(|e| {
            StorageError::lock(format!("Failed to acquire exclusive lock: {e}"))
        })
    }

    /// Tries to acquire an exclusive lock on the file without blocking.
    fn try_acquire_exclusive_lock(file: &File) -> StorageResult<bool> {
        match file.try_lock_exclusive() {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(false),
            Err(e) => Err(StorageError::lock(format!(
                "Failed to try lock: {e}"
            ))),
        }
    }
}

impl AccountLockManager for IosLockManager {
    /// Acquires the account lock and executes a closure.
    ///
    /// This method blocks until the lock is acquired. The lock is held
    /// for the entire duration of the closure execution.
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
    /// - The lock file cannot be created/opened
    /// - The lock cannot be acquired
    /// - The closure returns an error
    fn with_account_lock<R, F>(&self, account_id: &AccountId, f: F) -> StorageResult<R>
    where
        F: FnOnce() -> StorageResult<R>,
    {
        // First, acquire in-process lock to prevent threads from racing
        let in_process_lock = self.get_in_process_lock(account_id);
        let _in_process_guard = in_process_lock.lock().map_err(|_| {
            StorageError::lock("In-process lock poisoned")
        })?;

        // Now acquire the file lock (this may block waiting for other processes)
        let file = self.open_lock_file(account_id)?;
        Self::acquire_exclusive_lock(&file)?;

        // Execute the closure while holding both locks
        let result = f();

        // Locks are released when guards are dropped (in-process lock when
        // _in_process_guard drops, file lock when file closes)

        result
    }

    /// Tries to acquire the account lock without blocking.
    ///
    /// If the lock is already held by another thread or process, returns
    /// `Ok(None)` immediately without executing the closure.
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
    /// - The lock file cannot be created/opened
    /// - An unexpected error occurs while trying to acquire the lock
    /// - The closure returns an error
    fn try_with_account_lock<R, F>(&self, account_id: &AccountId, f: F) -> StorageResult<Option<R>>
    where
        F: FnOnce() -> StorageResult<R>,
    {
        // First, try to acquire in-process lock
        let in_process_lock = self.get_in_process_lock(account_id);
        let in_process_guard = match in_process_lock.try_lock() {
            Ok(guard) => guard,
            Err(_) => return Ok(None), // Another thread holds the lock
        };

        // Now try to acquire the file lock
        let file = self.open_lock_file(account_id)?;
        if !Self::try_acquire_exclusive_lock(&file)? {
            // Another process holds the lock
            drop(in_process_guard);
            return Ok(None);
        }

        // Execute the closure while holding both locks
        let result = f()?;

        Ok(Some(result))
    }
}

impl IosLockManager {
    /// Acquires the account lock and returns a guard.
    ///
    /// The lock is held until the returned guard is dropped.
    ///
    /// # Arguments
    ///
    /// * `account_id` - The account to lock
    ///
    /// # Returns
    ///
    /// A lock guard that releases the lock when dropped.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock cannot be acquired.
    pub fn acquire_lock(&self, account_id: &AccountId) -> StorageResult<AccountLock> {
        // Note: For the guard-based API, we don't use in-process locking
        // because we can't hold the MutexGuard across the return boundary
        // without more complex lifetime management.
        //
        // This is acceptable because:
        // 1. File locks ARE cross-process safe
        // 2. The in-process lock is primarily to prevent thundering herd issues
        // 3. Most real-world usage will use with_account_lock() anyway

        let file = self.open_lock_file(account_id)?;
        Self::acquire_exclusive_lock(&file)?;

        Ok(AccountLock::new(file, *account_id))
    }
}
