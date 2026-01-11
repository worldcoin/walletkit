//! iOS platform implementation for credential storage.
//!
//! This module provides iOS-specific implementations of the platform abstraction
//! traits using:
//!
//! - **Keychain Services**: For device-protected encryption via `DeviceKeystore`
//! - **File System**: For atomic blob storage via `AtomicBlobStore`
//! - **Random Access Files**: For vault storage via `VaultFileStore`
//! - **File Locking**: For cross-process locking via `AccountLockManager`
//!
//! # Usage
//!
//! ```ignore
//! use walletkit_core::credential_storage::platform::ios::IosPlatform;
//! use walletkit_core::credential_storage::WorldIdStore;
//!
//! // Create iOS platform with a root directory
//! let platform = IosPlatform::new("/path/to/app/data")?;
//!
//! // Create the World ID store
//! let store = WorldIdStore::new(platform)?;
//! ```
//!
//! # Security
//!
//! The iOS implementation uses:
//!
//! - **Keychain with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`**: Keys are only
//!   accessible when the device is unlocked and are not included in backups.
//! - **Secure Enclave (when available)**: For hardware-backed key protection.
//! - **Atomic file operations**: Write-to-temp-then-rename for crash safety.
//! - **Advisory file locking**: Using `flock()` for cross-process serialization.

mod blob_store;
mod keystore;
mod lock_manager;
mod vault_store;

pub use blob_store::IosBlobStore;
pub use keystore::IosKeystore;
pub use lock_manager::IosLockManager;
pub use vault_store::IosVaultStore;

use crate::credential_storage::{
    account::PlatformBundle,
    AccountId, StorageError, StorageResult,
};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Helper to create an IO error from an std::io::Error.
fn io_error<S: Into<String>>(context: S, err: std::io::Error) -> StorageError {
    StorageError::IoError {
        context: context.into(),
        source: err,
    }
}

// IosPlatform

/// iOS platform implementation bundling all platform traits.
///
/// This is the main entry point for iOS applications to create a properly
/// configured credential storage system.
///
/// # Directory Structure
///
/// The platform creates the following directory structure under `root_path`:
///
/// ```text
/// <root_path>/
/// └── worldid/
///     └── accounts/
///         └── <account_id_hex>/
///             ├── account_state.bin     (device-encrypted)
///             ├── pending_actions.bin   (device-encrypted)
///             └── account.vault         (vault-encrypted)
/// ```
#[derive(Debug, Clone)]
pub struct IosPlatform {
    /// Root path for all World ID data.
    root_path: PathBuf,
    /// Shared keystore instance.
    keystore: Arc<IosKeystore>,
    /// Shared lock manager instance.
    lock_manager: Arc<IosLockManager>,
}

impl IosPlatform {
    /// Creates a new iOS platform instance.
    ///
    /// # Arguments
    ///
    /// * `root_path` - The root directory for World ID data. This should typically
    ///   be the app's `Application Support` or `Documents` directory.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The root path cannot be created
    /// - Keystore initialization fails
    ///
    /// # Example
    ///
    /// ```ignore
    /// // Get the app's Application Support directory
    /// let app_support = get_application_support_directory();
    /// let platform = IosPlatform::new(app_support)?;
    /// ```
    pub fn new<P: AsRef<Path>>(root_path: P) -> StorageResult<Self> {
        let root_path = root_path.as_ref().to_path_buf();

        // Create the root directory if it doesn't exist
        std::fs::create_dir_all(&root_path).map_err(|e| {
            io_error("Failed to create root directory", e)
        })?;

        let keystore = Arc::new(IosKeystore::new()?);
        let lock_manager = Arc::new(IosLockManager::new(&root_path)?);

        Ok(Self {
            root_path,
            keystore,
            lock_manager,
        })
    }

    /// Returns the root path for World ID data.
    #[must_use]
    pub fn root_path(&self) -> &Path {
        &self.root_path
    }

    /// Returns the path to the accounts directory.
    #[must_use]
    pub fn accounts_path(&self) -> PathBuf {
        self.root_path.join("worldid").join("accounts")
    }

    /// Returns the path to a specific account's directory.
    #[must_use]
    pub fn account_path(&self, account_id: &AccountId) -> PathBuf {
        self.accounts_path().join(account_id.to_string())
    }

    /// Returns the shared keystore instance.
    #[must_use]
    pub fn keystore(&self) -> Arc<IosKeystore> {
        Arc::clone(&self.keystore)
    }

    /// Returns the shared lock manager instance.
    #[must_use]
    pub fn lock_manager(&self) -> Arc<IosLockManager> {
        Arc::clone(&self.lock_manager)
    }
}

impl PlatformBundle for IosPlatform {
    type BlobStore = IosBlobStore;
    type VaultStore = IosVaultStore;

    fn create_blob_store(&self, account_id: &AccountId) -> Self::BlobStore {
        let account_path = self.account_path(account_id);
        // Note: This unwrap is safe because we create the directory in create_account_directory
        IosBlobStore::new(&account_path).expect("Failed to create blob store")
    }

    fn create_vault_store(&self, account_id: &AccountId) -> Self::VaultStore {
        let vault_path = self.account_path(account_id).join("account.vault");
        IosVaultStore::new(&vault_path).expect("Failed to create vault store")
    }

    fn list_account_ids(&self) -> StorageResult<Vec<AccountId>> {
        let accounts_path = self.accounts_path();

        if !accounts_path.exists() {
            return Ok(Vec::new());
        }

        let mut account_ids = Vec::new();

        let entries = std::fs::read_dir(&accounts_path).map_err(|e| {
            io_error("Failed to read accounts directory", e)
        })?;

        for entry in entries {
            let entry = entry.map_err(|e| {
                io_error("Failed to read directory entry", e)
            })?;

            if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                if let Some(name) = entry.file_name().to_str() {
                    if let Ok(account_id) = AccountId::from_hex(name) {
                        account_ids.push(account_id);
                    }
                }
            }
        }

        Ok(account_ids)
    }

    fn account_exists(&self, account_id: &AccountId) -> StorageResult<bool> {
        let account_path = self.account_path(account_id);
        Ok(account_path.exists())
    }

    fn create_account_directory(&self, account_id: &AccountId) -> StorageResult<()> {
        let account_path = self.account_path(account_id);
        std::fs::create_dir_all(&account_path).map_err(|e| {
            io_error(format!("Failed to create account directory '{}'", account_path.display()), e)
        })
    }
}

impl IosPlatform {
    /// Deletes an account and all its data.
    ///
    /// This removes the account directory and any associated Keychain items.
    ///
    /// # Warning
    ///
    /// This operation is irreversible. All credentials stored in this account
    /// will be permanently deleted.
    pub fn delete_account(&self, account_id: &AccountId) -> StorageResult<()> {
        let account_path = self.account_path(account_id);

        if account_path.exists() {
            std::fs::remove_dir_all(&account_path).map_err(|e| {
                io_error("Failed to delete account directory", e)
            })?;
        }

        // Also remove any keychain items for this account
        self.keystore.delete_account_keys(account_id)?;

        Ok(())
    }
}
