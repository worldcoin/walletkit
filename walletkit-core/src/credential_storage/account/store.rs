//! `WorldIdStore` implementation for managing World ID accounts.
//!
//! The store provides the root entry point for credential storage,
//! managing multiple accounts on a single device.

use std::sync::Arc;

use crate::credential_storage::{
    platform::{AccountLockManager, AtomicBlobStore, DeviceKeystore, VaultFileStore},
    vault::{VaultFile, VaultKey},
    AccountId, StorageError, StorageResult,
};

use super::{
    derivation::derive_account_id,
    handle::AccountHandle,
    state::{create_account_state, load_account_state, save_account_state},
};

// =============================================================================
// Platform Bundle
// =============================================================================

/// A bundle of platform implementations for a specific account.
///
/// This trait allows `WorldIdStore` to create platform components for each account.
pub trait PlatformBundle: Send + Sync {
    /// The blob store type for small files.
    type BlobStore: AtomicBlobStore + 'static;
    /// The vault file store type.
    type VaultStore: VaultFileStore + 'static;

    /// Creates a blob store for an account.
    fn create_blob_store(&self, account_id: &AccountId) -> Self::BlobStore;

    /// Creates a vault store for an account.
    fn create_vault_store(&self, account_id: &AccountId) -> Self::VaultStore;

    /// Lists all account IDs that have storage directories.
    fn list_account_ids(&self) -> StorageResult<Vec<AccountId>>;

    /// Checks if an account exists.
    fn account_exists(&self, account_id: &AccountId) -> StorageResult<bool>;

    /// Creates the storage directory for a new account.
    fn create_account_directory(&self, account_id: &AccountId) -> StorageResult<()>;
}

// =============================================================================
// WorldIdStore
// =============================================================================

/// Root store for World ID credential storage.
///
/// `WorldIdStore` manages multiple accounts on a single device. It provides
/// methods to list, open, and create accounts.
///
/// # Type Parameters
///
/// * `K` - Device keystore implementation
/// * `P` - Platform bundle providing blob and vault stores
/// * `L` - Account lock manager implementation
///
/// # Example
///
/// ```ignore
/// let store = WorldIdStore::new(keystore, platform, lock_manager);
///
/// // Create a new account
/// let handle = store.create_account()?;
/// println!("Created account: {}", handle.account_id());
///
/// // List all accounts
/// for account_id in store.list_accounts()? {
///     println!("Account: {}", account_id);
/// }
///
/// // Open an existing account
/// let handle = store.open_account(&account_id)?;
/// ```
pub struct WorldIdStore<K, P, L>
where
    K: DeviceKeystore,
    P: PlatformBundle,
    L: AccountLockManager,
{
    /// Device keystore for encryption/decryption.
    keystore: Arc<K>,
    /// Platform bundle for creating stores.
    platform: Arc<P>,
    /// Lock manager for serializing account access.
    lock_manager: Arc<L>,
}

impl<K, P, L> WorldIdStore<K, P, L>
where
    K: DeviceKeystore + 'static,
    P: PlatformBundle + 'static,
    L: AccountLockManager + 'static,
{
    /// Creates a new `WorldIdStore`.
    ///
    /// # Arguments
    ///
    /// * `keystore` - Device keystore for encryption
    /// * `platform` - Platform bundle for creating stores
    /// * `lock_manager` - Lock manager for serialization
    #[must_use]
    pub fn new(keystore: Arc<K>, platform: Arc<P>, lock_manager: Arc<L>) -> Self {
        Self {
            keystore,
            platform,
            lock_manager,
        }
    }

    /// Lists all account IDs present on this device.
    ///
    /// # Errors
    ///
    /// Returns an error if listing the accounts fails.
    pub fn list_accounts(&self) -> StorageResult<Vec<AccountId>> {
        self.platform.list_account_ids()
    }

    /// Opens an existing account.
    ///
    /// # Arguments
    ///
    /// * `account_id` - The account to open
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The account doesn't exist
    /// - Loading account state fails
    /// - Opening the vault fails
    pub fn open_account(
        &self,
        account_id: &AccountId,
    ) -> StorageResult<AccountHandle<K, P::BlobStore, P::VaultStore, L>> {
        // Verify account exists
        if !self.platform.account_exists(account_id)? {
            return Err(StorageError::AccountNotFound {
                account_id: *account_id,
            });
        }

        // Create platform components for this account
        let blob_store = Arc::new(self.platform.create_blob_store(account_id));
        let vault_store = Arc::new(self.platform.create_vault_store(account_id));

        // We need to discover the device_id first by attempting to load state
        // This is a bit of a chicken-and-egg problem - we need device_id to decrypt
        // but device_id is inside the encrypted state.
        //
        // Solution: Store device_id in a separate unencrypted metadata file,
        // or use a fixed location. For now, we'll use a probe approach where
        // we try to find an existing state file.
        //
        // Actually, looking at the spec more carefully, the account_state.bin is
        // encrypted with K_device using AAD that includes device_id. This means
        // we need to know device_id to decrypt. The solution is to store device_id
        // separately or derive it deterministically per device.
        //
        // For this implementation, we'll use a probe file approach: store
        // device_id in plaintext (it's not secret, just stable per install).
        let device_id = self.load_or_create_device_id(&*blob_store)?;

        // Load account state
        let state = load_account_state(&*blob_store, &*self.keystore, account_id, &device_id)?
            .ok_or_else(|| StorageError::AccountNotFound {
                account_id: *account_id,
            })?;

        // Unwrap vault key
        let vault_key = super::state::unwrap_vault_key(
            &state.vault_key_wrap,
            account_id,
            &device_id,
            &*self.keystore,
        )?;

        // Open vault
        let vault = VaultFile::open(vault_store, *account_id, vault_key)?;

        Ok(AccountHandle::new(
            state,
            vault,
            blob_store,
            Arc::clone(&self.keystore),
            Arc::clone(&self.lock_manager),
        ))
    }

    /// Creates a new account with fresh keys.
    ///
    /// # Returns
    ///
    /// A handle to the newly created account.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Key generation fails
    /// - Creating the account directory fails
    /// - Saving account state fails
    /// - Creating the vault fails
    pub fn create_account(
        &self,
    ) -> StorageResult<AccountHandle<K, P::BlobStore, P::VaultStore, L>> {
        // Generate vault key
        let vault_key = VaultKey::generate();

        // Derive account ID
        let account_id = derive_account_id(&vault_key);

        // Check if account already exists
        if self.platform.account_exists(&account_id)? {
            return Err(StorageError::AccountAlreadyExists { account_id });
        }

        // Create account directory
        self.platform.create_account_directory(&account_id)?;

        // Create platform components
        let blob_store = Arc::new(self.platform.create_blob_store(&account_id));
        let vault_store = Arc::new(self.platform.create_vault_store(&account_id));

        // Create account state
        let state = create_account_state(&vault_key, &*self.keystore)?;
        let device_id = state.device_id;

        // Save device ID for future opens
        self.save_device_id(&*blob_store, &device_id)?;

        // Save account state
        save_account_state(&state, &*blob_store, &*self.keystore)?;

        // Create vault
        let vault = VaultFile::create(vault_store, account_id, vault_key)?;

        Ok(AccountHandle::new(
            state,
            vault,
            blob_store,
            Arc::clone(&self.keystore),
            Arc::clone(&self.lock_manager),
        ))
    }

    /// Imports an account from a provisioning envelope.
    ///
    /// This is used when setting up a new device with an existing account.
    /// The envelope contains the vault key and blinding seeds.
    ///
    /// # Arguments
    ///
    /// * `envelope` - The provisioning envelope bytes
    ///
    /// # Returns
    ///
    /// A handle to the imported account.
    ///
    /// # Note
    ///
    /// This is a placeholder implementation. Full provisioning envelope
    /// support will be added in Phase 6 (Sync & Provisioning).
    ///
    /// # Errors
    ///
    /// Returns an error if import fails.
    pub fn import_vault_provisioning_envelope(
        &self,
        _envelope: &[u8],
    ) -> StorageResult<AccountHandle<K, P::BlobStore, P::VaultStore, L>> {
        Err(StorageError::NotSupported {
            operation: "import_vault_provisioning_envelope (Phase 6)".to_string(),
        })
    }

    // =========================================================================
    // Device ID Management
    // =========================================================================

    /// Filename for device ID.
    const DEVICE_ID_FILENAME: &'static str = "device_id.bin";

    /// Loads the device ID or creates a new one.
    fn load_or_create_device_id(&self, blob_store: &dyn AtomicBlobStore) -> StorageResult<[u8; 16]> {
        if let Some(data) = blob_store.read(Self::DEVICE_ID_FILENAME)? {
            if data.len() == 16 {
                let mut device_id = [0u8; 16];
                device_id.copy_from_slice(&data);
                return Ok(device_id);
            }
        }

        // Generate and save new device ID
        let device_id = super::derivation::generate_device_id();
        self.save_device_id(blob_store, &device_id)?;
        Ok(device_id)
    }

    /// Saves the device ID.
    fn save_device_id(
        &self,
        blob_store: &dyn AtomicBlobStore,
        device_id: &[u8; 16],
    ) -> StorageResult<()> {
        blob_store.write_atomic(Self::DEVICE_ID_FILENAME, device_id)
    }
}

impl<K, P, L> std::fmt::Debug for WorldIdStore<K, P, L>
where
    K: DeviceKeystore,
    P: PlatformBundle,
    L: AccountLockManager,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WorldIdStore").finish_non_exhaustive()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential_storage::platform::memory::{MemoryBlobStore, MemoryKeystore, MemoryLockManager, MemoryVaultStore};
    use std::collections::HashMap;
    use std::sync::RwLock;

    // =========================================================================
    // Test-only Platform Bundle Implementation
    // =========================================================================

    /// Shared in-memory platform bundle that properly shares storage across opens.
    ///
    /// This version ensures that when an account is opened multiple times,
    /// the same underlying storage is used.
    pub struct SharedMemoryPlatformBundle {
        /// Blob stores keyed by account ID.
        blob_stores: RwLock<HashMap<AccountId, Arc<MemoryBlobStore>>>,
        /// Vault stores keyed by account ID.
        vault_stores: RwLock<HashMap<AccountId, Arc<MemoryVaultStore>>>,
        /// Set of existing account IDs.
        accounts: RwLock<Vec<AccountId>>,
    }

    impl SharedMemoryPlatformBundle {
        /// Creates a new empty shared memory platform bundle.
        #[must_use]
        pub fn new() -> Self {
            Self {
                blob_stores: RwLock::new(HashMap::new()),
                vault_stores: RwLock::new(HashMap::new()),
                accounts: RwLock::new(Vec::new()),
            }
        }

        /// Gets or creates a blob store for an account.
        pub fn get_or_create_blob_store(&self, account_id: &AccountId) -> Arc<MemoryBlobStore> {
            let mut stores = self.blob_stores.write().unwrap();
            stores
                .entry(*account_id)
                .or_insert_with(|| Arc::new(MemoryBlobStore::new()))
                .clone()
        }

        /// Gets or creates a vault store for an account.
        pub fn get_or_create_vault_store(&self, account_id: &AccountId) -> Arc<MemoryVaultStore> {
            let mut stores = self.vault_stores.write().unwrap();
            stores
                .entry(*account_id)
                .or_insert_with(|| Arc::new(MemoryVaultStore::new()))
                .clone()
        }
    }

    impl Default for SharedMemoryPlatformBundle {
        fn default() -> Self {
            Self::new()
        }
    }

    /// Wrapper blob store that delegates to a shared store.
    pub struct SharedBlobStore {
        inner: Arc<MemoryBlobStore>,
    }

    impl SharedBlobStore {
        /// Creates a new shared blob store.
        pub fn new(inner: Arc<MemoryBlobStore>) -> Self {
            Self { inner }
        }
    }

    impl AtomicBlobStore for SharedBlobStore {
        fn read(&self, name: &str) -> StorageResult<Option<Vec<u8>>> {
            self.inner.read(name)
        }

        fn write_atomic(&self, name: &str, bytes: &[u8]) -> StorageResult<()> {
            self.inner.write_atomic(name, bytes)
        }

        fn delete(&self, name: &str) -> StorageResult<()> {
            self.inner.delete(name)
        }

        fn exists(&self, name: &str) -> StorageResult<bool> {
            self.inner.exists(name)
        }
    }

    /// Wrapper vault store that delegates to a shared store.
    pub struct SharedVaultStore {
        inner: Arc<MemoryVaultStore>,
    }

    impl SharedVaultStore {
        /// Creates a new shared vault store.
        pub fn new(inner: Arc<MemoryVaultStore>) -> Self {
            Self { inner }
        }
    }

    impl VaultFileStore for SharedVaultStore {
        fn len(&self) -> StorageResult<u64> {
            self.inner.len()
        }

        fn read_at(&self, offset: u64, len: u32) -> StorageResult<Vec<u8>> {
            self.inner.read_at(offset, len)
        }

        fn write_at(&self, offset: u64, bytes: &[u8]) -> StorageResult<()> {
            self.inner.write_at(offset, bytes)
        }

        fn append(&self, bytes: &[u8]) -> StorageResult<u64> {
            self.inner.append(bytes)
        }

        fn sync(&self) -> StorageResult<()> {
            self.inner.sync()
        }

        fn set_len(&self, len: u64) -> StorageResult<()> {
            self.inner.set_len(len)
        }
    }

    impl PlatformBundle for SharedMemoryPlatformBundle {
        type BlobStore = SharedBlobStore;
        type VaultStore = SharedVaultStore;

        fn create_blob_store(&self, account_id: &AccountId) -> Self::BlobStore {
            SharedBlobStore::new(self.get_or_create_blob_store(account_id))
        }

        fn create_vault_store(&self, account_id: &AccountId) -> Self::VaultStore {
            SharedVaultStore::new(self.get_or_create_vault_store(account_id))
        }

        fn list_account_ids(&self) -> StorageResult<Vec<AccountId>> {
            Ok(self.accounts.read().unwrap().clone())
        }

        fn account_exists(&self, account_id: &AccountId) -> StorageResult<bool> {
            Ok(self.accounts.read().unwrap().contains(account_id))
        }

        fn create_account_directory(&self, account_id: &AccountId) -> StorageResult<()> {
            let mut accounts = self.accounts.write().unwrap();
            if !accounts.contains(account_id) {
                accounts.push(*account_id);
            }
            Ok(())
        }
    }

    // =========================================================================
    // Test Helpers
    // =========================================================================

    fn create_test_store(
    ) -> WorldIdStore<MemoryKeystore, SharedMemoryPlatformBundle, MemoryLockManager> {
        let keystore = Arc::new(MemoryKeystore::new());
        let platform = Arc::new(SharedMemoryPlatformBundle::new());
        let lock_manager = Arc::new(MemoryLockManager::new());

        WorldIdStore::new(keystore, platform, lock_manager)
    }

    // =========================================================================
    // Tests
    // =========================================================================

    #[test]
    fn test_create_account() {
        let store = create_test_store();

        let handle = store.create_account().unwrap();
        let account_id = *handle.account_id();

        // Account should appear in list
        let accounts = store.list_accounts().unwrap();
        assert!(accounts.contains(&account_id));
    }

    #[test]
    fn test_list_accounts_empty() {
        let store = create_test_store();

        let accounts = store.list_accounts().unwrap();
        assert!(accounts.is_empty());
    }

    #[test]
    fn test_create_multiple_accounts() {
        let store = create_test_store();

        let handle1 = store.create_account().unwrap();
        let handle2 = store.create_account().unwrap();
        let handle3 = store.create_account().unwrap();

        let accounts = store.list_accounts().unwrap();
        assert_eq!(accounts.len(), 3);
        assert!(accounts.contains(handle1.account_id()));
        assert!(accounts.contains(handle2.account_id()));
        assert!(accounts.contains(handle3.account_id()));
    }

    #[test]
    fn test_open_account() {
        let keystore = Arc::new(MemoryKeystore::new());
        let platform = Arc::new(SharedMemoryPlatformBundle::new());
        let lock_manager = Arc::new(MemoryLockManager::new());
        let store = WorldIdStore::new(
            Arc::clone(&keystore),
            Arc::clone(&platform),
            Arc::clone(&lock_manager),
        );

        // Create account
        let handle = store.create_account().unwrap();
        let account_id = *handle.account_id();
        drop(handle);

        // Re-open account
        let store2 = WorldIdStore::new(keystore, platform, lock_manager);
        let handle2 = store2.open_account(&account_id).unwrap();

        assert_eq!(handle2.account_id(), &account_id);
    }

    #[test]
    fn test_open_nonexistent_account() {
        let store = create_test_store();
        let fake_id = AccountId::new([0xFFu8; 32]);

        let result = store.open_account(&fake_id);
        assert!(matches!(result, Err(StorageError::AccountNotFound { .. })));
    }

    #[test]
    fn test_account_state_persists() {
        let keystore = Arc::new(MemoryKeystore::new());
        let platform = Arc::new(SharedMemoryPlatformBundle::new());
        let lock_manager = Arc::new(MemoryLockManager::new());
        let store = WorldIdStore::new(
            Arc::clone(&keystore),
            Arc::clone(&platform),
            Arc::clone(&lock_manager),
        );

        // Create account and set leaf index
        let mut handle = store.create_account().unwrap();
        let account_id = *handle.account_id();
        handle.set_leaf_index_cache(12345).unwrap();
        drop(handle);

        // Re-open and verify
        let store2 = WorldIdStore::new(keystore, platform, lock_manager);
        let handle2 = store2.open_account(&account_id).unwrap();

        assert_eq!(handle2.get_leaf_index_cache().unwrap(), Some(12345));
    }

    #[test]
    fn test_import_envelope_not_supported_yet() {
        let store = create_test_store();

        let result = store.import_vault_provisioning_envelope(&[1, 2, 3]);
        assert!(matches!(result, Err(StorageError::NotSupported { .. })));
    }

    #[test]
    fn test_store_debug() {
        let store = create_test_store();
        let debug = format!("{store:?}");
        assert!(debug.contains("WorldIdStore"));
    }
}
