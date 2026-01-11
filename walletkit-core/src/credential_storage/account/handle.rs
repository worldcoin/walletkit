//! `AccountHandle` implementation for account operations.
//!
//! The handle provides access to account state, key derivation, and
//! credential operations.

use std::sync::Arc;

use crate::credential_storage::{
    platform::{AccountLockManager, AtomicBlobStore, DeviceKeystore, VaultFileStore},
    vault::VaultFile,
    AccountId, AccountState, StorageResult,
};

use super::{
    derivation::{derive_issuer_blind, derive_session_r},
    state::save_account_state,
};

// =============================================================================
// AccountHandle
// =============================================================================

/// Handle to an open World ID account.
///
/// `AccountHandle` provides all account operations including:
/// - Account state management (leaf index cache)
/// - Key derivation (issuer blind, session R)
/// - Vault access (via `vault()` method for credential operations)
///
/// # Thread Safety
///
/// `AccountHandle` is NOT thread-safe. External locking should be used
/// for concurrent access. The lock manager is available for serializing
/// mutations via `with_lock()`.
///
/// # Example
///
/// ```ignore
/// // Get account ID
/// let account_id = handle.account_id();
///
/// // Manage leaf index cache
/// handle.set_leaf_index_cache(12345)?;
/// let cached = handle.get_leaf_index_cache()?;
///
/// // Derive keys
/// let issuer_blind = handle.derive_issuer_blind(schema_id)?;
/// let session_r = handle.derive_session_r(rp_id, action_id)?;
///
/// // Access vault for credential operations
/// handle.vault_mut().with_txn(|txn| {
///     // ... credential operations
///     Ok(())
/// })?;
/// ```
pub struct AccountHandle<K, B, V, L>
where
    K: DeviceKeystore,
    B: AtomicBlobStore,
    V: VaultFileStore,
    L: AccountLockManager,
{
    /// Current account state.
    state: AccountState,
    /// Vault file handle.
    vault: VaultFile<V>,
    /// Blob store for this account.
    blob_store: Arc<B>,
    /// Device keystore.
    keystore: Arc<K>,
    /// Lock manager for serialization.
    lock_manager: Arc<L>,
}

impl<K, B, V, L> AccountHandle<K, B, V, L>
where
    K: DeviceKeystore + 'static,
    B: AtomicBlobStore + 'static,
    V: VaultFileStore + 'static,
    L: AccountLockManager + 'static,
{
    /// Creates a new account handle.
    ///
    /// This is typically called by `WorldIdStore` when opening or creating
    /// an account, not directly by users.
    pub(crate) fn new(
        state: AccountState,
        vault: VaultFile<V>,
        blob_store: Arc<B>,
        keystore: Arc<K>,
        lock_manager: Arc<L>,
    ) -> Self {
        Self {
            state,
            vault,
            blob_store,
            keystore,
            lock_manager,
        }
    }

    // =========================================================================
    // Identity
    // =========================================================================

    /// Returns the account ID.
    #[must_use]
    pub const fn account_id(&self) -> &AccountId {
        &self.state.account_id
    }

    /// Returns the device ID.
    #[must_use]
    pub const fn device_id(&self) -> &[u8; 16] {
        &self.state.device_id
    }

    // =========================================================================
    // Leaf Index Cache
    // =========================================================================

    /// Gets the cached leaf index.
    ///
    /// The leaf index is the account's position in the World ID Registry
    /// Merkle tree. It's cached locally to avoid repeated lookups.
    ///
    /// # Returns
    ///
    /// `Some(index)` if cached, `None` if not set.
    ///
    /// # Errors
    ///
    /// This method doesn't fail - errors are only possible in `set_leaf_index_cache`.
    #[must_use]
    pub fn get_leaf_index_cache(&self) -> StorageResult<Option<u64>> {
        Ok(self.state.leaf_index_cache)
    }

    /// Sets the cached leaf index.
    ///
    /// This persists the leaf index to device-protected storage so it
    /// survives app restarts.
    ///
    /// # Arguments
    ///
    /// * `leaf_index` - The leaf index to cache
    ///
    /// # Errors
    ///
    /// Returns an error if persisting the state fails.
    pub fn set_leaf_index_cache(&mut self, leaf_index: u64) -> StorageResult<()> {
        self.state.leaf_index_cache = Some(leaf_index);
        self.state.updated_at = get_current_timestamp();
        self.save_state()
    }

    /// Clears the cached leaf index.
    ///
    /// # Errors
    ///
    /// Returns an error if persisting the state fails.
    pub fn clear_leaf_index_cache(&mut self) -> StorageResult<()> {
        self.state.leaf_index_cache = None;
        self.state.updated_at = get_current_timestamp();
        self.save_state()
    }

    // =========================================================================
    // Key Derivation
    // =========================================================================

    /// Derives the issuer blinding factor for a specific issuer schema.
    ///
    /// This is used to blind credentials during issuance to prevent
    /// correlation even among issuers.
    ///
    /// # Arguments
    ///
    /// * `issuer_schema_id` - The issuer schema ID from the registry
    ///
    /// # Returns
    ///
    /// A 32-byte blinding factor.
    #[must_use]
    pub fn derive_issuer_blind(&self, issuer_schema_id: u64) -> [u8; 32] {
        derive_issuer_blind(&self.state.issuer_blind_seed, issuer_schema_id)
    }

    /// Derives the session blinding factor for a specific RP and action.
    ///
    /// This is used in proof generation to provide session binding while
    /// maintaining unlinkability.
    ///
    /// # Arguments
    ///
    /// * `rp_id` - The 32-byte relying party identifier
    /// * `action_id` - The 32-byte action identifier
    ///
    /// # Returns
    ///
    /// A 32-byte blinding factor (session R).
    #[must_use]
    pub fn derive_session_r(&self, rp_id: &[u8; 32], action_id: &[u8; 32]) -> [u8; 32] {
        derive_session_r(&self.state.session_blind_seed, rp_id, action_id)
    }

    // =========================================================================
    // Vault Access
    // =========================================================================

    /// Returns a reference to the vault file.
    ///
    /// Use this for read-only vault operations like reading the index
    /// or reading blobs.
    #[must_use]
    pub const fn vault(&self) -> &VaultFile<V> {
        &self.vault
    }

    /// Returns a mutable reference to the vault file.
    ///
    /// Use this for write operations via transactions.
    ///
    /// # Example
    ///
    /// ```ignore
    /// handle.vault_mut().with_txn(|txn| {
    ///     let (cid, ptr) = txn.put_blob(BlobKind::CredentialBlob, &data)?;
    ///     // ...
    ///     Ok(())
    /// })?;
    /// ```
    pub fn vault_mut(&mut self) -> &mut VaultFile<V> {
        &mut self.vault
    }

    // =========================================================================
    // Locking
    // =========================================================================

    /// Executes a closure while holding the account lock.
    ///
    /// This ensures serialized access to the account across threads/processes.
    ///
    /// # Arguments
    ///
    /// * `f` - The closure to execute
    ///
    /// # Errors
    ///
    /// Returns an error if the lock cannot be acquired or if the closure fails.
    pub fn with_lock<R, F>(&self, f: F) -> StorageResult<R>
    where
        F: FnOnce() -> StorageResult<R>,
    {
        self.lock_manager.with_account_lock(&self.state.account_id, f)
    }

    // =========================================================================
    // State Access (for advanced use)
    // =========================================================================

    /// Returns a reference to the account state.
    ///
    /// This is primarily for advanced use cases or testing.
    #[must_use]
    pub const fn state(&self) -> &AccountState {
        &self.state
    }

    /// Returns the issuer blind seed.
    ///
    /// This is the raw seed used for deriving issuer blinding factors.
    /// Generally, you should use `derive_issuer_blind()` instead.
    #[must_use]
    pub const fn issuer_blind_seed(&self) -> &[u8; 32] {
        &self.state.issuer_blind_seed
    }

    /// Returns the session blind seed.
    ///
    /// This is the raw seed used for deriving session R values.
    /// Generally, you should use `derive_session_r()` instead.
    #[must_use]
    pub const fn session_blind_seed(&self) -> &[u8; 32] {
        &self.state.session_blind_seed
    }

    // =========================================================================
    // Internal
    // =========================================================================

    /// Saves the current state to device-protected storage.
    fn save_state(&self) -> StorageResult<()> {
        save_account_state(&self.state, &*self.blob_store, &*self.keystore)
    }
}

impl<K, B, V, L> std::fmt::Debug for AccountHandle<K, B, V, L>
where
    K: DeviceKeystore,
    B: AtomicBlobStore,
    V: VaultFileStore,
    L: AccountLockManager,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccountHandle")
            .field("account_id", &self.state.account_id)
            .field("leaf_index_cache", &self.state.leaf_index_cache)
            .finish_non_exhaustive()
    }
}

// =============================================================================
// Helpers
// =============================================================================

/// Returns the current Unix timestamp.
fn get_current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time before Unix epoch")
        .as_secs()
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential_storage::{
        account::store::{PlatformBundle, WorldIdStore},
        platform::memory::{MemoryBlobStore, MemoryKeystore, MemoryLockManager, MemoryVaultStore},
    };
    use std::collections::HashMap;
    use std::sync::RwLock;

    // =========================================================================
    // Test-only Platform Bundle Implementation
    // =========================================================================

    /// Shared in-memory platform bundle that properly shares storage across opens.
    struct SharedMemoryPlatformBundle {
        blob_stores: RwLock<HashMap<AccountId, Arc<MemoryBlobStore>>>,
        vault_stores: RwLock<HashMap<AccountId, Arc<MemoryVaultStore>>>,
        accounts: RwLock<Vec<AccountId>>,
    }

    impl SharedMemoryPlatformBundle {
        fn new() -> Self {
            Self {
                blob_stores: RwLock::new(HashMap::new()),
                vault_stores: RwLock::new(HashMap::new()),
                accounts: RwLock::new(Vec::new()),
            }
        }

        fn get_or_create_blob_store(&self, account_id: &AccountId) -> Arc<MemoryBlobStore> {
            let mut stores = self.blob_stores.write().unwrap();
            stores
                .entry(*account_id)
                .or_insert_with(|| Arc::new(MemoryBlobStore::new()))
                .clone()
        }

        fn get_or_create_vault_store(&self, account_id: &AccountId) -> Arc<MemoryVaultStore> {
            let mut stores = self.vault_stores.write().unwrap();
            stores
                .entry(*account_id)
                .or_insert_with(|| Arc::new(MemoryVaultStore::new()))
                .clone()
        }
    }

    struct SharedBlobStore {
        inner: Arc<MemoryBlobStore>,
    }

    impl SharedBlobStore {
        fn new(inner: Arc<MemoryBlobStore>) -> Self {
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

    struct SharedVaultStore {
        inner: Arc<MemoryVaultStore>,
    }

    impl SharedVaultStore {
        fn new(inner: Arc<MemoryVaultStore>) -> Self {
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
    // Test Helper
    // =========================================================================

    fn create_test_handle() -> AccountHandle<MemoryKeystore, SharedBlobStore, SharedVaultStore, MemoryLockManager> {
        let keystore = Arc::new(MemoryKeystore::new());
        let platform = Arc::new(SharedMemoryPlatformBundle::new());
        let lock_manager = Arc::new(MemoryLockManager::new());
        let store = WorldIdStore::new(keystore, platform, lock_manager);

        store.create_account().unwrap()
    }

    // =========================================================================
    // Tests
    // =========================================================================

    #[test]
    fn test_account_id() {
        let handle = create_test_handle();
        let id = handle.account_id();

        // ID should be a valid 32-byte value
        assert_eq!(id.as_bytes().len(), 32);
    }

    #[test]
    fn test_device_id() {
        let handle = create_test_handle();
        let id = handle.device_id();

        // Device ID should be 16 bytes
        assert_eq!(id.len(), 16);
    }

    #[test]
    fn test_leaf_index_cache() {
        let mut handle = create_test_handle();

        // Initially None
        assert_eq!(handle.get_leaf_index_cache().unwrap(), None);

        // Set value
        handle.set_leaf_index_cache(42).unwrap();
        assert_eq!(handle.get_leaf_index_cache().unwrap(), Some(42));

        // Update value
        handle.set_leaf_index_cache(999).unwrap();
        assert_eq!(handle.get_leaf_index_cache().unwrap(), Some(999));

        // Clear value
        handle.clear_leaf_index_cache().unwrap();
        assert_eq!(handle.get_leaf_index_cache().unwrap(), None);
    }

    #[test]
    fn test_derive_issuer_blind_deterministic() {
        let handle = create_test_handle();

        let blind1 = handle.derive_issuer_blind(1);
        let blind2 = handle.derive_issuer_blind(1);

        assert_eq!(blind1, blind2);
    }

    #[test]
    fn test_derive_issuer_blind_different_schemas() {
        let handle = create_test_handle();

        let blind1 = handle.derive_issuer_blind(1);
        let blind2 = handle.derive_issuer_blind(2);

        assert_ne!(blind1, blind2);
    }

    #[test]
    fn test_derive_session_r_deterministic() {
        let handle = create_test_handle();
        let rp_id = [0x11u8; 32];
        let action_id = [0x22u8; 32];

        let r1 = handle.derive_session_r(&rp_id, &action_id);
        let r2 = handle.derive_session_r(&rp_id, &action_id);

        assert_eq!(r1, r2);
    }

    #[test]
    fn test_derive_session_r_different_inputs() {
        let handle = create_test_handle();
        let rp_id1 = [0x11u8; 32];
        let rp_id2 = [0x33u8; 32];
        let action_id = [0x22u8; 32];

        let r1 = handle.derive_session_r(&rp_id1, &action_id);
        let r2 = handle.derive_session_r(&rp_id2, &action_id);

        assert_ne!(r1, r2);
    }

    #[test]
    fn test_vault_access() {
        let handle = create_test_handle();

        // Read vault index
        let index = handle.vault().read_index().unwrap();

        // Index should belong to this account
        assert_eq!(index.account_id, *handle.account_id());
        assert!(index.records.is_empty());
    }

    #[test]
    fn test_vault_mut_access() {
        let mut handle = create_test_handle();

        // Perform a transaction
        handle
            .vault_mut()
            .with_txn(|_txn| {
                // Just commit an empty transaction
                Ok(())
            })
            .unwrap();

        // Verify index sequence increased
        let index = handle.vault().read_index().unwrap();
        assert!(index.sequence > 0);
    }

    #[test]
    fn test_with_lock() {
        let handle = create_test_handle();
        let _account_id = *handle.account_id();

        let result = handle.with_lock(|| {
            // Some operation under lock
            Ok(42)
        });

        assert_eq!(result.unwrap(), 42);
    }

    #[test]
    fn test_state_access() {
        let handle = create_test_handle();

        let state = handle.state();
        assert_eq!(state.account_id, *handle.account_id());
    }

    #[test]
    fn test_debug_format() {
        let handle = create_test_handle();
        let debug = format!("{handle:?}");

        assert!(debug.contains("AccountHandle"));
        assert!(debug.contains("account_id"));
    }

    #[test]
    fn test_issuer_blind_seed_access() {
        let handle = create_test_handle();

        let seed = handle.issuer_blind_seed();
        assert_eq!(seed.len(), 32);

        // Verify it matches what derivation uses
        let derived = derive_issuer_blind(seed, 123);
        let via_handle = handle.derive_issuer_blind(123);
        assert_eq!(derived, via_handle);
    }

    #[test]
    fn test_session_blind_seed_access() {
        let handle = create_test_handle();

        let seed = handle.session_blind_seed();
        assert_eq!(seed.len(), 32);

        // Verify it matches what derivation uses
        let rp_id = [0xAA; 32];
        let action_id = [0xBB; 32];
        let derived = derive_session_r(seed, &rp_id, &action_id);
        let via_handle = handle.derive_session_r(&rp_id, &action_id);
        assert_eq!(derived, via_handle);
    }
}
