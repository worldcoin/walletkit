//! `AccountHandle` implementation for account operations.
//!
//! The handle provides access to account state, key derivation, and
//! credential operations.

mod credentials;
mod nullifier;

#[cfg(test)]
mod tests;

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
    pub(crate) state: AccountState,
    /// Vault file handle.
    pub(crate) vault: VaultFile<V>,
    /// Blob store for this account.
    pub(crate) blob_store: Arc<B>,
    /// Device keystore.
    pub(crate) keystore: Arc<K>,
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
    pub(crate) const fn new(
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
    pub const fn get_leaf_index_cache(&self) -> StorageResult<Option<u64>> {
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
    pub(crate) fn save_state(&self) -> StorageResult<()> {
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
pub(crate) fn get_current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time before Unix epoch")
        .as_secs()
}
