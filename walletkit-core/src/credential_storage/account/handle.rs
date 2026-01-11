//! `AccountHandle` implementation for account operations.
//!
//! The handle provides access to account state, key derivation, and
//! credential operations.

use std::sync::Arc;

use crate::credential_storage::{
    pending::{load_pending_actions, save_pending_actions, OnpClient},
    platform::{AccountLockManager, AtomicBlobStore, DeviceKeystore, VaultFileStore},
    vault::VaultFile,
    AccountId, AccountState, BlobKind, CredentialFilter, CredentialId, CredentialRecord,
    CredentialStatus, PendingActionEntry, StorageError, StorageResult,
};

use super::{
    derivation::{compute_action_scope, compute_request_id, derive_issuer_blind, derive_session_r},
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
    pub const fn vault_mut(&mut self) -> &mut VaultFile<V> {
        &mut self.vault
    }

    // =========================================================================
    // Credential Operations
    // =========================================================================

    /// Stores or updates a credential and its associated blobs.
    ///
    /// This atomically writes the credential blob (and optional associated data)
    /// to the vault and updates the credential index.
    ///
    /// # Arguments
    ///
    /// * `credential_id` - Unique identifier for this credential
    /// * `issuer_schema_id` - Schema identifier from the Credential Schema Issuer Registry
    /// * `expires_at` - Optional Unix timestamp when the credential expires
    /// * `credential_blob` - The main credential data
    /// * `associated_data` - Optional associated data (metadata, auxiliary info)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Writing blobs to the vault fails
    /// - Updating the index fails
    /// - The transaction cannot be committed
    ///
    /// # Example
    ///
    /// ```ignore
    /// let cred_id = CredentialId::generate();
    /// handle.put_credential(
    ///     cred_id,
    ///     42, // issuer_schema_id
    ///     Some(now + 86400 * 365), // expires in 1 year
    ///     b"credential data",
    ///     Some(b"metadata"),
    /// )?;
    /// ```
    pub fn put_credential(
        &mut self,
        credential_id: CredentialId,
        issuer_schema_id: u64,
        expires_at: Option<u64>,
        credential_blob: &[u8],
        associated_data: Option<&[u8]>,
    ) -> StorageResult<()> {
        let now = get_current_timestamp();

        self.vault.with_txn(|txn| {
            // Load current index
            let mut index = txn.load_index()?;

            // Write credential blob
            let (cred_cid, cred_ptr) = txn.put_blob(BlobKind::CredentialBlob, credential_blob)?;
            index.blobs.push(cred_ptr);

            // Write associated data if provided
            let assoc_cid = if let Some(data) = associated_data {
                let (cid, ptr) = txn.put_blob(BlobKind::AssociatedData, data)?;
                index.blobs.push(ptr);
                Some(cid)
            } else {
                None
            };

            // Check if credential already exists (update case)
            if let Some(existing) = index.find_credential_mut(&credential_id) {
                // Update existing record
                existing.issuer_schema_id = issuer_schema_id;
                existing.expires_at = expires_at;
                existing.credential_blob_cid = cred_cid;
                existing.associated_data_cid = assoc_cid;
                existing.updated_at = now;
                // Keep existing status and created_at
            } else {
                // Create new record
                let record = CredentialRecord::new(
                    credential_id,
                    issuer_schema_id,
                    now,
                    expires_at,
                    cred_cid,
                    assoc_cid,
                );
                index.records.push(record);
            }

            txn.set_index(index);
            Ok(())
        })
    }

    /// Retrieves a credential's blobs by ID.
    ///
    /// Returns the credential blob and optional associated data.
    ///
    /// # Arguments
    ///
    /// * `credential_id` - The credential ID to retrieve
    ///
    /// # Returns
    ///
    /// A tuple of `(credential_blob, associated_data)`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The credential is not found
    /// - Reading blobs from the vault fails
    ///
    /// # Example
    ///
    /// ```ignore
    /// let (cred_blob, assoc_data) = handle.get_credential(cred_id)?;
    /// println!("Credential: {} bytes", cred_blob.len());
    /// if let Some(data) = assoc_data {
    ///     println!("Associated data: {} bytes", data.len());
    /// }
    /// ```
    pub fn get_credential(
        &self,
        credential_id: CredentialId,
    ) -> StorageResult<(Vec<u8>, Option<Vec<u8>>)> {
        // Read the current index
        let index = self.vault.read_index()?;

        // Find the credential record
        let record = index
            .find_credential(&credential_id)
            .ok_or(StorageError::CredentialNotFound { credential_id })?;

        // Find and read the credential blob
        let cred_ptr = index
            .find_blob(&record.credential_blob_cid)
            .ok_or_else(|| {
                StorageError::corrupted(format!(
                    "credential blob not found for content_id: {}",
                    record.credential_blob_cid
                ))
            })?;
        let cred_blob = self.vault.read_blob(cred_ptr)?;

        // Read associated data if present
        let assoc_blob = if let Some(ref assoc_cid) = record.associated_data_cid {
            let assoc_ptr = index.find_blob(assoc_cid).ok_or_else(|| {
                StorageError::corrupted(format!(
                    "associated data blob not found for content_id: {assoc_cid}"
                ))
            })?;
            Some(self.vault.read_blob(assoc_ptr)?)
        } else {
            None
        };

        Ok((cred_blob, assoc_blob))
    }

    /// Lists credentials matching an optional filter.
    ///
    /// Returns credential records (metadata only, not blob contents).
    /// Use `get_credential()` to retrieve the actual blob data.
    ///
    /// # Arguments
    ///
    /// * `filter` - Optional filter criteria. If `None`, returns all credentials.
    ///
    /// # Returns
    ///
    /// A vector of matching `CredentialRecord`s.
    ///
    /// # Errors
    ///
    /// Returns an error if reading the vault index fails.
    ///
    /// # Example
    ///
    /// ```ignore
    /// // List all active, non-expired credentials
    /// let active = handle.list_credentials(Some(CredentialFilter::new()))?;
    ///
    /// // List all credentials for a specific issuer
    /// let filter = CredentialFilter::new()
    ///     .with_issuer_schema_id(42)
    ///     .any_status()
    ///     .include_expired();
    /// let issuer_creds = handle.list_credentials(Some(filter))?;
    ///
    /// // List all credentials (no filter)
    /// let all = handle.list_credentials(None)?;
    /// ```
    pub fn list_credentials(
        &self,
        filter: Option<CredentialFilter>,
    ) -> StorageResult<Vec<CredentialRecord>> {
        let index = self.vault.read_index()?;
        let now = get_current_timestamp();

        let credentials = if let Some(f) = filter {
            index
                .records
                .iter()
                .filter(|record| f.matches(record, now))
                .cloned()
                .collect()
        } else {
            // No filter - return all credentials
            index.records
        };

        Ok(credentials)
    }

    /// Marks a credential as retired (soft-delete).
    ///
    /// Retired credentials are not eligible for use in proofs but remain
    /// in the vault for audit purposes. They can be filtered out using
    /// `CredentialFilter::with_status(CredentialStatus::Active)`.
    ///
    /// # Arguments
    ///
    /// * `credential_id` - The credential ID to retire
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The credential is not found
    /// - Updating the vault fails
    ///
    /// # Example
    ///
    /// ```ignore
    /// // Retire a credential
    /// handle.retire_credential(cred_id)?;
    ///
    /// // It will no longer appear in default listings
    /// let active = handle.list_credentials(Some(CredentialFilter::new()))?;
    /// assert!(!active.iter().any(|r| r.credential_id == cred_id));
    ///
    /// // But can still be retrieved explicitly
    /// let (blob, _) = handle.get_credential(cred_id)?;
    /// ```
    pub fn retire_credential(&mut self, credential_id: CredentialId) -> StorageResult<()> {
        let now = get_current_timestamp();

        self.vault.with_txn(|txn| {
            // Load current index
            let mut index = txn.load_index()?;

            // Find the credential record
            let record = index
                .find_credential_mut(&credential_id)
                .ok_or(StorageError::CredentialNotFound { credential_id })?;

            // Update status
            record.status = CredentialStatus::Retired;
            record.updated_at = now;

            txn.set_index(index);
            Ok(())
        })
    }

    /// Gets a credential record (metadata) by ID without reading blobs.
    ///
    /// This is more efficient than `get_credential()` when you only need
    /// the metadata (status, timestamps, etc.) and not the actual blob data.
    ///
    /// # Arguments
    ///
    /// * `credential_id` - The credential ID to look up
    ///
    /// # Returns
    ///
    /// The `CredentialRecord` if found.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The credential is not found
    /// - Reading the vault index fails
    pub fn get_credential_record(
        &self,
        credential_id: CredentialId,
    ) -> StorageResult<CredentialRecord> {
        let index = self.vault.read_index()?;
        index
            .find_credential(&credential_id)
            .cloned()
            .ok_or(StorageError::CredentialNotFound { credential_id })
    }

    // =========================================================================
    // Nullifier Protection (ONP Integration)
    // =========================================================================

    /// Begins nullifier disclosure for an action.
    ///
    /// This method implements the nullifier single-use invariant by:
    /// 1. Checking for existing pending actions (idempotent replay)
    /// 2. Verifying the nullifier hasn't been consumed via ONP
    /// 3. Storing the pending action for crash recovery
    ///
    /// # Arguments
    ///
    /// * `rp_id` - The 32-byte relying party identifier
    /// * `action_id` - The 32-byte action identifier
    /// * `signed_request_bytes` - The signed proof request (for request_id computation)
    /// * `nullifier` - The 32-byte nullifier being disclosed
    /// * `proof_package` - The complete proof package bytes to return to RP
    /// * `onp` - The ONP client for nullifier consumption checks
    ///
    /// # Returns
    ///
    /// The proof package bytes (either newly stored or from idempotent replay).
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - An action is already pending for this scope with a different request
    /// - The nullifier has already been consumed (from ONP)
    /// - The pending action store is at capacity
    /// - Storage operations fail
    ///
    /// # Idempotent Replay
    ///
    /// If called again with the same `(rp_id, action_id, signed_request_bytes)`,
    /// returns the stored `proof_package` without error. This allows retrying
    /// after transient failures.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let proof_package = handle.begin_action_disclosure(
    ///     &rp_id,
    ///     &action_id,
    ///     &signed_request,
    ///     &nullifier,
    ///     &proof_bytes,
    ///     &onp_client,
    /// )?;
    /// // Send proof_package to RP...
    /// ```
    pub fn begin_action_disclosure(
        &self,
        rp_id: &[u8; 32],
        action_id: &[u8; 32],
        signed_request_bytes: &[u8],
        nullifier: &[u8; 32],
        proof_package: &[u8],
        onp: &dyn OnpClient,
    ) -> StorageResult<Vec<u8>> {
        let action_scope = compute_action_scope(rp_id, action_id);
        let request_id = compute_request_id(signed_request_bytes);
        let now = get_current_timestamp();

        // Load and prune pending store
        let mut pending = load_pending_actions(
            &*self.blob_store,
            &*self.keystore,
            &self.state.account_id,
            &self.state.device_id,
        )?;
        pending.prune_expired(now);

        // Check for existing entry
        if let Some(entry) = pending.find_by_scope(&action_scope) {
            if entry.request_id == request_id {
                // Idempotent replay - return stored proof
                return Ok(entry.proof_package.clone());
            } else if !entry.is_expired(now) {
                // Different request for same action still pending
                return Err(StorageError::ActionAlreadyPending { action_scope });
            }
            // Entry exists but is expired - will be replaced
        }

        // Check ONP for nullifier consumption
        if onp.check_consumed(nullifier)? {
            return Err(StorageError::NullifierAlreadyConsumed);
        }

        // Remove any expired entry for this scope before inserting
        pending.remove(&action_scope);

        // Store pending entry
        let entry = PendingActionEntry::new(
            action_scope,
            request_id,
            *nullifier,
            proof_package.to_vec(),
            now,
        );

        if !pending.insert(entry) {
            return Err(StorageError::PendingActionStoreFull);
        }

        // Save pending store
        save_pending_actions(&pending, &*self.blob_store, &*self.keystore, &self.state.device_id)?;

        Ok(proof_package.to_vec())
    }

    /// Commits an action, marking the nullifier as consumed.
    ///
    /// This method should be called after the RP has successfully verified
    /// the proof. It:
    /// 1. Retrieves the pending action entry
    /// 2. Marks the nullifier as consumed in ONP
    /// 3. Removes the pending entry
    ///
    /// # Arguments
    ///
    /// * `rp_id` - The 32-byte relying party identifier
    /// * `action_id` - The 32-byte action identifier
    /// * `onp` - The ONP client for marking nullifier as consumed
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - No pending action found for this scope
    /// - ONP fails to mark the nullifier as consumed
    /// - Storage operations fail
    ///
    /// # Example
    ///
    /// ```ignore
    /// // After RP confirms proof verification...
    /// handle.commit_action(&rp_id, &action_id, &onp_client)?;
    /// ```
    pub fn commit_action(
        &self,
        rp_id: &[u8; 32],
        action_id: &[u8; 32],
        onp: &dyn OnpClient,
    ) -> StorageResult<()> {
        let action_scope = compute_action_scope(rp_id, action_id);

        // Load pending store
        let mut pending = load_pending_actions(
            &*self.blob_store,
            &*self.keystore,
            &self.state.account_id,
            &self.state.device_id,
        )?;

        // Find and remove the entry
        let entry = pending.remove(&action_scope).ok_or(StorageError::PendingActionNotFound {
            action_scope,
        })?;

        // Mark nullifier as consumed in ONP
        onp.mark_consumed(&entry.nullifier)?;

        // Save pending store (with entry removed)
        save_pending_actions(&pending, &*self.blob_store, &*self.keystore, &self.state.device_id)?;

        Ok(())
    }

    /// Cancels an action without consuming the nullifier.
    ///
    /// This method should be called when the proof disclosure is abandoned
    /// (e.g., user cancels, RP rejects, timeout). It removes the pending
    /// entry without interacting with ONP, allowing the nullifier to be
    /// reused in a future action.
    ///
    /// # Arguments
    ///
    /// * `rp_id` - The 32-byte relying party identifier
    /// * `action_id` - The 32-byte action identifier
    ///
    /// # Errors
    ///
    /// Returns an error if storage operations fail.
    /// Does NOT error if no pending action exists (idempotent).
    ///
    /// # Example
    ///
    /// ```ignore
    /// // User cancelled the proof request
    /// handle.cancel_action(&rp_id, &action_id)?;
    /// ```
    pub fn cancel_action(&self, rp_id: &[u8; 32], action_id: &[u8; 32]) -> StorageResult<()> {
        let action_scope = compute_action_scope(rp_id, action_id);

        // Load pending store
        let mut pending = load_pending_actions(
            &*self.blob_store,
            &*self.keystore,
            &self.state.account_id,
            &self.state.device_id,
        )?;

        // Remove entry if exists (no error if not found - idempotent)
        pending.remove(&action_scope);

        // Save pending store
        save_pending_actions(&pending, &*self.blob_store, &*self.keystore, &self.state.device_id)?;

        Ok(())
    }

    /// Gets the pending action entry for a specific scope.
    ///
    /// This is primarily for debugging and testing purposes.
    ///
    /// # Arguments
    ///
    /// * `rp_id` - The 32-byte relying party identifier
    /// * `action_id` - The 32-byte action identifier
    ///
    /// # Returns
    ///
    /// The pending action entry if one exists.
    pub fn get_pending_action(
        &self,
        rp_id: &[u8; 32],
        action_id: &[u8; 32],
    ) -> StorageResult<Option<PendingActionEntry>> {
        let action_scope = compute_action_scope(rp_id, action_id);

        let pending = load_pending_actions(
            &*self.blob_store,
            &*self.keystore,
            &self.state.account_id,
            &self.state.device_id,
        )?;

        Ok(pending.find_by_scope(&action_scope).cloned())
    }

    /// Lists all pending actions for this account.
    ///
    /// This is primarily for debugging and testing purposes.
    ///
    /// # Arguments
    ///
    /// * `prune_expired` - If true, removes expired entries before returning
    ///
    /// # Returns
    ///
    /// A vector of all pending action entries.
    pub fn list_pending_actions(&self, prune_expired: bool) -> StorageResult<Vec<PendingActionEntry>> {
        let mut pending = load_pending_actions(
            &*self.blob_store,
            &*self.keystore,
            &self.state.account_id,
            &self.state.device_id,
        )?;

        if prune_expired {
            let now = get_current_timestamp();
            pending.prune_expired(now);
            save_pending_actions(&pending, &*self.blob_store, &*self.keystore, &self.state.device_id)?;
        }

        Ok(pending.entries)
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

    // =========================================================================
    // Credential Operations Tests
    // =========================================================================

    #[test]
    fn test_put_and_get_credential() {
        let mut handle = create_test_handle();

        let cred_id = crate::credential_storage::CredentialId::generate();
        let cred_blob = b"test credential data";
        let assoc_data = b"associated metadata";

        // Put credential with associated data
        handle
            .put_credential(cred_id, 42, None, cred_blob, Some(assoc_data))
            .unwrap();

        // Get credential
        let (retrieved_cred, retrieved_assoc) = handle.get_credential(cred_id).unwrap();

        assert_eq!(retrieved_cred, cred_blob);
        assert_eq!(retrieved_assoc, Some(assoc_data.to_vec()));
    }

    #[test]
    fn test_put_credential_without_associated_data() {
        let mut handle = create_test_handle();

        let cred_id = crate::credential_storage::CredentialId::generate();
        let cred_blob = b"credential without assoc data";

        // Put credential without associated data
        handle.put_credential(cred_id, 1, None, cred_blob, None).unwrap();

        // Get credential
        let (retrieved_cred, retrieved_assoc) = handle.get_credential(cred_id).unwrap();

        assert_eq!(retrieved_cred, cred_blob);
        assert!(retrieved_assoc.is_none());
    }

    #[test]
    fn test_put_credential_update() {
        let mut handle = create_test_handle();

        let cred_id = crate::credential_storage::CredentialId::generate();
        let original_blob = b"original data";
        let updated_blob = b"updated data";

        // Put original credential
        handle.put_credential(cred_id, 1, None, original_blob, None).unwrap();

        // Verify original
        let (blob, _) = handle.get_credential(cred_id).unwrap();
        assert_eq!(blob, original_blob);

        // Update credential
        handle.put_credential(cred_id, 2, Some(9999), updated_blob, Some(b"new assoc")).unwrap();

        // Verify updated
        let (blob, assoc) = handle.get_credential(cred_id).unwrap();
        assert_eq!(blob, updated_blob);
        assert_eq!(assoc, Some(b"new assoc".to_vec()));

        // Verify record metadata was updated
        let record = handle.get_credential_record(cred_id).unwrap();
        assert_eq!(record.issuer_schema_id, 2);
        assert_eq!(record.expires_at, Some(9999));
        // Status should still be Active after update
        assert_eq!(record.status, crate::credential_storage::CredentialStatus::Active);
    }

    #[test]
    fn test_get_credential_not_found() {
        let handle = create_test_handle();

        let non_existent_id = crate::credential_storage::CredentialId::generate();
        let result = handle.get_credential(non_existent_id);

        assert!(matches!(
            result,
            Err(crate::credential_storage::StorageError::CredentialNotFound { .. })
        ));
    }

    #[test]
    fn test_list_credentials_empty() {
        let handle = create_test_handle();

        let creds = handle.list_credentials(None).unwrap();
        assert!(creds.is_empty());
    }

    #[test]
    fn test_list_credentials_all() {
        let mut handle = create_test_handle();

        // Add multiple credentials
        let cred1 = crate::credential_storage::CredentialId::generate();
        let cred2 = crate::credential_storage::CredentialId::generate();
        let cred3 = crate::credential_storage::CredentialId::generate();

        handle.put_credential(cred1, 1, None, b"cred1", None).unwrap();
        handle.put_credential(cred2, 2, None, b"cred2", None).unwrap();
        handle.put_credential(cred3, 1, None, b"cred3", None).unwrap();

        // List all (no filter)
        let all = handle.list_credentials(None).unwrap();
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn test_list_credentials_filter_by_schema() {
        let mut handle = create_test_handle();

        let cred1 = crate::credential_storage::CredentialId::generate();
        let cred2 = crate::credential_storage::CredentialId::generate();
        let cred3 = crate::credential_storage::CredentialId::generate();

        handle.put_credential(cred1, 1, None, b"cred1", None).unwrap();
        handle.put_credential(cred2, 2, None, b"cred2", None).unwrap();
        handle.put_credential(cred3, 1, None, b"cred3", None).unwrap();

        // Filter by schema ID 1
        let filter = crate::credential_storage::CredentialFilter::new()
            .with_issuer_schema_id(1);
        let filtered = handle.list_credentials(Some(filter)).unwrap();

        assert_eq!(filtered.len(), 2);
        assert!(filtered.iter().all(|r| r.issuer_schema_id == 1));
    }

    #[test]
    fn test_list_credentials_filter_by_status() {
        let mut handle = create_test_handle();

        let cred1 = crate::credential_storage::CredentialId::generate();
        let cred2 = crate::credential_storage::CredentialId::generate();

        handle.put_credential(cred1, 1, None, b"cred1", None).unwrap();
        handle.put_credential(cred2, 1, None, b"cred2", None).unwrap();

        // Retire cred2
        handle.retire_credential(cred2).unwrap();

        // Default filter (Active only)
        let active = handle.list_credentials(Some(crate::credential_storage::CredentialFilter::new())).unwrap();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].credential_id, cred1);

        // Filter for Retired
        let retired = handle.list_credentials(Some(
            crate::credential_storage::CredentialFilter::new()
                .with_status(crate::credential_storage::CredentialStatus::Retired)
        )).unwrap();
        assert_eq!(retired.len(), 1);
        assert_eq!(retired[0].credential_id, cred2);

        // Any status
        let all = handle.list_credentials(Some(
            crate::credential_storage::CredentialFilter::new().any_status()
        )).unwrap();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn test_list_credentials_filter_expired() {
        let mut handle = create_test_handle();

        let now = super::get_current_timestamp();

        let cred_valid = crate::credential_storage::CredentialId::generate();
        let cred_expired = crate::credential_storage::CredentialId::generate();

        // Valid credential (expires in future)
        handle.put_credential(cred_valid, 1, Some(now + 3600), b"valid", None).unwrap();
        // Expired credential
        handle.put_credential(cred_expired, 1, Some(now - 3600), b"expired", None).unwrap();

        // Default filter excludes expired
        let non_expired = handle.list_credentials(Some(crate::credential_storage::CredentialFilter::new())).unwrap();
        assert_eq!(non_expired.len(), 1);
        assert_eq!(non_expired[0].credential_id, cred_valid);

        // Include expired
        let with_expired = handle.list_credentials(Some(
            crate::credential_storage::CredentialFilter::new().include_expired()
        )).unwrap();
        assert_eq!(with_expired.len(), 2);
    }

    #[test]
    fn test_retire_credential() {
        let mut handle = create_test_handle();

        let cred_id = crate::credential_storage::CredentialId::generate();
        handle.put_credential(cred_id, 1, None, b"test", None).unwrap();

        // Verify initially active
        let record = handle.get_credential_record(cred_id).unwrap();
        assert_eq!(record.status, crate::credential_storage::CredentialStatus::Active);

        // Retire
        handle.retire_credential(cred_id).unwrap();

        // Verify retired
        let record = handle.get_credential_record(cred_id).unwrap();
        assert_eq!(record.status, crate::credential_storage::CredentialStatus::Retired);

        // Can still get the credential data
        let (blob, _) = handle.get_credential(cred_id).unwrap();
        assert_eq!(blob, b"test");
    }

    #[test]
    fn test_retire_credential_not_found() {
        let mut handle = create_test_handle();

        let non_existent = crate::credential_storage::CredentialId::generate();
        let result = handle.retire_credential(non_existent);

        assert!(matches!(
            result,
            Err(crate::credential_storage::StorageError::CredentialNotFound { .. })
        ));
    }

    #[test]
    fn test_get_credential_record() {
        let mut handle = create_test_handle();

        let now = super::get_current_timestamp();
        let cred_id = crate::credential_storage::CredentialId::generate();

        handle.put_credential(cred_id, 42, Some(now + 1000), b"data", None).unwrap();

        let record = handle.get_credential_record(cred_id).unwrap();

        assert_eq!(record.credential_id, cred_id);
        assert_eq!(record.issuer_schema_id, 42);
        assert_eq!(record.expires_at, Some(now + 1000));
        assert_eq!(record.status, crate::credential_storage::CredentialStatus::Active);
        assert!(record.created_at >= now);
        assert!(record.updated_at >= now);
    }

    #[test]
    fn test_get_credential_record_not_found() {
        let handle = create_test_handle();

        let non_existent = crate::credential_storage::CredentialId::generate();
        let result = handle.get_credential_record(non_existent);

        assert!(matches!(
            result,
            Err(crate::credential_storage::StorageError::CredentialNotFound { .. })
        ));
    }

    #[test]
    fn test_multiple_credentials_with_large_blobs() {
        let mut handle = create_test_handle();

        // Create credentials with various sizes
        let small_cred = crate::credential_storage::CredentialId::generate();
        let medium_cred = crate::credential_storage::CredentialId::generate();
        let large_cred = crate::credential_storage::CredentialId::generate();

        let small_data = vec![0xAA; 100];
        let medium_data = vec![0xBB; 10_000];
        let large_data = vec![0xCC; 100_000];

        handle.put_credential(small_cred, 1, None, &small_data, None).unwrap();
        handle.put_credential(medium_cred, 2, None, &medium_data, Some(&small_data)).unwrap();
        handle.put_credential(large_cred, 3, None, &large_data, Some(&medium_data)).unwrap();

        // Verify all can be read back
        let (s, _) = handle.get_credential(small_cred).unwrap();
        assert_eq!(s, small_data);

        let (m, ma) = handle.get_credential(medium_cred).unwrap();
        assert_eq!(m, medium_data);
        assert_eq!(ma, Some(small_data.clone()));

        let (l, la) = handle.get_credential(large_cred).unwrap();
        assert_eq!(l, large_data);
        assert_eq!(la, Some(medium_data));

        // List should show all 3
        let all = handle.list_credentials(None).unwrap();
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn test_credential_eligibility() {
        let mut handle = create_test_handle();

        let now = super::get_current_timestamp();

        // Active, non-expired
        let cred1 = crate::credential_storage::CredentialId::generate();
        handle.put_credential(cred1, 1, Some(now + 3600), b"1", None).unwrap();

        // Active, no expiration
        let cred2 = crate::credential_storage::CredentialId::generate();
        handle.put_credential(cred2, 1, None, b"2", None).unwrap();

        // Active, expired
        let cred3 = crate::credential_storage::CredentialId::generate();
        handle.put_credential(cred3, 1, Some(now - 3600), b"3", None).unwrap();

        let record1 = handle.get_credential_record(cred1).unwrap();
        let record2 = handle.get_credential_record(cred2).unwrap();
        let record3 = handle.get_credential_record(cred3).unwrap();

        assert!(record1.is_eligible(now));
        assert!(record2.is_eligible(now));
        assert!(!record3.is_eligible(now)); // expired

        // Retire cred1
        handle.retire_credential(cred1).unwrap();
        let record1 = handle.get_credential_record(cred1).unwrap();
        assert!(!record1.is_eligible(now)); // retired
    }

    #[test]
    fn test_credentials_persist_across_reopen() {
        // This test verifies credentials survive vault reopen
        let keystore = Arc::new(MemoryKeystore::new());
        let platform = Arc::new(SharedMemoryPlatformBundle::new());
        let lock_manager = Arc::new(MemoryLockManager::new());
        let store = WorldIdStore::new(Arc::clone(&keystore), Arc::clone(&platform), Arc::clone(&lock_manager));

        let cred_id = crate::credential_storage::CredentialId::generate();

        // Create account and add credential
        let account_id = {
            let mut handle = store.create_account().unwrap();
            handle.put_credential(cred_id, 99, None, b"persistent data", Some(b"persistent assoc")).unwrap();
            *handle.account_id()
        };

        // Re-open the account
        let handle = store.open_account(&account_id).unwrap();

        // Verify credential is still there
        let (blob, assoc) = handle.get_credential(cred_id).unwrap();
        assert_eq!(blob, b"persistent data");
        assert_eq!(assoc, Some(b"persistent assoc".to_vec()));

        let record = handle.get_credential_record(cred_id).unwrap();
        assert_eq!(record.issuer_schema_id, 99);
        assert_eq!(record.status, crate::credential_storage::CredentialStatus::Active);
    }

    // =========================================================================
    // Nullifier Protection Tests
    // =========================================================================

    mod onp_tests {
        use super::*;
        use crate::credential_storage::pending::{InMemoryOnpClient, StubOnpClient};

        #[test]
        fn test_begin_action_disclosure_basic() {
            let handle = create_test_handle();
            let onp = StubOnpClient::new();

            let rp_id = [0x11u8; 32];
            let action_id = [0x22u8; 32];
            let request = b"signed request bytes";
            let nullifier = [0x33u8; 32];
            let proof = b"proof package bytes";

            let result = handle
                .begin_action_disclosure(&rp_id, &action_id, request, &nullifier, proof, &onp)
                .unwrap();

            assert_eq!(result, proof);

            // Verify pending action was stored
            let pending = handle.get_pending_action(&rp_id, &action_id).unwrap();
            assert!(pending.is_some());
            let entry = pending.unwrap();
            assert_eq!(entry.nullifier, nullifier);
            assert_eq!(entry.proof_package, proof);
        }

        #[test]
        fn test_begin_action_disclosure_idempotent_replay() {
            let handle = create_test_handle();
            let onp = StubOnpClient::new();

            let rp_id = [0x11u8; 32];
            let action_id = [0x22u8; 32];
            let request = b"same request bytes";
            let nullifier = [0x33u8; 32];
            let proof = b"proof package";

            // First call
            let result1 = handle
                .begin_action_disclosure(&rp_id, &action_id, request, &nullifier, proof, &onp)
                .unwrap();

            // Second call with same parameters (idempotent replay)
            let result2 = handle
                .begin_action_disclosure(&rp_id, &action_id, request, &nullifier, proof, &onp)
                .unwrap();

            assert_eq!(result1, result2);
            assert_eq!(result2, proof);

            // Should still only have one pending action
            let pending = handle.list_pending_actions(false).unwrap();
            assert_eq!(pending.len(), 1);
        }

        #[test]
        fn test_begin_action_disclosure_different_request_fails() {
            let handle = create_test_handle();
            let onp = StubOnpClient::new();

            let rp_id = [0x11u8; 32];
            let action_id = [0x22u8; 32];
            let request1 = b"first request";
            let request2 = b"different request";
            let nullifier = [0x33u8; 32];
            let proof = b"proof";

            // First call succeeds
            handle
                .begin_action_disclosure(&rp_id, &action_id, request1, &nullifier, proof, &onp)
                .unwrap();

            // Second call with different request should fail
            let result = handle.begin_action_disclosure(
                &rp_id,
                &action_id,
                request2,
                &nullifier,
                proof,
                &onp,
            );

            assert!(matches!(
                result,
                Err(crate::credential_storage::StorageError::ActionAlreadyPending { .. })
            ));
        }

        #[test]
        fn test_begin_action_disclosure_nullifier_consumed() {
            let handle = create_test_handle();
            let onp = InMemoryOnpClient::new();

            let rp_id = [0x11u8; 32];
            let action_id = [0x22u8; 32];
            let request = b"request";
            let nullifier = [0x33u8; 32];
            let proof = b"proof";

            // Pre-mark nullifier as consumed
            onp.mark_consumed(&nullifier).unwrap();

            // Should fail because nullifier is already consumed
            let result = handle.begin_action_disclosure(
                &rp_id,
                &action_id,
                request,
                &nullifier,
                proof,
                &onp,
            );

            assert!(matches!(
                result,
                Err(crate::credential_storage::StorageError::NullifierAlreadyConsumed)
            ));
        }

        #[test]
        fn test_commit_action_basic() {
            let handle = create_test_handle();
            let onp = InMemoryOnpClient::new();

            let rp_id = [0x11u8; 32];
            let action_id = [0x22u8; 32];
            let request = b"request";
            let nullifier = [0x33u8; 32];
            let proof = b"proof";

            // Begin disclosure
            handle
                .begin_action_disclosure(&rp_id, &action_id, request, &nullifier, proof, &onp)
                .unwrap();

            // Verify nullifier is NOT consumed yet
            assert!(!onp.check_consumed(&nullifier).unwrap());

            // Commit action
            handle.commit_action(&rp_id, &action_id, &onp).unwrap();

            // Verify nullifier IS now consumed
            assert!(onp.check_consumed(&nullifier).unwrap());

            // Verify pending action was removed
            let pending = handle.get_pending_action(&rp_id, &action_id).unwrap();
            assert!(pending.is_none());
        }

        #[test]
        fn test_commit_action_not_found() {
            let handle = create_test_handle();
            let onp = StubOnpClient::new();

            let rp_id = [0x11u8; 32];
            let action_id = [0x22u8; 32];

            // Try to commit without begin
            let result = handle.commit_action(&rp_id, &action_id, &onp);

            assert!(matches!(
                result,
                Err(crate::credential_storage::StorageError::PendingActionNotFound { .. })
            ));
        }

        #[test]
        fn test_cancel_action_basic() {
            let handle = create_test_handle();
            let onp = InMemoryOnpClient::new();

            let rp_id = [0x11u8; 32];
            let action_id = [0x22u8; 32];
            let request = b"request";
            let nullifier = [0x33u8; 32];
            let proof = b"proof";

            // Begin disclosure
            handle
                .begin_action_disclosure(&rp_id, &action_id, request, &nullifier, proof, &onp)
                .unwrap();

            // Cancel action
            handle.cancel_action(&rp_id, &action_id).unwrap();

            // Verify pending action was removed
            let pending = handle.get_pending_action(&rp_id, &action_id).unwrap();
            assert!(pending.is_none());

            // Verify nullifier was NOT consumed
            assert!(!onp.check_consumed(&nullifier).unwrap());
        }

        #[test]
        fn test_cancel_action_idempotent() {
            let handle = create_test_handle();

            let rp_id = [0x11u8; 32];
            let action_id = [0x22u8; 32];

            // Cancel without any pending action (should not error)
            handle.cancel_action(&rp_id, &action_id).unwrap();

            // Cancel again (still should not error)
            handle.cancel_action(&rp_id, &action_id).unwrap();
        }

        #[test]
        fn test_cancel_allows_reuse() {
            let handle = create_test_handle();
            let onp = InMemoryOnpClient::new();

            let rp_id = [0x11u8; 32];
            let action_id = [0x22u8; 32];
            let request1 = b"request 1";
            let request2 = b"request 2";
            let nullifier = [0x33u8; 32];
            let proof1 = b"proof 1";
            let proof2 = b"proof 2";

            // Begin first disclosure
            handle
                .begin_action_disclosure(&rp_id, &action_id, request1, &nullifier, proof1, &onp)
                .unwrap();

            // Cancel
            handle.cancel_action(&rp_id, &action_id).unwrap();

            // Begin new disclosure with different request (should succeed)
            let result = handle
                .begin_action_disclosure(&rp_id, &action_id, request2, &nullifier, proof2, &onp)
                .unwrap();

            assert_eq!(result, proof2);
        }

        #[test]
        fn test_full_disclosure_flow() {
            let handle = create_test_handle();
            let onp = InMemoryOnpClient::new();

            let rp_id = [0xAAu8; 32];
            let action_id = [0xBBu8; 32];
            let request = b"full flow request";
            let nullifier = [0xCCu8; 32];
            let proof = b"full flow proof package";

            // 1. Begin disclosure
            let returned_proof = handle
                .begin_action_disclosure(&rp_id, &action_id, request, &nullifier, proof, &onp)
                .unwrap();
            assert_eq!(returned_proof, proof);

            // 2. Verify pending
            let pending = handle.get_pending_action(&rp_id, &action_id).unwrap();
            assert!(pending.is_some());

            // 3. Commit (simulating RP verification success)
            handle.commit_action(&rp_id, &action_id, &onp).unwrap();

            // 4. Verify nullifier consumed
            assert!(onp.check_consumed(&nullifier).unwrap());

            // 5. Verify no pending action
            assert!(handle.get_pending_action(&rp_id, &action_id).unwrap().is_none());

            // 6. Try to use same nullifier again - should fail
            let result = handle.begin_action_disclosure(
                &rp_id,
                &[0xDDu8; 32], // different action
                b"new request",
                &nullifier, // same nullifier
                b"new proof",
                &onp,
            );
            assert!(matches!(
                result,
                Err(crate::credential_storage::StorageError::NullifierAlreadyConsumed)
            ));
        }

        #[test]
        fn test_multiple_concurrent_actions() {
            let handle = create_test_handle();
            let onp = StubOnpClient::new();

            // Start multiple actions for different RP/action pairs
            for i in 0..5u8 {
                let rp_id = [i; 32];
                let action_id = [i + 100; 32];
                let request = format!("request {i}");
                let nullifier = [i + 200; 32];
                let proof = format!("proof {i}");

                handle
                    .begin_action_disclosure(
                        &rp_id,
                        &action_id,
                        request.as_bytes(),
                        &nullifier,
                        proof.as_bytes(),
                        &onp,
                    )
                    .unwrap();
            }

            // List all pending
            let pending = handle.list_pending_actions(false).unwrap();
            assert_eq!(pending.len(), 5);
        }

        #[test]
        fn test_list_pending_actions_prune() {
            let handle = create_test_handle();
            let onp = StubOnpClient::new();

            let rp_id = [0x11u8; 32];
            let action_id = [0x22u8; 32];
            let request = b"request";
            let nullifier = [0x33u8; 32];
            let proof = b"proof";

            // Begin disclosure
            handle
                .begin_action_disclosure(&rp_id, &action_id, request, &nullifier, proof, &onp)
                .unwrap();

            // List without pruning
            let pending = handle.list_pending_actions(false).unwrap();
            assert_eq!(pending.len(), 1);

            // List with pruning (entry not expired yet, so still there)
            let pending = handle.list_pending_actions(true).unwrap();
            assert_eq!(pending.len(), 1);
        }

        #[test]
        fn test_different_actions_same_nullifier() {
            // Two different RP/action combinations can't use the same nullifier
            // (once one commits)
            let handle = create_test_handle();
            let onp = InMemoryOnpClient::new();

            let rp1 = [0x11u8; 32];
            let action1 = [0x22u8; 32];
            let rp2 = [0x33u8; 32];
            let action2 = [0x44u8; 32];
            let nullifier = [0x55u8; 32]; // Same nullifier

            // First action begins and commits
            handle
                .begin_action_disclosure(&rp1, &action1, b"req1", &nullifier, b"proof1", &onp)
                .unwrap();
            handle.commit_action(&rp1, &action1, &onp).unwrap();

            // Second action tries to use same nullifier - should fail
            let result =
                handle.begin_action_disclosure(&rp2, &action2, b"req2", &nullifier, b"proof2", &onp);

            assert!(matches!(
                result,
                Err(crate::credential_storage::StorageError::NullifierAlreadyConsumed)
            ));
        }

        #[test]
        fn test_pending_actions_persist_across_reopen() {
            let keystore = Arc::new(MemoryKeystore::new());
            let platform = Arc::new(SharedMemoryPlatformBundle::new());
            let lock_manager = Arc::new(MemoryLockManager::new());
            let store = WorldIdStore::new(
                Arc::clone(&keystore),
                Arc::clone(&platform),
                Arc::clone(&lock_manager),
            );
            let onp = StubOnpClient::new();

            let rp_id = [0x11u8; 32];
            let action_id = [0x22u8; 32];
            let request = b"persistent request";
            let nullifier = [0x33u8; 32];
            let proof = b"persistent proof";

            // Create account and begin disclosure
            let account_id = {
                let handle = store.create_account().unwrap();
                handle
                    .begin_action_disclosure(&rp_id, &action_id, request, &nullifier, proof, &onp)
                    .unwrap();
                *handle.account_id()
            };

            // Re-open account
            let handle = store.open_account(&account_id).unwrap();

            // Verify pending action still exists
            let pending = handle.get_pending_action(&rp_id, &action_id).unwrap();
            assert!(pending.is_some());
            let entry = pending.unwrap();
            assert_eq!(entry.nullifier, nullifier);
            assert_eq!(entry.proof_package, proof);

            // Can still commit
            handle.commit_action(&rp_id, &action_id, &onp).unwrap();

            // Now it's gone
            let pending = handle.get_pending_action(&rp_id, &action_id).unwrap();
            assert!(pending.is_none());
        }
    }
}
