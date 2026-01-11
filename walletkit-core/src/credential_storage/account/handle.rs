//! `AccountHandle` implementation for account operations.
//!
//! The handle provides access to account state, key derivation, and
//! credential operations.

use std::sync::Arc;

use crate::credential_storage::{
    pending::{load_pending_actions, save_pending_actions, OnpClient},
    platform::{AccountLockManager, AtomicBlobStore, DeviceKeystore, VaultFileStore},
    vault::VaultFile,
    AccountId, AccountState, BlobKind, CredentialFilter, CredentialId,
    CredentialRecord, CredentialStatus, PendingActionEntry, StorageError,
    StorageResult,
};

use super::{
    derivation::{
        compute_action_scope, compute_request_id, derive_issuer_blind, derive_session_r,
    },
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
            let (cred_cid, cred_ptr) =
                txn.put_blob(BlobKind::CredentialBlob, credential_blob)?;
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
        let cred_ptr =
            index
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
    pub fn retire_credential(
        &mut self,
        credential_id: CredentialId,
    ) -> StorageResult<()> {
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
        save_pending_actions(
            &pending,
            &*self.blob_store,
            &*self.keystore,
            &self.state.device_id,
        )?;

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
        let entry = pending
            .remove(&action_scope)
            .ok_or(StorageError::PendingActionNotFound { action_scope })?;

        // Mark nullifier as consumed in ONP
        onp.mark_consumed(&entry.nullifier)?;

        // Save pending store (with entry removed)
        save_pending_actions(
            &pending,
            &*self.blob_store,
            &*self.keystore,
            &self.state.device_id,
        )?;

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
    pub fn cancel_action(
        &self,
        rp_id: &[u8; 32],
        action_id: &[u8; 32],
    ) -> StorageResult<()> {
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
        save_pending_actions(
            &pending,
            &*self.blob_store,
            &*self.keystore,
            &self.state.device_id,
        )?;

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
    pub fn list_pending_actions(
        &self,
        prune_expired: bool,
    ) -> StorageResult<Vec<PendingActionEntry>> {
        let mut pending = load_pending_actions(
            &*self.blob_store,
            &*self.keystore,
            &self.state.account_id,
            &self.state.device_id,
        )?;

        if prune_expired {
            let now = get_current_timestamp();
            pending.prune_expired(now);
            save_pending_actions(
                &pending,
                &*self.blob_store,
                &*self.keystore,
                &self.state.device_id,
            )?;
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
        self.lock_manager
            .with_account_lock(&self.state.account_id, f)
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
        platform::memory::{
            MemoryBlobStore, MemoryKeystore, MemoryLockManager, MemoryVaultStore,
        },
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

        fn get_or_create_blob_store(
            &self,
            account_id: &AccountId,
        ) -> Arc<MemoryBlobStore> {
            let mut stores = self.blob_stores.write().unwrap();
            stores
                .entry(*account_id)
                .or_insert_with(|| Arc::new(MemoryBlobStore::new()))
                .clone()
        }

        fn get_or_create_vault_store(
            &self,
            account_id: &AccountId,
        ) -> Arc<MemoryVaultStore> {
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

        fn create_account_directory(
            &self,
            account_id: &AccountId,
        ) -> StorageResult<()> {
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

    fn create_test_handle() -> AccountHandle<
        MemoryKeystore,
        SharedBlobStore,
        SharedVaultStore,
        MemoryLockManager,
    > {
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
    fn test_account_creation() {
        let handle = create_test_handle();
        assert_eq!(handle.account_id().as_bytes().len(), 32);
        assert_eq!(handle.device_id().len(), 16);
    }

    #[test]
    fn test_leaf_index_cache() {
        let mut handle = create_test_handle();
        assert_eq!(handle.get_leaf_index_cache().unwrap(), None);
        handle.set_leaf_index_cache(42).unwrap();
        assert_eq!(handle.get_leaf_index_cache().unwrap(), Some(42));
        handle.clear_leaf_index_cache().unwrap();
        assert_eq!(handle.get_leaf_index_cache().unwrap(), None);
    }

    #[test]
    fn test_derivation() {
        let handle = create_test_handle();
        let blind1 = handle.derive_issuer_blind(1);
        let blind2 = handle.derive_issuer_blind(1);
        assert_eq!(blind1, blind2);
        let blind3 = handle.derive_issuer_blind(2);
        assert_ne!(blind1, blind3);
        let rp_id = [0x11u8; 32];
        let action_id = [0x22u8; 32];
        let r1 = handle.derive_session_r(&rp_id, &action_id);
        let r2 = handle.derive_session_r(&rp_id, &action_id);
        assert_eq!(r1, r2);
    }

    #[test]
    fn test_vault_access() {
        let mut handle = create_test_handle();
        let index = handle.vault().read_index().unwrap();
        assert_eq!(index.account_id, *handle.account_id());
        handle.vault_mut().with_txn(|_txn| Ok(())).unwrap();
        let index = handle.vault().read_index().unwrap();
        assert!(index.sequence > 0);
    }

    #[test]
    fn test_credential_crud() {
        let mut handle = create_test_handle();
        let cred_id = crate::credential_storage::CredentialId::generate();
        handle.put_credential(cred_id, 42, None, b"data", Some(b"assoc")).unwrap();
        let (blob, assoc) = handle.get_credential(cred_id).unwrap();
        assert_eq!(blob, b"data");
        assert_eq!(assoc, Some(b"assoc".to_vec()));
        handle.put_credential(cred_id, 99, Some(1000), b"updated", None).unwrap();
        let (blob, _) = handle.get_credential(cred_id).unwrap();
        assert_eq!(blob, b"updated");
    }

    #[test]
    fn test_list_and_filter_credentials() {
        let mut handle = create_test_handle();
        let cred1 = crate::credential_storage::CredentialId::generate();
        let cred2 = crate::credential_storage::CredentialId::generate();
        handle.put_credential(cred1, 1, None, b"c1", None).unwrap();
        handle.put_credential(cred2, 2, None, b"c2", None).unwrap();
        let all = handle.list_credentials(None).unwrap();
        assert_eq!(all.len(), 2);
        let filter = crate::credential_storage::CredentialFilter::new().with_issuer_schema_id(1);
        let filtered = handle.list_credentials(Some(filter)).unwrap();
        assert_eq!(filtered.len(), 1);
    }

    #[test]
    fn test_retire_credential() {
        let mut handle = create_test_handle();
        let cred_id = crate::credential_storage::CredentialId::generate();
        handle.put_credential(cred_id, 1, None, b"test", None).unwrap();
        let record = handle.get_credential_record(cred_id).unwrap();
        assert_eq!(record.status, crate::credential_storage::CredentialStatus::Active);
        handle.retire_credential(cred_id).unwrap();
        let record = handle.get_credential_record(cred_id).unwrap();
        assert_eq!(record.status, crate::credential_storage::CredentialStatus::Retired);
    }

    #[test]
    fn test_onp_flow() {
        use crate::credential_storage::pending::InMemoryOnpClient;
        let handle = create_test_handle();
        let onp = InMemoryOnpClient::new();
        let rp_id = [0x11u8; 32];
        let action_id = [0x22u8; 32];
        let nullifier = [0x33u8; 32];
        handle.begin_action_disclosure(&rp_id, &action_id, b"req", &nullifier, b"proof", &onp).unwrap();
        assert!(!onp.check_consumed(&nullifier).unwrap());
        handle.commit_action(&rp_id, &action_id, &onp).unwrap();
        assert!(onp.check_consumed(&nullifier).unwrap());
        let pending = handle.get_pending_action(&rp_id, &action_id).unwrap();
        assert!(pending.is_none());
    }

    #[test]
    fn test_with_lock() {
        let handle = create_test_handle();
        let result = handle.with_lock(|| Ok(42)).unwrap();
        assert_eq!(result, 42);
    }
}
