//! Nullifier protection (ONP integration) for `AccountHandle`.

use crate::credential_storage::{
    pending::{load_pending_actions, save_pending_actions, OnpClient},
    platform::{AccountLockManager, AtomicBlobStore, DeviceKeystore, VaultFileStore},
    PendingActionEntry, StorageError, StorageResult,
};

use super::{get_current_timestamp, AccountHandle};
use crate::credential_storage::account::derivation::{compute_action_scope, compute_request_id};

impl<K, B, V, L> AccountHandle<K, B, V, L>
where
    K: DeviceKeystore + 'static,
    B: AtomicBlobStore + 'static,
    V: VaultFileStore + 'static,
    L: AccountLockManager + 'static,
{
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
        let entry = pending
            .remove(&action_scope)
            .ok_or(StorageError::PendingActionNotFound { action_scope })?;

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
}
