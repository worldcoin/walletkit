//! Sync operations for `AccountHandle`.
//!
//! This module provides credential transfer and provisioning operations
//! for device-to-device synchronization.

use crate::credential_storage::{
    platform::{AccountLockManager, AtomicBlobStore, DeviceKeystore, VaultFileStore},
    transfer::{apply_import, decide_import, ImportDecision, TransferPayload},
    BlobKind, CredentialId, CredentialRecord, CredentialStatus, CredentialTransferBytes,
    ImportOutcome, StorageError, StorageResult, VaultProvisioningEnvelope,
};

use super::AccountHandle;

impl<K, B, V, L> AccountHandle<K, B, V, L>
where
    K: DeviceKeystore + 'static,
    B: AtomicBlobStore + 'static,
    V: VaultFileStore + 'static,
    L: AccountLockManager + 'static,
{
    // =========================================================================
    // Credential Export
    // =========================================================================

    /// Exports a credential for transfer to another device.
    ///
    /// Creates encrypted transfer bytes containing the credential record
    /// and its blob data, suitable for syncing via an untrusted backend.
    ///
    /// # Arguments
    ///
    /// * `credential_id` - The credential to export
    ///
    /// # Returns
    ///
    /// Encrypted `CredentialTransferBytes` that can be safely stored on
    /// an untrusted backend and imported on another device.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The credential is not found
    /// - The credential is retired (use `export_credential_tombstone` instead)
    /// - Reading blobs from the vault fails
    /// - Encryption fails
    ///
    /// # Example
    ///
    /// ```ignore
    /// // Export a credential
    /// let transfer = handle.export_credential(cred_id)?;
    ///
    /// // Upload to sync backend
    /// backend.upload(transfer.as_bytes());
    ///
    /// // On another device, download and import
    /// let transfer = CredentialTransferBytes::new(downloaded_bytes);
    /// other_handle.import_credential(&transfer)?;
    /// ```
    pub fn export_credential(
        &self,
        credential_id: CredentialId,
    ) -> StorageResult<CredentialTransferBytes> {
        // Get the credential record
        let record = self.get_credential_record(credential_id)?;

        // For active credentials, include the blobs
        if record.status == CredentialStatus::Retired {
            return Err(StorageError::invalid_input(
                "credential_id",
                "Credential is retired; use export_credential_tombstone instead".to_string(),
            ));
        }

        // Get the blob data
        let (cred_blob, assoc_data) = self.get_credential(credential_id)?;

        // Export
        CredentialTransferBytes::export(
            self.vault.vault_key(),
            self.account_id(),
            &record,
            Some(&cred_blob),
            assoc_data.as_deref(),
        )
    }

    /// Exports a tombstone (retired credential) for transfer.
    ///
    /// Tombstones propagate retirement status to other devices without
    /// including credential blob data. This is used to sync the retirement
    /// of a credential across devices.
    ///
    /// # Arguments
    ///
    /// * `credential_id` - The retired credential to export as tombstone
    ///
    /// # Returns
    ///
    /// Encrypted `CredentialTransferBytes` containing only the record metadata
    /// (no blob data).
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The credential is not found
    /// - Encryption fails
    ///
    /// # Note
    ///
    /// Unlike `export_credential`, this method works for both active and
    /// retired credentials. When exporting an active credential as a tombstone,
    /// no blob data is included.
    pub fn export_credential_tombstone(
        &self,
        credential_id: CredentialId,
    ) -> StorageResult<CredentialTransferBytes> {
        // Get the credential record
        let record = self.get_credential_record(credential_id)?;

        // Export without blobs (tombstone)
        CredentialTransferBytes::export(
            self.vault.vault_key(),
            self.account_id(),
            &record,
            None, // No credential blob for tombstone
            None, // No associated data for tombstone
        )
    }

    // =========================================================================
    // Credential Import
    // =========================================================================

    /// Imports a credential from transfer bytes.
    ///
    /// Import is idempotent and uses timestamp-based conflict resolution:
    /// - If `incoming.updated_at > existing.updated_at`: apply the import
    /// - If `incoming.updated_at <= existing.updated_at`: return `NoOp`
    ///
    /// For tombstones (retired credentials), only the status is updated;
    /// no blob data is included.
    ///
    /// # Arguments
    ///
    /// * `transfer` - The encrypted transfer bytes from another device
    ///
    /// # Returns
    ///
    /// - `Applied` if the credential was imported or updated
    /// - `NoOp` if the existing credential is newer or equal
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Decryption fails
    /// - The account ID doesn't match
    /// - The transfer format is invalid
    /// - Writing to the vault fails
    ///
    /// # Example
    ///
    /// ```ignore
    /// // Download from sync backend
    /// let transfer = CredentialTransferBytes::new(downloaded_bytes);
    ///
    /// // Import - idempotent, safe to retry
    /// match handle.import_credential(&transfer)? {
    ///     ImportOutcome::Applied => println!("Credential imported"),
    ///     ImportOutcome::NoOp => println!("Already up to date"),
    /// }
    /// ```
    pub fn import_credential(
        &mut self,
        transfer: &CredentialTransferBytes,
    ) -> StorageResult<ImportOutcome> {
        // Decrypt and validate
        let payload = transfer.decrypt(self.vault.vault_key(), self.account_id())?;

        // Check if we should apply the import
        let existing = self.get_credential_record_optional(payload.record.credential_id)?;
        let decision = decide_import(&payload, existing.as_ref());

        if decision == ImportDecision::Skip {
            return Ok(ImportOutcome::NoOp);
        }

        // Apply the import
        self.apply_credential_import(payload)
    }

    /// Internal helper to get a credential record, returning None if not found.
    fn get_credential_record_optional(
        &self,
        credential_id: CredentialId,
    ) -> StorageResult<Option<CredentialRecord>> {
        let index = self.vault.read_index()?;
        Ok(index.find_credential(&credential_id).cloned())
    }

    /// Internal helper to apply a credential import.
    fn apply_credential_import(
        &mut self,
        payload: TransferPayload,
    ) -> StorageResult<ImportOutcome> {
        let (record, credential_blob, associated_data) = apply_import(payload);

        self.vault.with_txn(|txn| {
            let mut index = txn.load_index()?;

            // For active imports (with blobs), store the blobs
            let (cred_cid, assoc_cid) = if let Some(blob) = credential_blob.as_ref() {
                // Store credential blob
                let (cid, ptr) = txn.put_blob(BlobKind::CredentialBlob, blob)?;
                index.blobs.push(ptr);

                // Store associated data if present
                let assoc = if let Some(data) = associated_data.as_ref() {
                    let (cid, ptr) = txn.put_blob(BlobKind::AssociatedData, data)?;
                    index.blobs.push(ptr);
                    Some(cid)
                } else {
                    None
                };

                (cid, assoc)
            } else {
                // Tombstone - use the existing CIDs from the record
                // These won't be used since the credential is retired
                (record.credential_blob_cid, record.associated_data_cid)
            };

            // Build the final record with correct CIDs
            let final_record = CredentialRecord {
                credential_id: record.credential_id,
                issuer_schema_id: record.issuer_schema_id,
                created_at: record.created_at,
                updated_at: record.updated_at,
                expires_at: record.expires_at,
                credential_blob_cid: cred_cid,
                associated_data_cid: assoc_cid,
                status: record.status,
            };

            // Upsert the record
            if let Some(existing) = index.find_credential_mut(&final_record.credential_id) {
                *existing = final_record;
            } else {
                index.records.push(final_record);
            }

            txn.set_index(index);
            Ok(ImportOutcome::Applied)
        })
    }

    // =========================================================================
    // Vault Provisioning
    // =========================================================================

    /// Exports a provisioning envelope for adding a new device.
    ///
    /// The envelope contains the vault key and blinding seeds encrypted
    /// to the recipient's device public key. This allows a new device to
    /// join the account and access the vault.
    ///
    /// # Arguments
    ///
    /// * `recipient_device_pubkey` - The recipient's X25519 public key (32 bytes)
    ///
    /// # Returns
    ///
    /// An encrypted `VaultProvisioningEnvelope` that only the recipient can decrypt.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The recipient public key is not 32 bytes
    /// - Encryption fails
    ///
    /// # Security
    ///
    /// The envelope should only be transmitted over a secure channel or
    /// after verifying the recipient's identity out-of-band. Anyone with
    /// the envelope and the matching private key gains full access to the vault.
    ///
    /// # Example
    ///
    /// ```ignore
    /// // Get recipient's public key (e.g., via QR code)
    /// let recipient_pubkey = receive_pubkey_from_new_device();
    ///
    /// // Create provisioning envelope
    /// let envelope = handle.export_vault_provisioning_envelope(&recipient_pubkey)?;
    ///
    /// // Send to new device (securely!)
    /// send_envelope_to_new_device(&envelope);
    ///
    /// // On new device, import the envelope
    /// let handle = store.import_vault_provisioning_envelope(&envelope, &device_secret)?;
    /// ```
    pub fn export_vault_provisioning_envelope(
        &self,
        recipient_device_pubkey: &[u8],
    ) -> StorageResult<VaultProvisioningEnvelope> {
        VaultProvisioningEnvelope::export(
            self.vault.vault_key(),
            self.issuer_blind_seed(),
            self.session_blind_seed(),
            recipient_device_pubkey,
        )
    }

    // =========================================================================
    // Bulk Export
    // =========================================================================

    /// Exports all active credentials for transfer.
    ///
    /// This is useful for initial sync when adding a new device.
    ///
    /// # Returns
    ///
    /// A vector of `CredentialTransferBytes` for all active credentials.
    ///
    /// # Errors
    ///
    /// Returns an error if reading or exporting any credential fails.
    pub fn export_all_credentials(&self) -> StorageResult<Vec<CredentialTransferBytes>> {
        let credentials = self.list_credentials(None)?;
        let mut transfers = Vec::with_capacity(credentials.len());

        for record in credentials {
            let transfer = if record.status == CredentialStatus::Active {
                self.export_credential(record.credential_id)?
            } else {
                self.export_credential_tombstone(record.credential_id)?
            };
            transfers.push(transfer);
        }

        Ok(transfers)
    }

    /// Imports multiple credentials from transfer bytes.
    ///
    /// This is useful for batch sync operations. Each credential is
    /// imported independently with its own conflict resolution.
    ///
    /// # Arguments
    ///
    /// * `transfers` - Slice of transfer bytes to import
    ///
    /// # Returns
    ///
    /// A vector of `ImportOutcome`s, one for each input transfer.
    ///
    /// # Errors
    ///
    /// Stops and returns an error if any import fails. Successfully
    /// imported credentials up to that point are committed.
    pub fn import_credentials(
        &mut self,
        transfers: &[CredentialTransferBytes],
    ) -> StorageResult<Vec<ImportOutcome>> {
        let mut outcomes = Vec::with_capacity(transfers.len());

        for transfer in transfers {
            let outcome = self.import_credential(transfer)?;
            outcomes.push(outcome);
        }

        Ok(outcomes)
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    // Tests are in the main tests.rs file for the handle module
    // to have access to the test infrastructure (SharedMemoryPlatformBundle, etc.)
}
