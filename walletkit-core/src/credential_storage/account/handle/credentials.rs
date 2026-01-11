//! Credential CRUD operations for `AccountHandle`.

use crate::credential_storage::{
    platform::{AccountLockManager, AtomicBlobStore, DeviceKeystore, VaultFileStore},
    BlobKind, CredentialFilter, CredentialId, CredentialRecord, CredentialStatus, StorageError,
    StorageResult,
};

use super::{get_current_timestamp, AccountHandle};

impl<K, B, V, L> AccountHandle<K, B, V, L>
where
    K: DeviceKeystore + 'static,
    B: AtomicBlobStore + 'static,
    V: VaultFileStore + 'static,
    L: AccountLockManager + 'static,
{
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
}
