//! Vault transaction implementation.
//!
//! This module provides the transaction API for making atomic changes
//! to the vault file.

// Binary format code uses small constant casts that are safe
#![allow(clippy::cast_possible_truncation)]
// Identifiers like content_id appear in docs without backticks for readability
#![allow(clippy::doc_markdown)]

use crate::credential_storage::{
    platform::VaultFileStore, BlobKind, BlobPointer, ContentId, CredentialRecord, StorageError,
    VaultIndex,
};

use super::{
    crypto::{encrypt_blob, encrypt_index, hash_record_body},
    file::{get_current_timestamp, new_txn_id, serialize_vault_index, VaultFile},
    header::Superblock,
    records::{EncryptedBlobObject, EncryptedIndexSnapshot, TxnBegin, TxnCommit},
};


/// An in-progress vault transaction.
///
/// Transactions buffer writes and only publish changes atomically via
/// a superblock update when committed. If the transaction is dropped
/// without committing, no changes are made.
///
/// # Crash Safety
///
/// - If the process crashes before `commit()` completes the superblock write,
///   the transaction is ignored on next open.
/// - If the process crashes after the superblock write completes, the vault
///   opens at the committed transaction.
///
/// # Example
///
/// ```ignore
/// vault.with_txn(|txn| {
///     // Load current index
///     let mut index = txn.load_index()?;
///     
///     // Add a blob
///     let (content_id, ptr) = txn.put_blob(BlobKind::CredentialBlob, b"data")?;
///     
///     // Update index
///     index.blobs.push(ptr);
///     txn.set_index(index);
///     
///     // Commit atomically publishes changes
///     txn.commit()
/// })?;
/// ```
pub struct VaultTxn<'a, V: VaultFileStore> {
    /// Reference to the vault file.
    vault: &'a mut VaultFile<V>,
    /// Random transaction ID.
    txn_id: [u8; 16],
    /// Timestamp when transaction started.
    started_at: u64,
    /// Blobs written in this transaction (content_id, pointer).
    pending_blobs: Vec<(ContentId, BlobPointer)>,
    /// Modified index to be committed.
    pending_index: Option<VaultIndex>,
    /// Whether this transaction has been committed.
    committed: bool,
}

impl<'a, V: VaultFileStore> VaultTxn<'a, V> {
    /// Begins a new transaction.
    ///
    /// Writes a `TxnBegin` record to the data region.
    ///
    /// # Errors
    ///
    /// Returns an error if writing the TxnBegin record fails.
    pub(super) fn begin(vault: &'a mut VaultFile<V>) -> Result<Self, StorageError> {
        let txn_id = new_txn_id();
        let started_at = get_current_timestamp();

        // Write TxnBegin record
        let txn_begin = TxnBegin::new(txn_id, started_at);
        let envelope = txn_begin.to_envelope();
        let record_bytes = envelope.encode();

        // Append TxnBegin record (offset stored implicitly in the file)
        vault.store().append(&record_bytes)?;

        Ok(Self {
            vault,
            txn_id,
            started_at,
            pending_blobs: Vec::new(),
            pending_index: None,
            committed: false,
        })
    }

    /// Loads the current index for modification.
    ///
    /// If the index has already been loaded in this transaction, returns
    /// the pending version. Otherwise reads from the vault.
    ///
    /// # Errors
    ///
    /// Returns an error if reading the index fails.
    pub fn load_index(&mut self) -> Result<VaultIndex, StorageError> {
        if let Some(ref index) = self.pending_index {
            Ok(index.clone())
        } else {
            let index = self.vault.read_index()?;
            Ok(index)
        }
    }

    /// Sets the index to be committed.
    ///
    /// The index is not written until `commit()` is called.
    pub fn set_index(&mut self, index: VaultIndex) {
        self.pending_index = Some(index);
    }

    /// Encrypts and appends a blob to the vault.
    ///
    /// The blob is immediately written to the file but is not reachable
    /// until the transaction is committed.
    ///
    /// # Arguments
    ///
    /// * `kind` - Classification of the blob
    /// * `plaintext` - The data to store
    ///
    /// # Returns
    ///
    /// A tuple of (content_id, blob_pointer). The blob pointer can be used
    /// to reference this blob in credential records.
    ///
    /// # Errors
    ///
    /// Returns an error if encryption or writing fails.
    pub fn put_blob(
        &mut self,
        kind: BlobKind,
        plaintext: &[u8],
    ) -> Result<(ContentId, BlobPointer), StorageError> {
        // Encrypt the blob
        let (content_id, ciphertext, nonce) =
            encrypt_blob(self.vault.vault_key(), self.vault.account_id(), kind, plaintext)?;

        // Create blob object record
        let blob_obj = EncryptedBlobObject::new(content_id, kind, nonce, ciphertext);
        let envelope = blob_obj.to_envelope();
        let record_bytes = envelope.encode();

        // Append to file
        let offset = self.vault.store().append(&record_bytes)?;
        let length = record_bytes.len() as u32;

        // Create pointer
        let ptr = BlobPointer::new(content_id, offset, length, kind);

        // Track this blob
        self.pending_blobs.push((content_id, ptr.clone()));

        Ok((content_id, ptr))
    }

    /// Upserts a credential record in the pending index.
    ///
    /// If a record with the same credential_id exists, it is replaced.
    /// Otherwise, the record is added.
    ///
    /// # Errors
    ///
    /// Returns an error if the index hasn't been loaded.
    pub fn upsert_record(&mut self, record: CredentialRecord) -> Result<(), StorageError> {
        let index = self.pending_index.as_mut().ok_or_else(|| {
            StorageError::Internal {
                message: "index must be loaded before upserting records".to_string(),
            }
        })?;

        // Find and replace or insert
        if let Some(existing) = index
            .records
            .iter_mut()
            .find(|r| r.credential_id == record.credential_id)
        {
            *existing = record;
        } else {
            index.records.push(record);
        }

        Ok(())
    }

    /// Adds a blob pointer to the pending index.
    ///
    /// This is typically called after `put_blob` to register the blob
    /// in the index.
    ///
    /// # Errors
    ///
    /// Returns an error if the index hasn't been loaded.
    pub fn add_blob_to_index(&mut self, ptr: BlobPointer) -> Result<(), StorageError> {
        let index = self.pending_index.as_mut().ok_or_else(|| {
            StorageError::Internal {
                message: "index must be loaded before adding blobs".to_string(),
            }
        })?;

        // Check for duplicate content_id
        if !index.blobs.iter().any(|b| b.content_id == ptr.content_id) {
            index.blobs.push(ptr);
        }

        Ok(())
    }

    /// Commits the transaction.
    ///
    /// This writes the encrypted index snapshot, TxnCommit record, and
    /// atomically updates the superblock.
    ///
    /// # Commit Sequence
    ///
    /// 1. Serialize and encrypt the pending index
    /// 2. Append `EncryptedIndexSnapshot` record
    /// 3. Append `TxnCommit` record
    /// 4. Sync all data to disk
    /// 5. Write the new superblock (alternating A/B)
    /// 6. Final sync
    ///
    /// # Errors
    ///
    /// Returns an error if any step fails. If an error occurs before
    /// the superblock write, the transaction has no effect.
    pub fn commit(mut self) -> Result<(), StorageError> {
        if self.committed {
            return Err(StorageError::Internal {
                message: "transaction already committed".to_string(),
            });
        }

        // Get or load the index
        let mut index = match self.pending_index.take() {
            Some(idx) => idx,
            None => self.vault.read_index()?,
        };

        // Bump sequence and timestamp
        let now = get_current_timestamp();
        index.bump_sequence(now);

        // Serialize index
        let index_bytes = serialize_vault_index(&index)?;

        // Encrypt index
        let (index_ciphertext, index_nonce) =
            encrypt_index(self.vault.vault_key(), self.vault.account_id(), &index_bytes)?;

        // Create and write index snapshot record
        let index_snapshot = EncryptedIndexSnapshot::new(index_nonce, index_ciphertext);
        let index_envelope = index_snapshot.to_envelope();
        let index_record_bytes = index_envelope.encode();

        let index_offset = self.vault.store().append(&index_record_bytes)?;
        let index_len = index_record_bytes.len() as u32;
        let index_hash = hash_record_body(&index_snapshot.encode_body());

        // Create and write TxnCommit record
        let txn_commit = TxnCommit::new(self.txn_id, index_offset, index_len, index_hash, now);
        let txn_commit_envelope = txn_commit.to_envelope();
        let txn_commit_bytes = txn_commit_envelope.encode();

        let txn_commit_offset = self.vault.store().append(&txn_commit_bytes)?;
        let txn_commit_hash = hash_record_body(&txn_commit.encode_body());

        // Sync data before superblock
        self.vault.store().sync()?;

        // Create new superblock
        let next_generation = self.vault.next_generation();
        let next_slot = self.vault.next_superblock_slot();
        let superblock = Superblock::new(next_generation, txn_commit_offset, txn_commit_hash);

        // Write superblock to the next slot
        self.vault
            .store()
            .write_at(next_slot.offset(), &superblock.encode())?;

        // Final sync
        self.vault.store().sync()?;

        // Update vault state
        self.vault.update_active_superblock(superblock, next_slot);

        self.committed = true;
        Ok(())
    }

    /// Returns the transaction ID.
    #[must_use]
    pub const fn txn_id(&self) -> &[u8; 16] {
        &self.txn_id
    }

    /// Returns when the transaction started.
    #[must_use]
    pub const fn started_at(&self) -> u64 {
        self.started_at
    }

    /// Returns the number of blobs written in this transaction.
    #[must_use]
    pub fn blob_count(&self) -> usize {
        self.pending_blobs.len()
    }

    /// Returns whether the transaction has been committed.
    #[must_use]
    pub const fn is_committed(&self) -> bool {
        self.committed
    }
}

impl<V: VaultFileStore> Drop for VaultTxn<'_, V> {
    fn drop(&mut self) {
        if !self.committed {
            // Transaction was abandoned.
            // Due to the append-only design, no cleanup is needed.
            // The uncommitted records will be unreachable from any superblock.
        }
    }
}


#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::credential_storage::{
        platform::memory::MemoryVaultStore, vault::{VaultKey, SuperblockSlot}, AccountId, CredentialId, CredentialStatus,
    };

    fn create_test_vault() -> VaultFile<MemoryVaultStore> {
        let store = Arc::new(MemoryVaultStore::new());
        let account_id = AccountId::new([0x42u8; 32]);
        let vault_key = VaultKey::generate();

        VaultFile::create(store, account_id, vault_key).unwrap()
    }

    #[test]
    fn test_transaction_commit() {
        let mut vault = create_test_vault();
        let initial_gen = vault.generation();
        vault.with_txn(|_txn| Ok(())).unwrap();
        assert_eq!(vault.generation(), initial_gen + 1);
    }

    #[test]
    fn test_transaction_put_blob_roundtrip() {
        let mut vault = create_test_vault();
        let (content_id, ptr) = vault
            .with_txn(|txn| {
                let mut index = txn.load_index()?;
                let (cid, ptr) = txn.put_blob(BlobKind::CredentialBlob, b"hello, vault!")?;
                index.blobs.push(ptr.clone());
                txn.set_index(index);
                Ok((cid, ptr))
            })
            .unwrap();
        let data = vault.read_blob(&ptr).unwrap();
        assert_eq!(data, b"hello, vault!");
        let expected_cid = super::super::crypto::compute_content_id(b"hello, vault!");
        assert_eq!(content_id, expected_cid);
    }

    #[test]
    fn test_transaction_crash_simulation() {
        let store = Arc::new(MemoryVaultStore::new());
        let account_id = AccountId::new([0x55u8; 32]);
        let vault_key = VaultKey::generate();
        let mut vault = VaultFile::create(Arc::clone(&store), account_id, vault_key.clone()).unwrap();
        vault
            .with_txn(|txn| {
                let mut index = txn.load_index()?;
                let (_, ptr) = txn.put_blob(BlobKind::CredentialBlob, b"important data")?;
                index.blobs.push(ptr);
                txn.set_index(index);
                Ok(())
            })
            .unwrap();
        {
            let mut txn = VaultTxn::begin(&mut vault).unwrap();
            txn.put_blob(BlobKind::CredentialBlob, b"this should be lost").unwrap();
        }
        let vault = VaultFile::open(store, account_id, vault_key).unwrap();
        let index = vault.read_index().unwrap();
        assert_eq!(index.blobs.len(), 1);
        let data = vault.read_blob(&index.blobs[0]).unwrap();
        assert_eq!(data, b"important data");
    }
}
