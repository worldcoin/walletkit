//! `VaultFile` implementation for managing vault container files.
//!
//! This module provides the main interface for opening, creating, and
//! interacting with vault files.

use std::sync::Arc;

use crate::credential_storage::{
    platform::VaultFileStore, AccountId, BlobPointer, StorageError, VaultIndex,
};

use super::{
    crypto::{decrypt_blob, decrypt_index, VaultKey},
    format::{
        DATA_REGION_START, FILE_HEADER_SIZE, RECORD_ENVELOPE_HEADER_SIZE,
        RECORD_TYPE_ENCRYPTED_BLOB, RECORD_TYPE_ENCRYPTED_INDEX,
        RECORD_TYPE_TXN_COMMIT, SUPERBLOCK_SIZE,
    },
    header::{select_active_superblock, FileHeader, Superblock, SuperblockSlot},
    records::{EncryptedBlobObject, EncryptedIndexSnapshot, RecordEnvelope, TxnCommit},
    transaction::VaultTxn,
};


/// Handle to an open vault file.
///
/// `VaultFile` provides the main interface for reading and writing to a vault
/// container. All mutations occur within transactions to ensure crash safety.
///
/// # Thread Safety
///
/// `VaultFile` is NOT thread-safe. External locking (via `AccountLockManager`)
/// must be used to serialize access across threads/processes.
///
/// # Example
///
/// ```ignore
/// let store = MemoryVaultStore::new();
/// let key = VaultKey::generate();
/// let account_id = AccountId::new([0u8; 32]);
///
/// // Create a new vault
/// let mut vault = VaultFile::create(store, account_id, key)?;
///
/// // Read the index
/// let index = vault.read_index()?;
///
/// // Execute a transaction
/// vault.with_txn(|txn| {
///     txn.put_blob(BlobKind::CredentialBlob, b"credential data")?;
///     txn.commit()
/// })?;
/// ```
pub struct VaultFile<V: VaultFileStore> {
    /// The underlying file store.
    store: Arc<V>,
    /// Account this vault belongs to.
    account_id: AccountId,
    /// Vault encryption key.
    vault_key: VaultKey,
    /// Currently active superblock (if any).
    active_superblock: Option<Superblock>,
    /// Which slot the active superblock is in.
    active_slot: SuperblockSlot,
}

impl<V: VaultFileStore> VaultFile<V> {
    /// Opens an existing vault file.
    ///
    /// # Arguments
    ///
    /// * `store` - The underlying file store
    /// * `account_id` - Expected account ID (must match file header)
    /// * `vault_key` - The vault encryption key
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The file doesn't exist or is empty
    /// - The header is invalid or account ID doesn't match
    /// - No valid superblock is found
    pub fn open(
        store: Arc<V>,
        account_id: AccountId,
        vault_key: VaultKey,
    ) -> Result<Self, StorageError> {
        // Check file exists and has content
        let file_len = store.len()?;
        if file_len < DATA_REGION_START {
            return Err(StorageError::VaultNotInitialized);
        }

        // Read and validate header
        #[allow(clippy::cast_possible_truncation)]
        // FILE_HEADER_SIZE is a small constant (48)
        let header_bytes = store.read_at(0, FILE_HEADER_SIZE as u32)?;
        let header = FileHeader::decode(&header_bytes)?;

        if header.account_id != account_id {
            return Err(StorageError::AccountIdMismatch {
                expected: account_id,
                found: header.account_id,
            });
        }

        // Read superblocks (A and B slots)
        #[allow(clippy::cast_possible_truncation)]
        // SUPERBLOCK_SIZE is a small constant (57)
        let first_sb_bytes = store
            .read_at(super::format::SUPERBLOCK_A_OFFSET, SUPERBLOCK_SIZE as u32)?;
        #[allow(clippy::cast_possible_truncation)]
        let second_sb_bytes = store
            .read_at(super::format::SUPERBLOCK_B_OFFSET, SUPERBLOCK_SIZE as u32)?;

        let superblock_a = Superblock::try_decode(&first_sb_bytes);
        let superblock_b = Superblock::try_decode(&second_sb_bytes);

        let (active_superblock, active_slot) =
            select_active_superblock(superblock_a, superblock_b)
                .ok_or(StorageError::NoValidSuperblock)?;

        Ok(Self {
            store,
            account_id,
            vault_key,
            active_superblock: Some(active_superblock),
            active_slot,
        })
    }

    /// Creates a new vault file with an empty index.
    ///
    /// # Arguments
    ///
    /// * `store` - The underlying file store (should be empty)
    /// * `account_id` - Account this vault belongs to
    /// * `vault_key` - The vault encryption key
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The file already has content
    /// - Writing the initial structure fails
    pub fn create(
        store: Arc<V>,
        account_id: AccountId,
        vault_key: VaultKey,
    ) -> Result<Self, StorageError> {
        // Ensure store is empty
        if store.len()? > 0 {
            return Err(StorageError::Internal {
                message: "cannot create vault: file already exists".to_string(),
            });
        }

        // Initialize file with header region
        store.set_len(DATA_REGION_START)?;

        // Write file header
        let header = FileHeader::new(account_id);
        store.write_at(0, &header.encode())?;

        // Create empty index
        let now = get_current_timestamp();
        let empty_index = VaultIndex::new(account_id, now);

        // Serialize index
        let index_bytes = serialize_vault_index(&empty_index)?;

        // Encrypt index
        let (ciphertext, nonce) =
            super::crypto::encrypt_index(&vault_key, &account_id, &index_bytes)?;

        // Create index snapshot record
        let index_snapshot = EncryptedIndexSnapshot::new(nonce, ciphertext);
        let index_envelope = index_snapshot.to_envelope();
        let index_record_bytes = index_envelope.encode();

        // Create TxnBegin record
        let txn_id = new_txn_id();
        let txn_begin = super::records::TxnBegin::new(txn_id, now);
        let txn_begin_envelope = txn_begin.to_envelope();
        let txn_begin_bytes = txn_begin_envelope.encode();

        // Create TxnCommit record
        let index_offset = DATA_REGION_START + txn_begin_bytes.len() as u64;
        #[allow(clippy::cast_possible_truncation)] // Index records fit in u32
        let index_len = index_record_bytes.len() as u32;
        let index_hash = super::crypto::hash_record_body(&index_snapshot.encode_body());

        let txn_commit =
            TxnCommit::new(txn_id, index_offset, index_len, index_hash, now);
        let txn_commit_envelope = txn_commit.to_envelope();
        let txn_commit_bytes = txn_commit_envelope.encode();

        let txn_commit_offset = DATA_REGION_START
            + txn_begin_bytes.len() as u64
            + index_record_bytes.len() as u64;

        // Append all records
        store.append(&txn_begin_bytes)?;
        store.append(&index_record_bytes)?;
        store.append(&txn_commit_bytes)?;

        // Sync data before writing superblock
        store.sync()?;

        // Write initial superblock A
        let txn_commit_hash =
            super::crypto::hash_record_body(&txn_commit.encode_body());
        let superblock = Superblock::new(1, txn_commit_offset, txn_commit_hash);
        store.write_at(super::format::SUPERBLOCK_A_OFFSET, &superblock.encode())?;

        // Final sync
        store.sync()?;

        Ok(Self {
            store,
            account_id,
            vault_key,
            active_superblock: Some(superblock),
            active_slot: SuperblockSlot::A,
        })
    }

    /// Opens an existing vault or creates a new one if it doesn't exist.
    ///
    /// # Arguments
    ///
    /// * `store` - The underlying file store
    /// * `account_id` - Account this vault belongs to
    /// * `vault_key` - The vault encryption key
    ///
    /// # Errors
    ///
    /// Returns an error if opening or creating fails.
    pub fn open_or_create(
        store: Arc<V>,
        account_id: AccountId,
        vault_key: VaultKey,
    ) -> Result<Self, StorageError> {
        if store.is_empty()? {
            Self::create(store, account_id, vault_key)
        } else {
            Self::open(store, account_id, vault_key)
        }
    }

    /// Returns the account ID for this vault.
    #[must_use]
    pub const fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    /// Returns a reference to the vault key.
    #[must_use]
    pub const fn vault_key(&self) -> &VaultKey {
        &self.vault_key
    }

    /// Returns the current active superblock generation.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.active_superblock
            .as_ref()
            .map_or(0, |sb| sb.generation)
    }

    /// Returns the current active superblock slot.
    #[must_use]
    pub const fn active_slot(&self) -> SuperblockSlot {
        self.active_slot
    }

    /// Returns a reference to the underlying store.
    #[must_use]
    pub const fn store(&self) -> &Arc<V> {
        &self.store
    }

    /// Reads and decrypts the current vault index.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - No valid superblock exists
    /// - Reading or decrypting the index fails
    /// - The index is corrupted
    pub fn read_index(&self) -> Result<VaultIndex, StorageError> {
        let superblock = self
            .active_superblock
            .as_ref()
            .ok_or(StorageError::NoValidSuperblock)?;

        // Read TxnCommit to get index location
        let txn_commit = self.read_txn_commit(superblock.committed_txn_offset)?;

        // Read and decrypt index
        self.read_index_at(txn_commit.index_offset, txn_commit.index_len)
    }

    /// Reads and decrypts a blob by its pointer.
    ///
    /// # Arguments
    ///
    /// * `ptr` - Pointer to the blob in the vault file
    ///
    /// # Errors
    ///
    /// Returns an error if reading or decrypting the blob fails.
    pub fn read_blob(&self, ptr: &BlobPointer) -> Result<Vec<u8>, StorageError> {
        // Read the record envelope
        let record_bytes = self.store.read_at(ptr.offset, ptr.length)?;
        let envelope = RecordEnvelope::decode(&record_bytes)?;

        if envelope.record_type != RECORD_TYPE_ENCRYPTED_BLOB {
            return Err(StorageError::corrupted(format!(
                "expected blob record, got type {}",
                envelope.record_type
            )));
        }

        // Decode blob object
        let blob_obj = EncryptedBlobObject::decode_body(&envelope.body)?;

        // Verify content ID matches
        if blob_obj.content_id != ptr.content_id {
            return Err(StorageError::corrupted("blob content ID mismatch"));
        }

        // Decrypt
        decrypt_blob(
            &self.vault_key,
            &self.account_id,
            ptr.kind,
            &ptr.content_id,
            &blob_obj.nonce,
            &blob_obj.ciphertext,
        )
    }

    /// Executes a transaction.
    ///
    /// Changes are committed only if the closure returns `Ok` and the commit
    /// sequence completes successfully. Any error results in no changes.
    ///
    /// # Arguments
    ///
    /// * `f` - Closure that receives a mutable reference to the transaction
    ///
    /// # Errors
    ///
    /// Returns an error if the transaction fails.
    ///
    /// # Example
    ///
    /// ```ignore
    /// vault.with_txn(|txn| {
    ///     let (content_id, ptr) = txn.put_blob(BlobKind::CredentialBlob, b"data")?;
    ///     txn.commit()
    /// })?;
    /// ```
    pub fn with_txn<R, F>(&mut self, f: F) -> Result<R, StorageError>
    where
        F: FnOnce(&mut VaultTxn<V>) -> Result<R, StorageError>,
    {
        let mut txn = VaultTxn::begin(self)?;
        let result = f(&mut txn)?;
        txn.commit()?;
        Ok(result)
    }


    /// Reads a `TxnCommit` record at the given offset.
    fn read_txn_commit(&self, offset: u64) -> Result<TxnCommit, StorageError> {
        // First read the header to get body length
        #[allow(clippy::cast_possible_truncation)]
        // RECORD_ENVELOPE_HEADER_SIZE is small (16)
        let header_bytes = self
            .store
            .read_at(offset, RECORD_ENVELOPE_HEADER_SIZE as u32)?;
        let body_len = RecordEnvelope::peek_body_len(&header_bytes)?;

        // Read full record
        #[allow(clippy::cast_possible_truncation)]
        let total_len = RECORD_ENVELOPE_HEADER_SIZE as u32 + body_len;
        let record_bytes = self.store.read_at(offset, total_len)?;
        let envelope = RecordEnvelope::decode(&record_bytes)?;

        if envelope.record_type != RECORD_TYPE_TXN_COMMIT {
            return Err(StorageError::corrupted(format!(
                "expected TxnCommit record, got type {}",
                envelope.record_type
            )));
        }

        TxnCommit::decode_body(&envelope.body)
    }

    /// Reads and decrypts an index at the given offset.
    fn read_index_at(&self, offset: u64, len: u32) -> Result<VaultIndex, StorageError> {
        // Read the record envelope
        let record_bytes = self.store.read_at(offset, len)?;
        let envelope = RecordEnvelope::decode(&record_bytes)?;

        if envelope.record_type != RECORD_TYPE_ENCRYPTED_INDEX {
            return Err(StorageError::corrupted(format!(
                "expected index record, got type {}",
                envelope.record_type
            )));
        }

        // Decode index snapshot
        let snapshot = EncryptedIndexSnapshot::decode_body(&envelope.body)?;

        // Decrypt
        let plaintext = decrypt_index(
            &self.vault_key,
            &self.account_id,
            &snapshot.nonce,
            &snapshot.ciphertext,
        )?;

        // Deserialize
        deserialize_vault_index(&plaintext)
    }

    /// Updates the active superblock after a successful commit.
    pub(super) const fn update_active_superblock(
        &mut self,
        superblock: Superblock,
        slot: SuperblockSlot,
    ) {
        self.active_superblock = Some(superblock);
        self.active_slot = slot;
    }

    /// Returns the slot for the next superblock write.
    pub(super) const fn next_superblock_slot(&self) -> SuperblockSlot {
        self.active_slot.other()
    }

    /// Returns the next generation number.
    pub(super) fn next_generation(&self) -> u64 {
        self.generation() + 1
    }
}

impl<V: VaultFileStore> std::fmt::Debug for VaultFile<V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultFile")
            .field("account_id", &self.account_id)
            .field("generation", &self.generation())
            .field("active_slot", &self.active_slot)
            .finish_non_exhaustive()
    }
}

// Helper Functions (pub(super) for transaction module access)

/// Serializes a `VaultIndex` to bytes using bincode.
pub(super) fn serialize_vault_index(
    index: &VaultIndex,
) -> Result<Vec<u8>, StorageError> {
    bincode::serialize(index).map_err(|e| StorageError::serialization(e.to_string()))
}

/// Deserializes a `VaultIndex` from bytes using bincode.
pub(super) fn deserialize_vault_index(
    bytes: &[u8],
) -> Result<VaultIndex, StorageError> {
    bincode::deserialize(bytes)
        .map_err(|e| StorageError::deserialization(e.to_string()))
}

/// Generates a random transaction ID.
pub(super) fn new_txn_id() -> [u8; 16] {
    let mut id = [0u8; 16];
    getrandom::getrandom(&mut id).expect("getrandom failed");
    id
}

/// Returns the current Unix timestamp.
pub(super) fn get_current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time before Unix epoch")
        .as_secs()
}


#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::credential_storage::platform::memory::MemoryVaultStore;


    #[test]
    fn test_vault_create_and_open() {
        let store = Arc::new(MemoryVaultStore::new());
        let account_id = AccountId::new([0x22u8; 32]);
        let vault_key = VaultKey::generate();
        let vault = VaultFile::create(Arc::clone(&store), account_id, vault_key.clone()).unwrap();
        assert_eq!(vault.generation(), 1);
        drop(vault);
        let vault = VaultFile::open(store, account_id, vault_key).unwrap();
        assert_eq!(vault.generation(), 1);
        let index = vault.read_index().unwrap();
        assert_eq!(index.account_id, account_id);
    }

    #[test]
    fn test_vault_header_parsing() {
        let store = Arc::new(MemoryVaultStore::new());
        let account_id = AccountId::new([0x11u8; 32]);
        let vault_key = VaultKey::generate();
        let _vault = VaultFile::create(Arc::clone(&store), account_id, vault_key).unwrap();
        let header_bytes = store.read_at(0, 8).unwrap();
        assert_eq!(&header_bytes, super::super::format::FILE_MAGIC);
        let sb_a_bytes = store
            .read_at(
                super::super::format::SUPERBLOCK_A_OFFSET,
                SUPERBLOCK_SIZE as u32,
            )
            .unwrap();
        assert!(Superblock::is_valid(&sb_a_bytes));
    }
}
