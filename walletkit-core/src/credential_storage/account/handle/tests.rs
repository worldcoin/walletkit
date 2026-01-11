//! Tests for `AccountHandle`.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::credential_storage::{
    account::{
        derivation::{derive_issuer_blind, derive_session_r},
        handle::AccountHandle,
        store::{PlatformBundle, WorldIdStore},
    },
    platform::{
        memory::{MemoryBlobStore, MemoryKeystore, MemoryLockManager, MemoryVaultStore},
        AtomicBlobStore, VaultFileStore,
    },
    AccountId, StorageResult,
};

// =============================================================================
// Test-only Platform Bundle Implementation
// =============================================================================

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

// =============================================================================
// Test Helper
// =============================================================================

fn create_test_handle(
) -> AccountHandle<MemoryKeystore, SharedBlobStore, SharedVaultStore, MemoryLockManager> {
    let keystore = Arc::new(MemoryKeystore::new());
    let platform = Arc::new(SharedMemoryPlatformBundle::new());
    let lock_manager = Arc::new(MemoryLockManager::new());
    let store = WorldIdStore::new(keystore, platform, lock_manager);

    store.create_account().unwrap()
}

// =============================================================================
// Core Tests
// =============================================================================

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

// =============================================================================
// Credential Operations Tests
// =============================================================================

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
    handle
        .put_credential(cred_id, 1, None, cred_blob, None)
        .unwrap();

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
    handle
        .put_credential(cred_id, 1, None, original_blob, None)
        .unwrap();

    // Verify original
    let (blob, _) = handle.get_credential(cred_id).unwrap();
    assert_eq!(blob, original_blob);

    // Update credential
    handle
        .put_credential(cred_id, 2, Some(9999), updated_blob, Some(b"new assoc"))
        .unwrap();

    // Verify updated
    let (blob, assoc) = handle.get_credential(cred_id).unwrap();
    assert_eq!(blob, updated_blob);
    assert_eq!(assoc, Some(b"new assoc".to_vec()));

    // Verify record metadata was updated
    let record = handle.get_credential_record(cred_id).unwrap();
    assert_eq!(record.issuer_schema_id, 2);
    assert_eq!(record.expires_at, Some(9999));
    // Status should still be Active after update
    assert_eq!(
        record.status,
        crate::credential_storage::CredentialStatus::Active
    );
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

    handle
        .put_credential(cred1, 1, None, b"cred1", None)
        .unwrap();
    handle
        .put_credential(cred2, 2, None, b"cred2", None)
        .unwrap();
    handle
        .put_credential(cred3, 1, None, b"cred3", None)
        .unwrap();

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

    handle
        .put_credential(cred1, 1, None, b"cred1", None)
        .unwrap();
    handle
        .put_credential(cred2, 2, None, b"cred2", None)
        .unwrap();
    handle
        .put_credential(cred3, 1, None, b"cred3", None)
        .unwrap();

    // Filter by schema ID 1
    let filter = crate::credential_storage::CredentialFilter::new().with_issuer_schema_id(1);
    let filtered = handle.list_credentials(Some(filter)).unwrap();

    assert_eq!(filtered.len(), 2);
    assert!(filtered.iter().all(|r| r.issuer_schema_id == 1));
}

#[test]
fn test_list_credentials_filter_by_status() {
    let mut handle = create_test_handle();

    let cred1 = crate::credential_storage::CredentialId::generate();
    let cred2 = crate::credential_storage::CredentialId::generate();

    handle
        .put_credential(cred1, 1, None, b"cred1", None)
        .unwrap();
    handle
        .put_credential(cred2, 1, None, b"cred2", None)
        .unwrap();

    // Retire cred2
    handle.retire_credential(cred2).unwrap();

    // Default filter (Active only)
    let active = handle
        .list_credentials(Some(crate::credential_storage::CredentialFilter::new()))
        .unwrap();
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].credential_id, cred1);

    // Filter for Retired
    let retired = handle
        .list_credentials(Some(
            crate::credential_storage::CredentialFilter::new()
                .with_status(crate::credential_storage::CredentialStatus::Retired),
        ))
        .unwrap();
    assert_eq!(retired.len(), 1);
    assert_eq!(retired[0].credential_id, cred2);

    // Any status
    let all = handle
        .list_credentials(Some(
            crate::credential_storage::CredentialFilter::new().any_status(),
        ))
        .unwrap();
    assert_eq!(all.len(), 2);
}

#[test]
fn test_list_credentials_filter_expired() {
    let mut handle = create_test_handle();

    let now = super::get_current_timestamp();

    let cred_valid = crate::credential_storage::CredentialId::generate();
    let cred_expired = crate::credential_storage::CredentialId::generate();

    // Valid credential (expires in future)
    handle
        .put_credential(cred_valid, 1, Some(now + 3600), b"valid", None)
        .unwrap();
    // Expired credential
    handle
        .put_credential(cred_expired, 1, Some(now - 3600), b"expired", None)
        .unwrap();

    // Default filter excludes expired
    let non_expired = handle
        .list_credentials(Some(crate::credential_storage::CredentialFilter::new()))
        .unwrap();
    assert_eq!(non_expired.len(), 1);
    assert_eq!(non_expired[0].credential_id, cred_valid);

    // Include expired
    let with_expired = handle
        .list_credentials(Some(
            crate::credential_storage::CredentialFilter::new().include_expired(),
        ))
        .unwrap();
    assert_eq!(with_expired.len(), 2);
}

#[test]
fn test_retire_credential() {
    let mut handle = create_test_handle();

    let cred_id = crate::credential_storage::CredentialId::generate();
    handle
        .put_credential(cred_id, 1, None, b"test", None)
        .unwrap();

    // Verify initially active
    let record = handle.get_credential_record(cred_id).unwrap();
    assert_eq!(
        record.status,
        crate::credential_storage::CredentialStatus::Active
    );

    // Retire
    handle.retire_credential(cred_id).unwrap();

    // Verify retired
    let record = handle.get_credential_record(cred_id).unwrap();
    assert_eq!(
        record.status,
        crate::credential_storage::CredentialStatus::Retired
    );

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

    handle
        .put_credential(cred_id, 42, Some(now + 1000), b"data", None)
        .unwrap();

    let record = handle.get_credential_record(cred_id).unwrap();

    assert_eq!(record.credential_id, cred_id);
    assert_eq!(record.issuer_schema_id, 42);
    assert_eq!(record.expires_at, Some(now + 1000));
    assert_eq!(
        record.status,
        crate::credential_storage::CredentialStatus::Active
    );
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

    handle
        .put_credential(small_cred, 1, None, &small_data, None)
        .unwrap();
    handle
        .put_credential(medium_cred, 2, None, &medium_data, Some(&small_data))
        .unwrap();
    handle
        .put_credential(large_cred, 3, None, &large_data, Some(&medium_data))
        .unwrap();

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
    handle
        .put_credential(cred1, 1, Some(now + 3600), b"1", None)
        .unwrap();

    // Active, no expiration
    let cred2 = crate::credential_storage::CredentialId::generate();
    handle.put_credential(cred2, 1, None, b"2", None).unwrap();

    // Active, expired
    let cred3 = crate::credential_storage::CredentialId::generate();
    handle
        .put_credential(cred3, 1, Some(now - 3600), b"3", None)
        .unwrap();

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
    let store = WorldIdStore::new(
        Arc::clone(&keystore),
        Arc::clone(&platform),
        Arc::clone(&lock_manager),
    );

    let cred_id = crate::credential_storage::CredentialId::generate();

    // Create account and add credential
    let account_id = {
        let mut handle = store.create_account().unwrap();
        handle
            .put_credential(
                cred_id,
                99,
                None,
                b"persistent data",
                Some(b"persistent assoc"),
            )
            .unwrap();
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
    assert_eq!(
        record.status,
        crate::credential_storage::CredentialStatus::Active
    );
}

// =============================================================================
// Nullifier Protection Tests
// =============================================================================

mod onp_tests {
    use super::*;
    use crate::credential_storage::pending::{InMemoryOnpClient, OnpClient, StubOnpClient};

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
        let result =
            handle.begin_action_disclosure(&rp_id, &action_id, request2, &nullifier, proof, &onp);

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
        let result =
            handle.begin_action_disclosure(&rp_id, &action_id, request, &nullifier, proof, &onp);

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
        assert!(handle
            .get_pending_action(&rp_id, &action_id)
            .unwrap()
            .is_none());

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

// =============================================================================
// Sync / Transfer Tests
// =============================================================================

mod sync_tests {
    use super::*;
    use crate::credential_storage::{provisioning::DeviceKeyPair, ImportOutcome};

    #[test]
    fn test_export_import_credential_roundtrip() {
        // Device A: create account and credential
        let keystore_a = Arc::new(MemoryKeystore::new());
        let platform_a = Arc::new(SharedMemoryPlatformBundle::new());
        let lock_manager_a = Arc::new(MemoryLockManager::new());
        let store_a = WorldIdStore::new(
            Arc::clone(&keystore_a),
            Arc::clone(&platform_a),
            Arc::clone(&lock_manager_a),
        );

        let mut handle_a = store_a.create_account().unwrap();
        let cred_id = crate::credential_storage::CredentialId::generate();
        let cred_blob = b"test credential data for sync";
        let assoc_data = b"associated metadata";

        handle_a
            .put_credential(cred_id, 42, None, cred_blob, Some(assoc_data))
            .unwrap();

        // Export credential from Device A
        let transfer = handle_a.export_credential(cred_id).unwrap();

        // Device B: provision with same vault key
        let device_b_keypair = DeviceKeyPair::generate();
        let envelope = handle_a
            .export_vault_provisioning_envelope(device_b_keypair.public_key())
            .unwrap();

        let keystore_b = Arc::new(MemoryKeystore::new());
        let platform_b = Arc::new(SharedMemoryPlatformBundle::new());
        let lock_manager_b = Arc::new(MemoryLockManager::new());
        let store_b = WorldIdStore::new(
            Arc::clone(&keystore_b),
            Arc::clone(&platform_b),
            Arc::clone(&lock_manager_b),
        );

        let mut handle_b = store_b
            .import_vault_provisioning_envelope(&envelope, device_b_keypair.secret_key())
            .unwrap();

        // Import credential on Device B
        let outcome = handle_b.import_credential(&transfer).unwrap();
        assert_eq!(outcome, ImportOutcome::Applied);

        // Verify credential on Device B
        let (blob_b, assoc_b) = handle_b.get_credential(cred_id).unwrap();
        assert_eq!(blob_b, cred_blob);
        assert_eq!(assoc_b.as_deref(), Some(assoc_data.as_slice()));
    }

    #[test]
    fn test_export_import_tombstone() {
        // Device A: create and retire a credential
        let mut handle_a = create_test_handle();
        let cred_id = crate::credential_storage::CredentialId::generate();

        handle_a
            .put_credential(cred_id, 1, None, b"data", None)
            .unwrap();
        handle_a.retire_credential(cred_id).unwrap();

        // Export tombstone
        let transfer = handle_a.export_credential_tombstone(cred_id).unwrap();

        // Device B: provision and import
        let device_b_keypair = DeviceKeyPair::generate();
        let envelope = handle_a
            .export_vault_provisioning_envelope(device_b_keypair.public_key())
            .unwrap();

        let keystore_b = Arc::new(MemoryKeystore::new());
        let platform_b = Arc::new(SharedMemoryPlatformBundle::new());
        let lock_manager_b = Arc::new(MemoryLockManager::new());
        let store_b = WorldIdStore::new(
            Arc::clone(&keystore_b),
            Arc::clone(&platform_b),
            Arc::clone(&lock_manager_b),
        );

        let mut handle_b = store_b
            .import_vault_provisioning_envelope(&envelope, device_b_keypair.secret_key())
            .unwrap();

        // Import tombstone
        let outcome = handle_b.import_credential(&transfer).unwrap();
        assert_eq!(outcome, ImportOutcome::Applied);

        // Verify credential is retired on Device B
        let record = handle_b.get_credential_record(cred_id).unwrap();
        assert_eq!(
            record.status,
            crate::credential_storage::CredentialStatus::Retired
        );
    }

    #[test]
    fn test_import_idempotent() {
        let mut handle = create_test_handle();
        let cred_id = crate::credential_storage::CredentialId::generate();

        handle
            .put_credential(cred_id, 1, None, b"data", None)
            .unwrap();

        // Export
        let transfer = handle.export_credential(cred_id).unwrap();

        // Import first time - should be NoOp because we already have it with same timestamp
        let outcome = handle.import_credential(&transfer).unwrap();
        assert_eq!(outcome, ImportOutcome::NoOp);
    }

    #[test]
    fn test_import_conflict_resolution() {
        // This test verifies conflict resolution logic
        // Instead of relying on real timestamps, we test directly with the transfer module
        use crate::credential_storage::transfer::{decide_import, ImportDecision, TransferPayload};
        use crate::credential_storage::{AccountId, ContentId, CredentialRecord, CredentialStatus};

        let account_id = AccountId::new([0u8; 32]);
        let cred_id = crate::credential_storage::CredentialId::generate();

        // Create existing record with timestamp 1000
        let existing_record = CredentialRecord {
            credential_id: cred_id,
            issuer_schema_id: 1,
            created_at: 1000,
            updated_at: 1000,
            expires_at: None,
            credential_blob_cid: ContentId::new([1u8; 32]),
            associated_data_cid: None,
            status: CredentialStatus::Active,
        };

        // Create incoming payload with older timestamp - should skip
        let older_payload = TransferPayload {
            version: 1,
            account_id,
            record: CredentialRecord {
                credential_id: cred_id,
                issuer_schema_id: 1,
                created_at: 500,
                updated_at: 500, // older
                expires_at: None,
                credential_blob_cid: ContentId::new([2u8; 32]),
                associated_data_cid: None,
                status: CredentialStatus::Active,
            },
            is_tombstone: false,
            credential_blob: Some(b"older".to_vec()),
            associated_data: None,
        };

        assert_eq!(
            decide_import(&older_payload, Some(&existing_record)),
            ImportDecision::Skip
        );

        // Create incoming payload with newer timestamp - should apply
        let newer_payload = TransferPayload {
            version: 1,
            account_id,
            record: CredentialRecord {
                credential_id: cred_id,
                issuer_schema_id: 1,
                created_at: 1500,
                updated_at: 1500, // newer
                expires_at: None,
                credential_blob_cid: ContentId::new([3u8; 32]),
                associated_data_cid: None,
                status: CredentialStatus::Active,
            },
            is_tombstone: false,
            credential_blob: Some(b"newer".to_vec()),
            associated_data: None,
        };

        assert_eq!(
            decide_import(&newer_payload, Some(&existing_record)),
            ImportDecision::Apply
        );

        // Create incoming payload for non-existent credential - should apply
        let new_cred_id = crate::credential_storage::CredentialId::generate();
        let new_payload = TransferPayload {
            version: 1,
            account_id,
            record: CredentialRecord {
                credential_id: new_cred_id,
                issuer_schema_id: 1,
                created_at: 100,
                updated_at: 100,
                expires_at: None,
                credential_blob_cid: ContentId::new([4u8; 32]),
                associated_data_cid: None,
                status: CredentialStatus::Active,
            },
            is_tombstone: false,
            credential_blob: Some(b"new".to_vec()),
            associated_data: None,
        };

        assert_eq!(decide_import(&new_payload, None), ImportDecision::Apply);
    }

    #[test]
    fn test_export_retired_fails() {
        let mut handle = create_test_handle();
        let cred_id = crate::credential_storage::CredentialId::generate();

        handle
            .put_credential(cred_id, 1, None, b"data", None)
            .unwrap();
        handle.retire_credential(cred_id).unwrap();

        // Exporting retired credential should fail
        let result = handle.export_credential(cred_id);
        assert!(matches!(
            result,
            Err(crate::credential_storage::StorageError::InvalidInput { .. })
        ));
    }

    #[test]
    fn test_export_all_credentials() {
        let mut handle = create_test_handle();

        // Create multiple credentials
        let cred1 = crate::credential_storage::CredentialId::generate();
        let cred2 = crate::credential_storage::CredentialId::generate();
        let cred3 = crate::credential_storage::CredentialId::generate();

        handle.put_credential(cred1, 1, None, b"c1", None).unwrap();
        handle.put_credential(cred2, 2, None, b"c2", None).unwrap();
        handle.put_credential(cred3, 3, None, b"c3", None).unwrap();

        // Retire one
        handle.retire_credential(cred2).unwrap();

        // Export all
        let transfers = handle.export_all_credentials().unwrap();
        assert_eq!(transfers.len(), 3);
    }

    #[test]
    fn test_import_credentials_batch() {
        // Device A
        let mut handle_a = create_test_handle();

        let cred1 = crate::credential_storage::CredentialId::generate();
        let cred2 = crate::credential_storage::CredentialId::generate();

        handle_a.put_credential(cred1, 1, None, b"c1", None).unwrap();
        handle_a.put_credential(cred2, 2, None, b"c2", None).unwrap();

        // Device B
        let device_b_keypair = DeviceKeyPair::generate();
        let envelope = handle_a
            .export_vault_provisioning_envelope(device_b_keypair.public_key())
            .unwrap();

        let keystore_b = Arc::new(MemoryKeystore::new());
        let platform_b = Arc::new(SharedMemoryPlatformBundle::new());
        let lock_manager_b = Arc::new(MemoryLockManager::new());
        let store_b = WorldIdStore::new(
            Arc::clone(&keystore_b),
            Arc::clone(&platform_b),
            Arc::clone(&lock_manager_b),
        );

        let mut handle_b = store_b
            .import_vault_provisioning_envelope(&envelope, device_b_keypair.secret_key())
            .unwrap();

        // Export all from A
        let transfers = handle_a.export_all_credentials().unwrap();

        // Import all to B
        let outcomes = handle_b.import_credentials(&transfers).unwrap();

        assert_eq!(outcomes.len(), 2);
        assert!(outcomes.iter().all(|o| *o == ImportOutcome::Applied));

        // Verify B has both
        let _ = handle_b.get_credential(cred1).unwrap();
        let _ = handle_b.get_credential(cred2).unwrap();
    }

    #[test]
    fn test_provisioning_preserves_derivation() {
        let handle_a = create_test_handle();

        // Derive some values
        let issuer_blind_a = handle_a.derive_issuer_blind(42);
        let rp_id = [0x11u8; 32];
        let action_id = [0x22u8; 32];
        let session_r_a = handle_a.derive_session_r(&rp_id, &action_id);

        // Provision Device B
        let device_b_keypair = DeviceKeyPair::generate();
        let envelope = handle_a
            .export_vault_provisioning_envelope(device_b_keypair.public_key())
            .unwrap();

        let keystore_b = Arc::new(MemoryKeystore::new());
        let platform_b = Arc::new(SharedMemoryPlatformBundle::new());
        let lock_manager_b = Arc::new(MemoryLockManager::new());
        let store_b = WorldIdStore::new(
            Arc::clone(&keystore_b),
            Arc::clone(&platform_b),
            Arc::clone(&lock_manager_b),
        );

        let handle_b = store_b
            .import_vault_provisioning_envelope(&envelope, device_b_keypair.secret_key())
            .unwrap();

        // Derive same values on B - should match
        let issuer_blind_b = handle_b.derive_issuer_blind(42);
        let session_r_b = handle_b.derive_session_r(&rp_id, &action_id);

        assert_eq!(issuer_blind_a, issuer_blind_b);
        assert_eq!(session_r_a, session_r_b);
    }
}
