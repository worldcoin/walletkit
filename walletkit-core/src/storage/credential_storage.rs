//! Storage facade implementing the credential storage API.

use std::io::Cursor;
use std::sync::{Arc, Mutex};

use world_id_core::FieldElement as CoreFieldElement;

use super::error::{StorageError, StorageResult};
use super::keys::StorageKeys;
use super::lock::{StorageLock, StorageLockGuard};
use super::paths::StoragePaths;
use super::traits::StorageProvider;
use super::traits::{AtomicBlobStore, DeviceKeystore};
use super::types::CredentialRecord;
use super::{CacheDb, VaultDb};
use crate::{Credential, FieldElement};

/// Concrete storage implementation backed by `SQLCipher` databases.
#[derive(uniffi::Object)]
pub struct CredentialStore {
    inner: Mutex<CredentialStoreInner>,
}

impl std::fmt::Debug for CredentialStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredentialStore").finish()
    }
}

struct CredentialStoreInner {
    lock: StorageLock,
    keystore: Arc<dyn DeviceKeystore>,
    blob_store: Arc<dyn AtomicBlobStore>,
    paths: StoragePaths,
    state: Option<StorageState>,
}

struct StorageState {
    #[allow(dead_code)]
    keys: StorageKeys,
    vault: VaultDb,
    cache: CacheDb,
    leaf_index: u64,
}

impl CredentialStoreInner {
    /// Creates a new storage handle from a platform provider.
    ///
    /// # Errors
    ///
    /// Returns an error if the storage lock cannot be opened.
    pub fn from_provider(provider: &dyn StorageProvider) -> StorageResult<Self> {
        let paths = provider.paths();
        Self::new(
            paths.as_ref().clone(),
            provider.keystore(),
            provider.blob_store(),
        )
    }

    /// Creates a new storage handle from explicit components.
    ///
    /// # Errors
    ///
    /// Returns an error if the storage lock cannot be opened.
    pub fn new(
        paths: StoragePaths,
        keystore: Arc<dyn DeviceKeystore>,
        blob_store: Arc<dyn AtomicBlobStore>,
    ) -> StorageResult<Self> {
        let lock = StorageLock::open(&paths.lock_path())?;
        Ok(Self {
            lock,
            keystore,
            blob_store,
            paths,
            state: None,
        })
    }

    fn guard(&self) -> StorageResult<StorageLockGuard> {
        self.lock.lock()
    }

    fn state(&self) -> StorageResult<&StorageState> {
        self.state.as_ref().ok_or(StorageError::NotInitialized)
    }

    fn state_mut(&mut self) -> StorageResult<&mut StorageState> {
        self.state.as_mut().ok_or(StorageError::NotInitialized)
    }
}

#[uniffi::export]
impl CredentialStore {
    /// Creates a new storage handle from explicit components.
    ///
    /// # Errors
    ///
    /// Returns an error if the storage lock cannot be opened.
    #[uniffi::constructor]
    pub fn new_with_components(
        paths: Arc<StoragePaths>,
        keystore: Arc<dyn DeviceKeystore>,
        blob_store: Arc<dyn AtomicBlobStore>,
    ) -> StorageResult<Self> {
        let paths = Arc::try_unwrap(paths).unwrap_or_else(|arc| (*arc).clone());
        let inner = CredentialStoreInner::new(paths, keystore, blob_store)?;
        Ok(Self {
            inner: Mutex::new(inner),
        })
    }

    /// Creates a new storage handle from a platform provider.
    ///
    /// # Errors
    ///
    /// Returns an error if the storage lock cannot be opened.
    #[uniffi::constructor]
    #[allow(clippy::needless_pass_by_value)]
    pub fn from_provider_arc(
        provider: Arc<dyn StorageProvider>,
    ) -> StorageResult<Self> {
        let inner = CredentialStoreInner::from_provider(provider.as_ref())?;
        Ok(Self {
            inner: Mutex::new(inner),
        })
    }

    /// Returns the storage paths used by this handle.
    ///
    /// # Errors
    ///
    /// Returns an error if the storage mutex is poisoned.
    pub fn storage_paths(&self) -> StorageResult<Arc<StoragePaths>> {
        self.lock_inner().map(|inner| Arc::new(inner.paths.clone()))
    }

    /// Initializes storage and validates the account leaf index.
    ///
    /// # Errors
    ///
    /// Returns an error if initialization fails or the leaf index mismatches.
    pub fn init(&self, leaf_index: u64, now: u64) -> StorageResult<()> {
        let mut inner = self.lock_inner()?;
        inner.init(leaf_index, now)
    }

    /// Lists active credential metadata, optionally filtered by issuer schema ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the credential query fails.
    pub fn list_credentials(
        &self,
        issuer_schema_id: Option<u64>,
        now: u64,
    ) -> StorageResult<Vec<CredentialRecord>> {
        self.lock_inner()?.list_credentials(issuer_schema_id, now)
    }

    /// Stores a credential and optional associated data.
    ///
    /// # Errors
    ///
    /// Returns an error if the credential cannot be stored.
    pub fn store_credential(
        &self,
        credential: &Credential,
        blinding_factor: &FieldElement,
        expires_at: u64,
        associated_data: Option<Vec<u8>>,
        now: u64,
    ) -> StorageResult<u64> {
        self.lock_inner()?.store_credential(
            credential,
            blinding_factor,
            expires_at,
            associated_data,
            now,
        )
    }

    /// Fetches a cached Merkle proof if it remains valid beyond `valid_before`.
    ///
    /// # Errors
    ///
    /// Returns an error if the cache lookup fails.
    pub fn merkle_cache_get(&self, valid_until: u64) -> StorageResult<Option<Vec<u8>>> {
        self.lock_inner()?.merkle_cache_get(valid_until)
    }

    /// Inserts a cached Merkle proof with a TTL.
    ///
    /// # Errors
    ///
    /// Returns an error if the cache insert fails.
    pub fn merkle_cache_put(
        &self,
        proof_bytes: Vec<u8>,
        now: u64,
        ttl_seconds: u64,
    ) -> StorageResult<()> {
        self.lock_inner()?
            .merkle_cache_put(proof_bytes, now, ttl_seconds)
    }

    /// Deletes all stored credentials from the vault.
    ///
    /// This removes all credentials but preserves storage metadata
    /// (leaf index, schema version). After deletion, the storage
    /// remains initialized and ready to store new credentials.
    ///
    /// # Returns
    ///
    /// The number of credentials deleted.
    ///
    /// # Errors
    ///
    /// Returns an error if the delete operation fails.
    pub fn delete_all_credentials(&self) -> StorageResult<u64> {
        let mut inner = self.lock_inner()?;
        inner.delete_all_credentials()
    }
}

/// Implementation not exposed to foreign bindings
impl CredentialStore {
    fn lock_inner(
        &self,
    ) -> StorageResult<std::sync::MutexGuard<'_, CredentialStoreInner>> {
        self.inner
            .lock()
            .map_err(|_| StorageError::Lock("storage mutex poisoned".to_string()))
    }

    /// Retrieves a full credential including raw bytes by issuer schema ID.
    ///
    /// Returns the most recent non-expired credential matching the issuer schema ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the credential query fails.
    pub fn get_credential(
        &self,
        issuer_schema_id: u64,
        now: u64,
    ) -> StorageResult<Option<(Credential, FieldElement)>> {
        self.lock_inner()?.get_credential(issuer_schema_id, now)
    }

    /// Checks whether a replay guard entry exists for the given nullifier.
    ///
    /// # Returns
    /// - bool: true if a replay guard entry exists (hence signalling a nullifier replay), false otherwise.
    ///
    /// # Errors
    ///
    /// Returns an error if the query to the cache unexpectedly fails.
    pub fn is_nullifier_replay(
        &self,
        nullifier: CoreFieldElement,
        now: u64,
    ) -> StorageResult<bool> {
        self.lock_inner()?.is_nullifier_replay(nullifier, now)
    }

    /// After a proof has been successfully generated, creates a replay guard entry
    /// locally to avoid future replays of the same nullifier.
    ///
    /// # Errors
    ///
    /// Returns an error if the query to the cache unexpectedly fails.
    pub fn replay_guard_set(
        &self,
        nullifier: CoreFieldElement,
        now: u64,
    ) -> StorageResult<()> {
        self.lock_inner()?.replay_guard_set(nullifier, now)
    }
}

impl CredentialStoreInner {
    fn init(&mut self, leaf_index: u64, now: u64) -> StorageResult<()> {
        let guard = self.guard()?;
        if let Some(state) = &mut self.state {
            state.vault.init_leaf_index(&guard, leaf_index, now)?;
            state.leaf_index = leaf_index;
            return Ok(());
        }

        let keys = StorageKeys::init(
            self.keystore.as_ref(),
            self.blob_store.as_ref(),
            &guard,
            now,
        )?;
        let vault =
            VaultDb::new(&self.paths.vault_db_path(), keys.intermediate_key(), &guard)?;
        let cache =
            CacheDb::new(&self.paths.cache_db_path(), keys.intermediate_key(), &guard)?;
        let mut state = StorageState {
            keys,
            vault,
            cache,
            leaf_index,
        };
        state.vault.init_leaf_index(&guard, leaf_index, now)?;
        self.state = Some(state);
        Ok(())
    }

    fn list_credentials(
        &self,
        issuer_schema_id: Option<u64>,
        now: u64,
    ) -> StorageResult<Vec<CredentialRecord>> {
        let state = self.state()?;
        state.vault.list_credentials(issuer_schema_id, now)
    }

    fn get_credential(
        &self,
        issuer_schema_id: u64,
        now: u64,
    ) -> StorageResult<Option<(Credential, FieldElement)>> {
        let state = self.state()?;
        if let Some((credential_bytes, blinding_factor_bytes)) = state
            .vault
            .fetch_credential_and_blinding_factor(issuer_schema_id, now)?
        {
            let credential = Credential::from_bytes(credential_bytes).map_err(|e| {
                StorageError::Serialization(format!(
                    "Critical. Failed to deserialize credential: {e}"
                ))
            })?;

            let blinding_factor = CoreFieldElement::deserialize_from_bytes(
                &mut Cursor::new(blinding_factor_bytes),
            )
            .map_err(|e| {
                StorageError::Serialization(format!(
                    "Critical. Failed to deserialize blinding factor: {e}"
                ))
            })?;
            return Ok(Some((credential, blinding_factor.into())));
        }
        Ok(None)
    }

    fn store_credential(
        &mut self,
        credential: &Credential,
        blinding_factor: &FieldElement,
        expires_at: u64,
        associated_data: Option<Vec<u8>>,
        now: u64,
    ) -> StorageResult<u64> {
        let issuer_schema_id = credential.issuer_schema_id();
        let genesis_issued_at = credential.genesis_issued_at();
        let credential_blob = credential
            .to_bytes()
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        let subject_blinding_factor = blinding_factor
            .to_bytes()
            .map_err(|e| StorageError::Serialization(e.to_string()))?;

        let guard = self.guard()?;
        let state = self.state_mut()?;
        state.vault.store_credential(
            &guard,
            issuer_schema_id,
            subject_blinding_factor,
            genesis_issued_at,
            expires_at,
            credential_blob,
            associated_data,
            now,
        )
    }

    fn merkle_cache_get(&self, valid_until: u64) -> StorageResult<Option<Vec<u8>>> {
        let state = self.state()?;
        state.cache.merkle_cache_get(valid_until)
    }

    fn merkle_cache_put(
        &mut self,
        proof_bytes: Vec<u8>,
        now: u64,
        ttl_seconds: u64,
    ) -> StorageResult<()> {
        let guard = self.guard()?;
        let state = self.state_mut()?;
        state
            .cache
            .merkle_cache_put(&guard, proof_bytes, now, ttl_seconds)
    }

    /// Checks whether a replay guard entry exists for the given nullifier.
    ///
    /// # Returns
    /// - bool: true if a replay guard entry exists (hence signalling a nullifier replay), false otherwise.
    ///
    /// # Errors
    ///
    /// Returns an error if the query to the cache unexpectedly fails.
    fn is_nullifier_replay(
        &self,
        nullifier: CoreFieldElement,
        now: u64,
    ) -> StorageResult<bool> {
        let mut nullifier_bytes = Vec::new();
        nullifier
            .serialize_as_bytes(&mut nullifier_bytes)
            .map_err(|e| {
                StorageError::Serialization(format!(
                    "critical. nullifier serialization failed: {e}"
                ))
            })?;
        let nullifier_len = nullifier_bytes.len();
        let nullifier_bytes: [u8; 32] = nullifier_bytes.try_into().map_err(|_| {
            StorageError::Serialization(format!(
                "critical. nullifier serialization failed: {nullifier_len}"
            ))
        })?;
        let state = self.state()?;
        state.cache.is_nullifier_replay(nullifier_bytes, now)
    }

    /// After a proof has been successfully generated, creates a replay guard entry
    /// locally to avoid future replays of the same nullifier.
    ///
    /// # Errors
    ///
    /// Returns an error if the query to the cache unexpectedly fails.
    fn replay_guard_set(
        &mut self,
        nullifier: CoreFieldElement,
        now: u64,
    ) -> StorageResult<()> {
        let guard = self.guard()?;
        let mut nullifier_bytes = Vec::new();
        nullifier
            .serialize_as_bytes(&mut nullifier_bytes)
            .map_err(|e| {
                StorageError::Serialization(format!(
                    "critical. nullifier serialization failed: {e}"
                ))
            })?;
        let nullifier_len = nullifier_bytes.len();
        let nullifier_bytes: [u8; 32] = nullifier_bytes.try_into().map_err(|_| {
            StorageError::Serialization(format!(
                "critical. nullifier serialization failed: {nullifier_len}"
            ))
        })?;
        let state = self.state_mut()?;
        state.cache.replay_guard_set(&guard, nullifier_bytes, now)
    }

    /// Deletes all stored credentials from the vault.
    ///
    /// # Errors
    ///
    /// Returns an error if the delete operation fails.
    fn delete_all_credentials(&mut self) -> StorageResult<u64> {
        let guard = self.guard()?;
        let state = self.state_mut()?;
        state.vault.delete_all_credentials(&guard)
    }
}

impl CredentialStore {
    /// Creates a new storage handle from a platform provider.
    ///
    /// # Errors
    ///
    /// Returns an error if the storage lock cannot be opened.
    pub fn from_provider(provider: &dyn StorageProvider) -> StorageResult<Self> {
        let inner = CredentialStoreInner::from_provider(provider)?;
        Ok(Self {
            inner: Mutex::new(inner),
        })
    }

    /// Creates a new storage handle from explicit components.
    ///
    /// # Errors
    ///
    /// Returns an error if the storage lock cannot be opened.
    pub fn new(
        paths: StoragePaths,
        keystore: Arc<dyn DeviceKeystore>,
        blob_store: Arc<dyn AtomicBlobStore>,
    ) -> StorageResult<Self> {
        let inner = CredentialStoreInner::new(paths, keystore, blob_store)?;
        Ok(Self {
            inner: Mutex::new(inner),
        })
    }

    /// Returns the storage paths used by this handle.
    ///
    /// # Errors
    ///
    /// Returns an error if the storage mutex is poisoned.
    pub fn paths(&self) -> StorageResult<StoragePaths> {
        self.lock_inner().map(|inner| inner.paths.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::tests_utils::{
        cleanup_test_storage, temp_root_path, InMemoryStorageProvider,
    };

    #[test]
    fn test_replay_guard_field_element_serialization() {
        let root = temp_root_path();
        let provider = InMemoryStorageProvider::new(&root);
        let paths = provider.paths().as_ref().clone();
        let keystore = provider.keystore();
        let blob_store = provider.blob_store();

        let mut inner = CredentialStoreInner::new(paths, keystore, blob_store)
            .expect("create inner");
        inner.init(42, 1000).expect("init storage");

        // Create a FieldElement from a known value
        let nullifier = CoreFieldElement::from(123_456_789u64);

        // Set a replay guard
        inner
            .replay_guard_set(nullifier, 1000)
            .expect("set replay guard");

        // The same FieldElement should be properly serialized and found after the grace period
        let exists_after_grace = inner
            .is_nullifier_replay(nullifier, 1601)
            .expect("check replay guard");
        assert!(
            exists_after_grace,
            "Replay guard should exist after grace period (10 minutes)"
        );

        cleanup_test_storage(&root);
    }

    #[test]
    fn test_replay_guard_grace_period() {
        let root = temp_root_path();
        let provider = InMemoryStorageProvider::new(&root);
        let paths = provider.paths().as_ref().clone();
        let keystore = provider.keystore();
        let blob_store = provider.blob_store();

        let mut inner = CredentialStoreInner::new(paths, keystore, blob_store)
            .expect("create inner");
        inner.init(42, 1000).expect("init storage");

        let nullifier = CoreFieldElement::from(999u64);
        let set_time = 1000u64;

        // Set a replay guard at time 1000
        inner
            .replay_guard_set(nullifier, set_time)
            .expect("set replay guard");

        // Within grace period (< 10 minutes): should return false
        // Grace period is 600 seconds (10 minutes)
        let check_time_1min = set_time + 60; // 1 minute later
        let exists_1min = inner
            .is_nullifier_replay(nullifier, check_time_1min)
            .expect("check at 1 minute");
        assert!(
            !exists_1min,
            "Replay guard should NOT be enforced during grace period (1 minute)"
        );

        let check_time_ten_min = set_time + 601; // 10 minutes later
        let exists_ten_min = inner
            .is_nullifier_replay(nullifier, check_time_ten_min)
            .expect("check at 9 minutes");
        assert!(
            exists_ten_min,
            "Replay guard should be enforced during grace period (10 minutes)"
        );

        cleanup_test_storage(&root);
    }

    #[test]
    fn test_replay_guard_expiration() {
        let root = temp_root_path();
        let provider = InMemoryStorageProvider::new(&root);
        let paths = provider.paths().as_ref().clone();
        let keystore = provider.keystore();
        let blob_store = provider.blob_store();

        let mut inner = CredentialStoreInner::new(paths, keystore, blob_store)
            .expect("create inner");
        inner.init(42, 1000).expect("init storage");

        let nullifier = CoreFieldElement::from(555u64);
        let set_time = 3000u64;

        // Set a replay guard at time 3000
        inner
            .replay_guard_set(nullifier, set_time)
            .expect("set replay guard");

        // After expiration (> 1 year): should return false
        let one_year_seconds = 365 * 24 * 60 * 60; // 31,536,000 seconds

        // Just before expiration: should still exist
        let check_time_before_exp = set_time + one_year_seconds - 1;
        let exists_before_exp = inner
            .is_nullifier_replay(nullifier, check_time_before_exp)
            .expect("check before expiration");
        assert!(
            exists_before_exp,
            "Replay guard SHOULD exist just before expiration"
        );

        // After expiration: should not exist
        let check_time_at_exp = set_time + one_year_seconds + 1;
        let exists_at_exp = inner
            .is_nullifier_replay(nullifier, check_time_at_exp)
            .expect("check at expiration");
        assert!(
            !exists_at_exp,
            "Replay guard should NOT exist at expiration (1 year)"
        );

        cleanup_test_storage(&root);
    }

    #[test]
    fn test_replay_guard_idempotency() {
        let root = temp_root_path();
        let provider = InMemoryStorageProvider::new(&root);
        let paths = provider.paths().as_ref().clone();
        let keystore = provider.keystore();
        let blob_store = provider.blob_store();

        let mut inner = CredentialStoreInner::new(paths, keystore, blob_store).unwrap();
        inner.init(42, 1000).expect("init storage");

        let nullifier = CoreFieldElement::from(12345u64);
        let first_set_time = 1000u64;

        // Set a replay guard at time 1000
        inner.replay_guard_set(nullifier, first_set_time).unwrap();

        // Try to set the same nullifier again at time 1060 (5 minutes later)
        let second_set_time = first_set_time + 300;
        inner
            .replay_guard_set(nullifier, second_set_time)
            .expect("second set should be idempotent");

        // Check at time 1601 (10+ minutes from first set)
        // This is past the grace period from the FIRST insertion
        let check_time_after_grace = first_set_time + 601;
        let exists_after_grace = inner
            .is_nullifier_replay(nullifier, check_time_after_grace)
            .expect("check after grace");
        assert!(
            exists_after_grace,
            "Replay guard SHOULD be enforced - past grace period from FIRST insertion"
        );

        cleanup_test_storage(&root);
    }

    #[test]
    fn test_get_credential() {
        use world_id_core::Credential as CoreCredential;

        let root = temp_root_path();
        let provider = InMemoryStorageProvider::new(&root);
        let paths = provider.paths().as_ref().clone();
        let keystore = provider.keystore();
        let blob_store = provider.blob_store();

        let mut inner = CredentialStoreInner::new(paths, keystore, blob_store)
            .expect("create inner");
        inner.init(42, 1000).expect("init storage");

        // Store a test credential
        let issuer_schema_id = 123u64;
        let blinding_factor = FieldElement::from(42u64);
        let expires_at = 2000u64;
        let core_cred = CoreCredential::new()
            .issuer_schema_id(issuer_schema_id)
            .genesis_issued_at(1000);
        let credential: Credential = core_cred.into();
        let associated_data = Some(vec![6, 7, 8]);

        inner
            .store_credential(
                &credential,
                &blinding_factor,
                expires_at,
                associated_data,
                1000,
            )
            .expect("store credential");

        // Retrieve the credential
        let (credential, _blinding_factor) = inner
            .get_credential(issuer_schema_id, 1000)
            .expect("get credential")
            .expect("credential should exist");

        // Verify the retrieved data
        assert_eq!(credential.issuer_schema_id(), issuer_schema_id);

        // Verify non-existent credential returns None
        let non_existent = inner
            .get_credential(999u64, 1000)
            .expect("get credential query should succeed");
        assert!(
            non_existent.is_none(),
            "Non-existent credential should return None"
        );

        // Verify expired credential returns None
        let expired = inner
            .get_credential(issuer_schema_id, 2001)
            .expect("get credential query should succeed");
        assert!(expired.is_none(), "Expired credential should return None");

        cleanup_test_storage(&root);
    }

    #[test]
    fn test_delete_all_credentials() {
        use world_id_core::Credential as CoreCredential;

        let root = temp_root_path();
        let provider = InMemoryStorageProvider::new(&root);
        let paths = provider.paths().as_ref().clone();
        let keystore = provider.keystore();
        let blob_store = provider.blob_store();

        let mut inner = CredentialStoreInner::new(paths, keystore, blob_store)
            .expect("create inner");
        inner.init(42, 1000).expect("init storage");

        // Store multiple test credentials with different issuer schema IDs
        let issuer_schema_id_1 = 100u64;
        let issuer_schema_id_2 = 200u64;
        let blinding_factor = FieldElement::from(42u64);
        let expires_at = 2000u64;

        let core_cred_1 = CoreCredential::new()
            .issuer_schema_id(issuer_schema_id_1)
            .genesis_issued_at(1000);
        let credential_1: Credential = core_cred_1.into();

        let core_cred_2 = CoreCredential::new()
            .issuer_schema_id(issuer_schema_id_2)
            .genesis_issued_at(1000);
        let credential_2: Credential = core_cred_2.into();

        inner
            .store_credential(&credential_1, &blinding_factor, expires_at, None, 1000)
            .expect("store credential 1");

        inner
            .store_credential(&credential_2, &blinding_factor, expires_at, None, 1000)
            .expect("store credential 2");

        // Verify both credentials exist
        let list_before = inner
            .list_credentials(None, 1000)
            .expect("list credentials before delete");
        assert_eq!(
            list_before.len(),
            2,
            "Should have 2 credentials before delete"
        );

        // Delete all credentials
        let deleted_count = inner
            .delete_all_credentials()
            .expect("delete all credentials");
        assert_eq!(deleted_count, 2, "Should have deleted 2 credentials");

        // Verify no credentials remain
        let list_after = inner
            .list_credentials(None, 1000)
            .expect("list credentials after delete");
        assert_eq!(
            list_after.len(),
            0,
            "Should have 0 credentials after delete"
        );

        // Verify specific credential lookups return None
        let cred_1_after = inner
            .get_credential(issuer_schema_id_1, 1000)
            .expect("get credential 1");
        assert!(
            cred_1_after.is_none(),
            "Credential 1 should not exist after delete"
        );

        let cred_2_after = inner
            .get_credential(issuer_schema_id_2, 1000)
            .expect("get credential 2");
        assert!(
            cred_2_after.is_none(),
            "Credential 2 should not exist after delete"
        );

        // Verify storage can still be used to store new credentials after deletion
        let core_cred_3 = CoreCredential::new()
            .issuer_schema_id(300u64)
            .genesis_issued_at(1000);
        let credential_3: Credential = core_cred_3.into();

        inner
            .store_credential(&credential_3, &blinding_factor, expires_at, None, 1000)
            .expect("store credential after delete");

        let list_new = inner
            .list_credentials(None, 1000)
            .expect("list credentials after new store");
        assert_eq!(
            list_new.len(),
            1,
            "Should have 1 credential after storing new one"
        );

        cleanup_test_storage(&root);
    }
}
