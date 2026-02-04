//! Storage facade implementing the credential storage API.

use std::sync::{Arc, Mutex};

use world_id_core::FieldElement;

use super::error::{StorageError, StorageResult};
use super::keys::StorageKeys;
use super::lock::{StorageLock, StorageLockGuard};
use super::paths::StoragePaths;
use super::traits::StorageProvider;
use super::traits::{AtomicBlobStore, DeviceKeystore};
use super::types::CredentialRecord;
use super::{CacheDb, VaultDb};

/// Concrete storage implementation backed by `SQLCipher` databases.
#[derive(uniffi::Object)]
pub struct CredentialStore {
    inner: Mutex<CredentialStoreInner>,
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
    #[allow(clippy::too_many_arguments)]
    pub fn store_credential(
        &self,
        issuer_schema_id: u64,
        subject_blinding_factor: Vec<u8>,
        genesis_issued_at: u64,
        expires_at: u64,
        credential_blob: Vec<u8>,
        associated_data: Option<Vec<u8>>,
        now: u64,
    ) -> StorageResult<u64> {
        let subject_blinding_factor = parse_fixed_bytes::<32>(
            subject_blinding_factor,
            "subject_blinding_factor",
        )?;
        let credential_id = self.lock_inner()?.store_credential(
            issuer_schema_id,
            subject_blinding_factor,
            genesis_issued_at,
            expires_at,
            credential_blob,
            associated_data,
            now,
        )?;
        Ok(credential_id)
    }

    /// Fetches a cached Merkle proof if it remains valid beyond `valid_before`.
    ///
    /// # Errors
    ///
    /// Returns an error if the cache lookup fails.
    pub fn merkle_cache_get(
        &self,
        registry_kind: u8,
        root: Vec<u8>,
        valid_before: u64,
    ) -> StorageResult<Option<Vec<u8>>> {
        let root = parse_fixed_bytes::<32>(root, "root")?;
        self.lock_inner()?
            .merkle_cache_get(registry_kind, root, valid_before)
    }

    /// Inserts a cached Merkle proof with a TTL.
    ///
    /// # Errors
    ///
    /// Returns an error if the cache insert fails.
    pub fn merkle_cache_put(
        &self,
        registry_kind: u8,
        root: Vec<u8>,
        proof_bytes: Vec<u8>,
        now: u64,
        ttl_seconds: u64,
    ) -> StorageResult<()> {
        let root = parse_fixed_bytes::<32>(root, "root")?;
        self.lock_inner()?.merkle_cache_put(
            registry_kind,
            root,
            proof_bytes,
            now,
            ttl_seconds,
        )
    }
}

fn parse_fixed_bytes<const N: usize>(
    bytes: Vec<u8>,
    label: &str,
) -> StorageResult<[u8; N]> {
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        StorageError::Serialization(format!(
            "{label} length mismatch: expected {N}, got {}",
            bytes.len()
        ))
    })
}

impl CredentialStore {
    fn lock_inner(
        &self,
    ) -> StorageResult<std::sync::MutexGuard<'_, CredentialStoreInner>> {
        self.inner
            .lock()
            .map_err(|_| StorageError::Lock("storage mutex poisoned".to_string()))
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

    #[allow(clippy::too_many_arguments)]
    fn store_credential(
        &mut self,
        issuer_schema_id: u64,
        subject_blinding_factor: [u8; 32],
        genesis_issued_at: u64,
        expires_at: u64,
        credential_blob: Vec<u8>,
        associated_data: Option<Vec<u8>>,
        now: u64,
    ) -> StorageResult<u64> {
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

    fn merkle_cache_get(
        &self,
        registry_kind: u8,
        root: [u8; 32],
        valid_before: u64,
    ) -> StorageResult<Option<Vec<u8>>> {
        let state = self.state()?;
        state.cache.merkle_cache_get(
            registry_kind,
            root,
            state.leaf_index,
            valid_before,
        )
    }

    fn merkle_cache_put(
        &mut self,
        registry_kind: u8,
        root: [u8; 32],
        proof_bytes: Vec<u8>,
        now: u64,
        ttl_seconds: u64,
    ) -> StorageResult<()> {
        let guard = self.guard()?;
        let state = self.state_mut()?;
        state.cache.merkle_cache_put(
            &guard,
            registry_kind,
            root,
            state.leaf_index,
            proof_bytes,
            now,
            ttl_seconds,
        )
    }

    /// Checks whether a replay guard entry exists for the given nullifier.
    ///
    /// # Returns
    /// - bool: true if a replay guard entry exists (hence signalling a nullifier replay), false otherwise.
    ///
    /// # Errors
    ///
    /// Returns an error if the query to the cache unexpectedly fails.
    #[allow(dead_code)] // TODO: Once it gets used
    fn replay_guard_get(
        &self,
        nullifier: FieldElement,
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
        state.cache.replay_guard_get(nullifier_bytes, now)
    }

    /// After a proof has been successfully generated, creates a replay guard entry
    /// locally to avoid future replays of the same nullifier.
    ///
    /// # Errors
    ///
    /// Returns an error if the query to the cache unexpectedly fails.
    #[allow(dead_code)] // TODO: Once it gets used
    fn replay_guard_set(
        &mut self,
        nullifier: FieldElement,
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
    use crate::storage::tests_utils::InMemoryStorageProvider;
    use std::fs;
    use std::path::{Path, PathBuf};
    use uuid::Uuid;
    use world_id_core::FieldElement;

    fn temp_root() -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!("walletkit-replay-guard-{}", Uuid::new_v4()));
        path
    }

    fn cleanup_storage(root: &Path) {
        let paths = StoragePaths::new(root);
        let vault = paths.vault_db_path();
        let cache = paths.cache_db_path();
        let lock = paths.lock_path();
        let _ = fs::remove_file(&vault);
        let _ = fs::remove_file(vault.with_extension("sqlite-wal"));
        let _ = fs::remove_file(vault.with_extension("sqlite-shm"));
        let _ = fs::remove_file(&cache);
        let _ = fs::remove_file(cache.with_extension("sqlite-wal"));
        let _ = fs::remove_file(cache.with_extension("sqlite-shm"));
        let _ = fs::remove_file(lock);
        let _ = fs::remove_dir_all(paths.worldid_dir());
        let _ = fs::remove_dir_all(paths.root());
    }

    #[test]
    fn test_replay_guard_field_element_serialization() {
        let root = temp_root();
        let provider = InMemoryStorageProvider::new(&root);
        let paths = provider.paths().as_ref().clone();
        let keystore = provider.keystore();
        let blob_store = provider.blob_store();

        let mut inner = CredentialStoreInner::new(paths, keystore, blob_store)
            .expect("create inner");
        inner.init(42, 1000).expect("init storage");

        // Create a FieldElement from a known value
        let nullifier = FieldElement::from(123_456_789u64);

        // Set a replay guard
        inner
            .replay_guard_set(nullifier, 1000)
            .expect("set replay guard");

        // The same FieldElement should be properly serialized and found after the grace period
        let exists_after_grace = inner
            .replay_guard_get(nullifier, 1601)
            .expect("check replay guard");
        assert!(
            exists_after_grace,
            "Replay guard should exist after grace period (10 minutes)"
        );

        cleanup_storage(&root);
    }

    #[test]
    fn test_replay_guard_grace_period() {
        let root = temp_root();
        let provider = InMemoryStorageProvider::new(&root);
        let paths = provider.paths().as_ref().clone();
        let keystore = provider.keystore();
        let blob_store = provider.blob_store();

        let mut inner = CredentialStoreInner::new(paths, keystore, blob_store)
            .expect("create inner");
        inner.init(42, 1000).expect("init storage");

        let nullifier = FieldElement::from(999u64);
        let set_time = 1000u64;

        // Set a replay guard at time 1000
        inner
            .replay_guard_set(nullifier, set_time)
            .expect("set replay guard");

        // Within grace period (< 10 minutes): should return false
        // Grace period is 600 seconds (10 minutes)
        let check_time_1min = set_time + 60; // 1 minute later
        let exists_1min = inner
            .replay_guard_get(nullifier, check_time_1min)
            .expect("check at 1 minute");
        assert!(
            !exists_1min,
            "Replay guard should NOT be enforced during grace period (1 minute)"
        );

        let check_time_ten_min = set_time + 601; // 10 minutes later
        let exists_ten_min = inner
            .replay_guard_get(nullifier, check_time_ten_min)
            .expect("check at 9 minutes");
        assert!(
            exists_ten_min,
            "Replay guard should be enforced during grace period (10 minutes)"
        );

        cleanup_storage(&root);
    }

    #[test]
    fn test_replay_guard_expiration() {
        let root = temp_root();
        let provider = InMemoryStorageProvider::new(&root);
        let paths = provider.paths().as_ref().clone();
        let keystore = provider.keystore();
        let blob_store = provider.blob_store();

        let mut inner = CredentialStoreInner::new(paths, keystore, blob_store)
            .expect("create inner");
        inner.init(42, 1000).expect("init storage");

        let nullifier = FieldElement::from(555u64);
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
            .replay_guard_get(nullifier, check_time_before_exp)
            .expect("check before expiration");
        assert!(
            exists_before_exp,
            "Replay guard SHOULD exist just before expiration"
        );

        // After expiration: should not exist
        let check_time_at_exp = set_time + one_year_seconds + 1;
        let exists_at_exp = inner
            .replay_guard_get(nullifier, check_time_at_exp)
            .expect("check at expiration");
        assert!(
            !exists_at_exp,
            "Replay guard should NOT exist at expiration (1 year)"
        );

        cleanup_storage(&root);
    }

    #[test]
    fn test_replay_guard_idempotency() {
        let root = temp_root();
        let provider = InMemoryStorageProvider::new(&root);
        let paths = provider.paths().as_ref().clone();
        let keystore = provider.keystore();
        let blob_store = provider.blob_store();

        let mut inner = CredentialStoreInner::new(paths, keystore, blob_store).unwrap();
        inner.init(42, 1000).expect("init storage");

        let nullifier = FieldElement::from(12345u64);
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
            .replay_guard_get(nullifier, check_time_after_grace)
            .expect("check after grace");
        assert!(
            exists_after_grace,
            "Replay guard SHOULD be enforced - past grace period from FIRST insertion"
        );

        cleanup_storage(&root);
    }
}
