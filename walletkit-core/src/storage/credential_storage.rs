//! Storage facade implementing the credential storage API.

use std::sync::{Arc, Mutex};

use super::error::{StorageError, StorageResult};
use super::keys::StorageKeys;
use super::lock::{StorageLock, StorageLockGuard};
use super::paths::StoragePaths;
use super::traits::StorageProvider;
use super::traits::{AtomicBlobStore, DeviceKeystore};
use super::types::{
    CredentialId, CredentialRecord, CredentialRecordFfi, Nullifier,
    ReplayGuardResult, ReplayGuardResultFfi, RequestId,
};
use super::{CacheDb, VaultDb};

/// Public-facing storage API used by `WalletKit` v4 flows.
pub trait CredentialStorage {
    /// Initializes storage and validates the account leaf index.
    ///
    /// Loads or creates the account key envelope, opens the vault/cache, and
    /// ensures the stored leaf index matches the provided value.
    ///
    /// # Errors
    ///
    /// Returns an error if storage initialization fails or the leaf index is invalid.
    fn init(&mut self, leaf_index: u64, now: u64) -> StorageResult<()>;

    /// Lists active credential metadata, optionally filtered by issuer schema ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the credential query fails.
    fn list_credentials(
        &self,
        issuer_schema_id: Option<u64>,
        now: u64,
    ) -> StorageResult<Vec<CredentialRecord>>;

    /// Stores a credential and optional associated data.
    ///
    /// # Errors
    ///
    /// Returns an error if the credential cannot be stored.
    #[allow(clippy::too_many_arguments)]
    fn store_credential(
        &mut self,
        issuer_schema_id: u64,
        subject_blinding_factor: [u8; 32],
        genesis_issued_at: u64,
        expires_at: Option<u64>,
        credential_blob: Vec<u8>,
        associated_data: Option<Vec<u8>>,
        now: u64,
    ) -> StorageResult<CredentialId>;

    /// Fetches a cached Merkle proof if it remains valid beyond `valid_before`.
    ///
    /// # Errors
    ///
    /// Returns an error if the cache lookup fails.
    fn merkle_cache_get(
        &self,
        registry_kind: u8,
        root: [u8; 32],
        valid_before: u64,
    ) -> StorageResult<Option<Vec<u8>>>;

    /// Inserts a cached Merkle proof with a TTL.
    ///
    /// # Errors
    ///
    /// Returns an error if the cache insert fails.
    fn merkle_cache_put(
        &mut self,
        registry_kind: u8,
        root: [u8; 32],
        proof_bytes: Vec<u8>,
        now: u64,
        ttl_seconds: u64,
    ) -> StorageResult<()>;

    /// Checks for a prior replay guard entry by request id.
    ///
    /// # Errors
    ///
    /// Returns an error if the cache lookup fails.
    fn replay_guard_get(
        &self,
        request_id: RequestId,
        now: u64,
    ) -> StorageResult<Option<Vec<u8>>>;

    /// Enforces replay safety for replay guard.
    ///
    /// Returns the stored proof bytes on replay and rejects nullifier reuse
    /// across different request ids.
    ///
    /// # Errors
    ///
    /// Returns an error if the nullifier is already disclosed or the cache
    /// operation fails.
    fn begin_replay_guard(
        &mut self,
        request_id: RequestId,
        nullifier: Nullifier,
        proof_bytes: Vec<u8>,
        now: u64,
        ttl_seconds: u64,
    ) -> StorageResult<ReplayGuardResult>;
}

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
    ) -> StorageResult<Vec<CredentialRecordFfi>> {
        let records = self.lock_inner()?.list_credentials(issuer_schema_id, now)?;
        Ok(records.into_iter().map(CredentialRecordFfi::from).collect())
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
        expires_at: Option<u64>,
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

    /// Checks for a prior replay guard entry by request id.
    ///
    /// # Errors
    ///
    /// Returns an error if the cache lookup fails.
    pub fn replay_guard_get(
        &self,
        request_id: Vec<u8>,
        now: u64,
    ) -> StorageResult<Option<Vec<u8>>> {
        let request_id = parse_fixed_bytes::<32>(request_id, "request_id")?;
        self.lock_inner()?.replay_guard_get(request_id, now)
    }

    /// Enforces replay safety for replay guard.
    ///
    /// # Errors
    ///
    /// Returns an error if the disclosure conflicts or storage fails.
    pub fn begin_replay_guard(
        &self,
        request_id: Vec<u8>,
        nullifier: Vec<u8>,
        proof_bytes: Vec<u8>,
        now: u64,
        ttl_seconds: u64,
    ) -> StorageResult<ReplayGuardResultFfi> {
        let request_id = parse_fixed_bytes::<32>(request_id, "request_id")?;
        let nullifier = parse_fixed_bytes::<32>(nullifier, "nullifier")?;
        let result = self.lock_inner()?.begin_replay_guard(
            request_id,
            nullifier,
            proof_bytes,
            now,
            ttl_seconds,
        )?;
        Ok(ReplayGuardResultFfi::from(result))
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

impl CredentialStorage for CredentialStoreInner {
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

    fn store_credential(
        &mut self,
        issuer_schema_id: u64,
        subject_blinding_factor: [u8; 32],
        genesis_issued_at: u64,
        expires_at: Option<u64>,
        credential_blob: Vec<u8>,
        associated_data: Option<Vec<u8>>,
        now: u64,
    ) -> StorageResult<CredentialId> {
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
        state
            .cache
            .merkle_cache_get(registry_kind, root, state.leaf_index, valid_before)
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

    fn replay_guard_get(
        &self,
        request_id: RequestId,
        now: u64,
    ) -> StorageResult<Option<Vec<u8>>> {
        let state = self.state()?;
        state.cache.replay_guard_get(request_id, now)
    }

    fn begin_replay_guard(
        &mut self,
        request_id: RequestId,
        nullifier: Nullifier,
        proof_bytes: Vec<u8>,
        now: u64,
        ttl_seconds: u64,
    ) -> StorageResult<ReplayGuardResult> {
        let guard = self.guard()?;
        let state = self.state_mut()?;
        state.cache.begin_replay_guard(
            &guard,
            request_id,
            nullifier,
            proof_bytes,
            now,
            ttl_seconds,
        )
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

impl CredentialStorage for CredentialStore {
    fn init(&mut self, leaf_index: u64, now: u64) -> StorageResult<()> {
        let mut inner = self.lock_inner()?;
        inner.init(leaf_index, now)
    }

    fn list_credentials(
        &self,
        issuer_schema_id: Option<u64>,
        now: u64,
    ) -> StorageResult<Vec<CredentialRecord>> {
        let inner = self.lock_inner()?;
        inner.list_credentials(issuer_schema_id, now)
    }

    #[allow(clippy::too_many_arguments)]
    fn store_credential(
        &mut self,
        issuer_schema_id: u64,
        subject_blinding_factor: [u8; 32],
        genesis_issued_at: u64,
        expires_at: Option<u64>,
        credential_blob: Vec<u8>,
        associated_data: Option<Vec<u8>>,
        now: u64,
    ) -> StorageResult<CredentialId> {
        let mut inner = self.lock_inner()?;
        inner.store_credential(
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
        let inner = self.lock_inner()?;
        inner.merkle_cache_get(registry_kind, root, valid_before)
    }

    fn merkle_cache_put(
        &mut self,
        registry_kind: u8,
        root: [u8; 32],
        proof_bytes: Vec<u8>,
        now: u64,
        ttl_seconds: u64,
    ) -> StorageResult<()> {
        let mut inner = self.lock_inner()?;
        inner.merkle_cache_put(registry_kind, root, proof_bytes, now, ttl_seconds)
    }

    fn replay_guard_get(
        &self,
        request_id: RequestId,
        now: u64,
    ) -> StorageResult<Option<Vec<u8>>> {
        let inner = self.lock_inner()?;
        inner.replay_guard_get(request_id, now)
    }

    fn begin_replay_guard(
        &mut self,
        request_id: RequestId,
        nullifier: Nullifier,
        proof_bytes: Vec<u8>,
        now: u64,
        ttl_seconds: u64,
    ) -> StorageResult<ReplayGuardResult> {
        let mut inner = self.lock_inner()?;
        inner.begin_replay_guard(
            request_id,
            nullifier,
            proof_bytes,
            now,
            ttl_seconds,
        )
    }
}
