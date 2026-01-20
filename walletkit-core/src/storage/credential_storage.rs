//! Storage facade implementing the credential storage API.

use std::sync::Arc;

use super::error::{StorageError, StorageResult};
use super::keys::StorageKeys;
use super::lock::{StorageLock, StorageLockGuard};
use super::paths::StoragePaths;
use super::traits::StorageProvider;
use super::traits::{AtomicBlobStore, DeviceKeystore};
use super::types::{
    CredentialId, CredentialRecord, CredentialStatus, Nullifier, ProofDisclosureResult,
    RequestId,
};
use super::{CacheDb, VaultDb};

/// Public-facing storage API used by WalletKit v4 flows.
pub trait CredentialStorage {
    /// Initializes storage and validates the account leaf index.
    fn init(&mut self, leaf_index: u64, now: u64) -> StorageResult<()>;

    /// Lists active credentials, optionally filtered by issuer schema ID.
    fn list_credentials(
        &self,
        issuer_schema_id: Option<u64>,
        now: u64,
    ) -> StorageResult<Vec<CredentialRecord>>;

    /// Stores a credential and optional associated data.
    #[allow(clippy::too_many_arguments)]
    fn store_credential(
        &mut self,
        issuer_schema_id: u64,
        status: CredentialStatus,
        subject_blinding_factor: [u8; 32],
        genesis_issued_at: u64,
        expires_at: Option<u64>,
        credential_blob: Vec<u8>,
        associated_data: Option<Vec<u8>>,
        now: u64,
    ) -> StorageResult<CredentialId>;

    /// Fetches a cached Merkle proof if available.
    fn merkle_cache_get(
        &self,
        registry_kind: u8,
        root: [u8; 32],
        now: u64,
    ) -> StorageResult<Option<Vec<u8>>>;

    /// Inserts a cached Merkle proof with a TTL.
    fn merkle_cache_put(
        &mut self,
        registry_kind: u8,
        root: [u8; 32],
        proof_bytes: Vec<u8>,
        now: u64,
        ttl_seconds: u64,
    ) -> StorageResult<()>;

    /// Enforces replay safety for proof disclosure.
    fn begin_proof_disclosure(
        &mut self,
        request_id: RequestId,
        nullifier: Nullifier,
        proof_bytes: Vec<u8>,
        now: u64,
        ttl_seconds: u64,
    ) -> StorageResult<ProofDisclosureResult>;
}

/// Concrete storage implementation backed by SQLCipher databases.
pub struct CredentialStore {
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

impl CredentialStore {
    /// Creates a new storage handle from a platform provider.
    ///
    /// # Errors
    ///
    /// Returns an error if the storage lock cannot be opened.
    pub fn from_provider(provider: &dyn StorageProvider) -> StorageResult<Self> {
        Self::new(provider.paths(), provider.keystore(), provider.blob_store())
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

    /// Returns the storage paths used by this handle.
    #[must_use]
    pub fn paths(&self) -> &StoragePaths {
        &self.paths
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

impl CredentialStorage for CredentialStore {
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
        status: CredentialStatus,
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
            status,
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
        now: u64,
    ) -> StorageResult<Option<Vec<u8>>> {
        let state = self.state()?;
        state
            .cache
            .merkle_cache_get(registry_kind, root, state.leaf_index, now)
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

    fn begin_proof_disclosure(
        &mut self,
        request_id: RequestId,
        nullifier: Nullifier,
        proof_bytes: Vec<u8>,
        now: u64,
        ttl_seconds: u64,
    ) -> StorageResult<ProofDisclosureResult> {
        let guard = self.guard()?;
        let state = self.state_mut()?;
        state.cache.begin_proof_disclosure(
            &guard,
            request_id,
            nullifier,
            proof_bytes,
            now,
            ttl_seconds,
        )
    }
}
