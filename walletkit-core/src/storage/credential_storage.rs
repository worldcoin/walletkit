//! Storage facade implementing the credential storage API.

use std::sync::{Arc, Mutex};

use world_id_core::FieldElement as CoreFieldElement;

use super::error::{StorageError, StorageResult};
use super::keys::StorageKeys;
use super::lock::{StorageLock, StorageLockGuard};
use super::paths::StoragePaths;
use super::traits::StorageProvider;
use super::traits::{AtomicBlobStore, DeviceKeystore, WalletKitBackupManager};
use super::types::CredentialRecord;
use super::{CacheDb, VaultDb};
use crate::{Credential, FieldElement};

/// No-op backup manager used as the default before the host app registers
/// a real implementation. All methods are no-ops.
struct NoopBackupManager;

impl WalletKitBackupManager for NoopBackupManager {
    fn dest_dir(&self) -> String {
        String::new()
    }

    fn on_vault_changed(&self, _vault_file_path: String) -> StorageResult<()> {
        Ok(())
    }
}

/// Concrete storage implementation backed by `SQLCipher` databases.
#[cfg_attr(not(target_arch = "wasm32"), derive(uniffi::Object))]
pub struct CredentialStore {
    inner: Mutex<CredentialStoreInner>,
    /// Holds the active backup manager. Defaults to [`NoopBackupManager`].
    /// The lock is held for the entire export+callback path inside
    /// `notify_vault_changed`, which serializes concurrent notifications
    /// so that backups are always delivered in mutation order.
    backup: Mutex<Arc<dyn WalletKitBackupManager>>,
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

#[cfg_attr(not(target_arch = "wasm32"), uniffi::export)]
impl CredentialStore {
    /// Creates a new storage handle from explicit components.
    ///
    /// # Errors
    ///
    /// Returns an error if the storage lock cannot be opened.
    #[cfg_attr(not(target_arch = "wasm32"), uniffi::constructor)]
    pub fn new_with_components(
        paths: Arc<StoragePaths>,
        keystore: Arc<dyn DeviceKeystore>,
        blob_store: Arc<dyn AtomicBlobStore>,
    ) -> StorageResult<Self> {
        let paths = Arc::try_unwrap(paths).unwrap_or_else(|arc| (*arc).clone());
        let inner = CredentialStoreInner::new(paths, keystore, blob_store)?;
        Ok(Self {
            inner: Mutex::new(inner),
            backup: Mutex::new(Arc::new(NoopBackupManager)),
        })
    }

    /// Creates a new storage handle from a platform provider.
    ///
    /// # Errors
    ///
    /// Returns an error if the storage lock cannot be opened.
    #[cfg_attr(not(target_arch = "wasm32"), uniffi::constructor)]
    #[allow(clippy::needless_pass_by_value)]
    pub fn from_provider_arc(
        provider: Arc<dyn StorageProvider>,
    ) -> StorageResult<Self> {
        let inner = CredentialStoreInner::from_provider(provider.as_ref())?;
        Ok(Self {
            inner: Mutex::new(inner),
            backup: Mutex::new(Arc::new(NoopBackupManager)),
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

    /// Lists credential metadata, optionally filtered by issuer schema ID.
    ///
    /// Results include both active and expired credentials. Expiry status is
    /// reported via [`CredentialRecord::is_expired`].
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

    /// Deletes a credential by ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the delete operation fails or the credential ID does
    /// not exist.
    pub fn delete_credential(&self, credential_id: u64) -> StorageResult<()> {
        self.lock_inner()?.delete_credential(credential_id)?;
        self.notify_vault_changed();
        Ok(())
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
        let id = self.lock_inner()?.store_credential(
            credential,
            blinding_factor,
            expires_at,
            associated_data,
            now,
        )?;
        self.notify_vault_changed();
        Ok(id)
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

    /// Exports a plaintext (unencrypted) copy of the vault for backup.
    ///
    /// The returned path points to a transient file containing the full vault
    /// schema and data without the `sqlite3mc` encryption layer. The caller
    /// is responsible for deleting the file after use.
    ///
    /// **Note:** when a [`WalletKitBackupManager`] is registered, vault
    /// mutations call this internally and delete the file automatically after
    /// the callback returns. This public method is for manual / one-off exports.
    ///
    /// `dest_dir` is the directory where the plaintext backup file will be
    /// written.
    ///
    /// # Errors
    ///
    /// Returns an error if the store is not initialized or the export fails.
    #[expect(
        clippy::needless_pass_by_value,
        reason = "non-owned strings cannot be lifted via UniFFI"
    )]
    pub fn export_vault_for_backup(&self, dest_dir: String) -> StorageResult<String> {
        self.lock_inner()?.export_vault_for_backup(&dest_dir)
    }

    /// Imports credentials from a plaintext vault backup produced by
    /// [`export_vault_for_backup`](Self::export_vault_for_backup).
    ///
    /// The store must already be initialized via [`init`](Self::init).
    /// Intended for restore on a fresh install where the vault is empty.
    /// The caller is responsible for deleting the source file after the
    /// import completes.
    ///
    /// # Errors
    ///
    /// Returns an error if the store is not initialized or the import fails.
    #[expect(
        clippy::needless_pass_by_value,
        reason = "non-owned strings cannot be lifted via UniFFI"
    )]
    pub fn import_vault_from_backup(&self, backup_path: String) -> StorageResult<()> {
        self.lock_inner()?.import_vault_from_backup(&backup_path)
    }

    /// **Development only.** Permanently deletes all stored credentials and their
    /// associated blob data from the vault.
    ///
    /// This is a destructive, unrecoverable operation intended for use in
    /// development and testing environments only. Do not call this in production.
    ///
    /// Preserves storage metadata (leaf index, schema version), so the store
    /// remains initialized and ready to accept new credentials after the call.
    ///
    /// # Returns
    ///
    /// The number of credentials deleted.
    ///
    /// # Errors
    ///
    /// Returns an error if the delete operation fails.
    pub fn danger_delete_all_credentials(&self) -> StorageResult<u64> {
        let mut inner = self.lock_inner()?;
        let count = inner.danger_delete_all_credentials()?;
        drop(inner);
        if count > 0 {
            self.notify_vault_changed();
        }
        Ok(count)
    }

    /// Registers a backup manager that will be notified after vault mutations
    /// ([`store_credential`](Self::store_credential),
    /// [`danger_delete_all_credentials`](Self::danger_delete_all_credentials)).
    /// Backup failures are logged but do not affect the mutation result.
    ///
    /// # Errors
    ///
    /// Returns an error if the backup mutex is poisoned.
    pub fn set_backup_manager(
        &self,
        manager: Arc<dyn WalletKitBackupManager>,
    ) -> StorageResult<()> {
        *self.backup.lock().map_err(|_| {
            StorageError::Lock("backup config mutex poisoned".to_string())
        })? = manager;
        Ok(())
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

    /// Best-effort export + notification to the backup manager, if one is set.
    ///
    /// Called after any vault mutation (store, delete) so the host app can
    /// sync the updated vault to its backup. Failures are logged but never
    /// propagated — the vault mutation has already succeeded and callers
    /// should not see an error from a backup side-effect.
    fn notify_vault_changed(&self) {
        // Hold the backup lock for the entire export+callback path. This
        // serializes concurrent notifications so backups are delivered in
        // mutation order. Recover the guard on poison — the manager is
        // still valid after a prior panic.
        let guard = self
            .backup
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let dest_dir = guard.dest_dir();
        if dest_dir.is_empty() {
            return; // NoopBackupManager — nothing to do.
        }

        // Export a plaintext snapshot of the vault. The file is sensitive
        // (unencrypted), so we wrap it in a guard that deletes it on drop —
        // no matter how we exit (normal return, early return, or panic).
        let vault_path = match self
            .lock_inner()
            .and_then(|inner| inner.export_vault_for_backup(&dest_dir))
        {
            Ok(path) => path,
            Err(e) => {
                tracing::error!("Failed to export vault for backup: {e}");
                return;
            }
        };

        let _cleanup = {
            struct CleanupFile(String);
            impl Drop for CleanupFile {
                fn drop(&mut self) {
                    if let Err(e) = std::fs::remove_file(&self.0) {
                        tracing::error!(
                            "Failed to delete plaintext vault backup {}: {e}",
                            self.0
                        );
                    }
                }
            }
            CleanupFile(vault_path.clone())
        };

        // Hand the path to the host app (e.g. iOS) so it can copy/upload
        // the vault to Bedrock. The host must finish with the file during
        // this synchronous call — the guard deletes it on return.
        if let Err(e) = guard.on_vault_changed(vault_path) {
            tracing::error!("Backup manager on_vault_changed failed: {e}");
        }
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
        let k_intermediate = keys.intermediate_key();
        let vault = VaultDb::new(&self.paths.vault_db_path(), &k_intermediate, &guard)?;
        let cache = CacheDb::new(&self.paths.cache_db_path(), &k_intermediate, &guard)?;
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

    fn delete_credential(&mut self, credential_id: u64) -> StorageResult<()> {
        let guard = self.guard()?;
        let state = self.state_mut()?;
        state.vault.delete_credential(&guard, credential_id)
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

            let blinding_factor = CoreFieldElement::from_be_bytes(
                &blinding_factor_bytes.try_into().map_err(|_| {
                    StorageError::Serialization(
                        "Critical. Blinding factor has invalid length".to_string(),
                    )
                })?,
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
        let subject_blinding_factor = blinding_factor.to_bytes();

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
        let nullifier = nullifier.to_be_bytes();
        let state = self.state()?;
        state.cache.is_nullifier_replay(nullifier, now)
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
        let nullifier = nullifier.to_be_bytes();
        let state = self.state_mut()?;
        state.cache.replay_guard_set(&guard, nullifier, now)
    }

    fn export_vault_for_backup(&self, dest_dir: &str) -> StorageResult<String> {
        let guard = self.guard()?;
        let state = self.state()?;
        // Use a unique filename per export so that concurrent calls to
        // `notify_vault_changed` don't race on the same file — one thread's
        // callback could still be reading while another overwrites or deletes.
        let filename =
            format!("vault_backup_plaintext_{}.sqlite", uuid::Uuid::new_v4());
        let dest = std::path::PathBuf::from(dest_dir).join(filename);
        state.vault.export_plaintext(&dest, &guard)?;
        Ok(dest.to_string_lossy().to_string())
    }

    fn import_vault_from_backup(&self, backup_path: &str) -> StorageResult<()> {
        let guard = self.guard()?;
        let state = self.state()?;
        let source = std::path::Path::new(backup_path);
        state.vault.import_plaintext(source, &guard)
    }

    /// Deletes all stored credentials from the vault.
    ///
    /// # Errors
    ///
    /// Returns an error if the delete operation fails.
    fn danger_delete_all_credentials(&mut self) -> StorageResult<u64> {
        let guard = self.guard()?;
        let state = self.state_mut()?;
        state.vault.danger_delete_all_credentials(&guard)
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
            backup: Mutex::new(Arc::new(NoopBackupManager)),
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
            backup: Mutex::new(Arc::new(NoopBackupManager)),
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
    use std::path::PathBuf;

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
    fn test_export_and_import_vault_backup() {
        use world_id_core::Credential as CoreCredential;

        // --- Source store: create and populate ---
        let src_root = temp_root_path();
        let src_provider = InMemoryStorageProvider::new(&src_root);
        let src_paths = src_provider.paths().as_ref().clone();
        let src_keystore = src_provider.keystore();
        let src_blob_store = src_provider.blob_store();

        let mut src_inner =
            CredentialStoreInner::new(src_paths, src_keystore, src_blob_store)
                .expect("create src inner");
        src_inner.init(42, 1000).expect("init src storage");

        let issuer_schema_id = 100u64;
        let blinding_factor = FieldElement::from(7u64);
        let expires_at = 9999u64;
        let core_cred = CoreCredential::new()
            .issuer_schema_id(issuer_schema_id)
            .genesis_issued_at(1000);
        let credential: Credential = core_cred.into();

        // Store a credential in the source store
        src_inner
            .store_credential(&credential, &blinding_factor, expires_at, None, 1000)
            .expect("store credential");

        // Export plaintext vault to a separate directory
        let export_dir = temp_root_path();
        std::fs::create_dir_all(&export_dir).expect("create export dir");
        let export_dir_str = export_dir.to_string_lossy().to_string();
        let backup_path = src_inner
            .export_vault_for_backup(&export_dir_str)
            .expect("export vault");

        // Verify the export file exists
        assert!(
            std::path::Path::new(&backup_path).exists(),
            "backup file should exist on disk"
        );

        // --- Destination store: create empty, then import ---
        let dst_root = temp_root_path();
        let dst_provider = InMemoryStorageProvider::new(&dst_root);
        let dst_paths = dst_provider.paths().as_ref().clone();
        let dst_keystore = dst_provider.keystore();
        let dst_blob_store = dst_provider.blob_store();

        let mut dst_inner =
            CredentialStoreInner::new(dst_paths, dst_keystore, dst_blob_store)
                .expect("create dst inner");
        dst_inner.init(42, 1000).expect("init dst storage");

        // Import from the backup
        dst_inner
            .import_vault_from_backup(&backup_path)
            .expect("import vault");

        // Verify credential data matches what was stored
        let (imported_cred, imported_bf) = dst_inner
            .get_credential(issuer_schema_id, 1000)
            .expect("get credential")
            .expect("imported credential should exist");
        assert_eq!(imported_cred.issuer_schema_id(), issuer_schema_id);
        assert_eq!(imported_bf.to_bytes(), blinding_factor.to_bytes());

        // Clean up
        std::fs::remove_file(&backup_path).ok();
        cleanup_test_storage(&src_root);
        cleanup_test_storage(&export_dir);
        cleanup_test_storage(&dst_root);
    }

    #[test]
    fn test_export_and_import_multiple_credentials_with_associated_data() {
        use world_id_core::Credential as CoreCredential;

        let src_root = temp_root_path();
        let src_provider = InMemoryStorageProvider::new(&src_root);
        let src_paths = src_provider.paths().as_ref().clone();
        let mut src_inner = CredentialStoreInner::new(
            src_paths,
            src_provider.keystore(),
            src_provider.blob_store(),
        )
        .expect("create src inner");
        src_inner.init(42, 1000).expect("init src storage");

        // Store credential A (schema 100) without associated data
        let cred_a: Credential = CoreCredential::new()
            .issuer_schema_id(100)
            .genesis_issued_at(1000)
            .into();
        src_inner
            .store_credential(&cred_a, &FieldElement::from(7u64), 9999, None, 1000)
            .expect("store cred A");

        // Store credential B (schema 200) with associated data
        let cred_b: Credential = CoreCredential::new()
            .issuer_schema_id(200)
            .genesis_issued_at(2000)
            .into();
        let associated_data = b"extra-payload-for-cred-b".to_vec();
        src_inner
            .store_credential(
                &cred_b,
                &FieldElement::from(13u64),
                9999,
                Some(associated_data),
                2000,
            )
            .expect("store cred B");

        // Store credential C (schema 300) without associated data
        let cred_c: Credential = CoreCredential::new()
            .issuer_schema_id(300)
            .genesis_issued_at(3000)
            .into();
        src_inner
            .store_credential(&cred_c, &FieldElement::from(42u64), 9999, None, 3000)
            .expect("store cred C");

        // Verify source has 3 credentials
        let src_list = src_inner.list_credentials(None, 1000).expect("list src");
        assert_eq!(src_list.len(), 3);

        // Export and import into fresh store
        let export_dir = temp_root_path();
        std::fs::create_dir_all(&export_dir).expect("create export dir");
        let export_dir_str = export_dir.to_string_lossy().to_string();
        let backup_path = src_inner
            .export_vault_for_backup(&export_dir_str)
            .expect("export vault");

        let dst_root = temp_root_path();
        let dst_provider = InMemoryStorageProvider::new(&dst_root);
        let dst_paths = dst_provider.paths().as_ref().clone();
        let mut dst_inner = CredentialStoreInner::new(
            dst_paths,
            dst_provider.keystore(),
            dst_provider.blob_store(),
        )
        .expect("create dst inner");
        dst_inner.init(42, 1000).expect("init dst storage");

        dst_inner
            .import_vault_from_backup(&backup_path)
            .expect("import vault");

        // Verify all 3 credentials were imported
        let dst_list = dst_inner.list_credentials(None, 1000).expect("list dst");
        assert_eq!(dst_list.len(), 3);

        // Verify credential data matches what was stored
        let (cred_a, bf_a) = dst_inner
            .get_credential(100, 1000)
            .expect("get cred A")
            .expect("cred A should exist");
        assert_eq!(cred_a.issuer_schema_id(), 100);
        assert_eq!(bf_a.to_bytes(), FieldElement::from(7u64).to_bytes());

        let (cred_b, bf_b) = dst_inner
            .get_credential(200, 2000)
            .expect("get cred B")
            .expect("cred B should exist");
        assert_eq!(cred_b.issuer_schema_id(), 200);
        assert_eq!(bf_b.to_bytes(), FieldElement::from(13u64).to_bytes());

        let (cred_c, bf_c) = dst_inner
            .get_credential(300, 3000)
            .expect("get cred C")
            .expect("cred C should exist");
        assert_eq!(cred_c.issuer_schema_id(), 300);
        assert_eq!(bf_c.to_bytes(), FieldElement::from(42u64).to_bytes());

        // Clean up
        std::fs::remove_file(&backup_path).ok();
        cleanup_test_storage(&src_root);
        cleanup_test_storage(&export_dir);
        cleanup_test_storage(&dst_root);
    }

    #[test]
    fn test_import_vault_backup_into_non_empty_vault_fails() {
        use world_id_core::Credential as CoreCredential;

        let root = temp_root_path();
        let provider = InMemoryStorageProvider::new(&root);
        let paths = provider.paths().as_ref().clone();
        let keystore = provider.keystore();
        let blob_store = provider.blob_store();

        let mut inner = CredentialStoreInner::new(paths, keystore, blob_store)
            .expect("create inner");
        inner.init(42, 1000).expect("init storage");

        let blinding_factor = FieldElement::from(7u64);
        let core_cred = CoreCredential::new()
            .issuer_schema_id(100u64)
            .genesis_issued_at(1000);
        let credential: Credential = core_cred.into();

        inner
            .store_credential(&credential, &blinding_factor, 9999, None, 1000)
            .expect("store credential");

        // Export the vault
        let export_dir = temp_root_path();
        std::fs::create_dir_all(&export_dir).expect("create export dir");
        let export_dir_str = export_dir.to_string_lossy().to_string();
        let backup_path = inner
            .export_vault_for_backup(&export_dir_str)
            .expect("export vault");

        // Importing into a non-empty vault should fail — the import checks that
        // destination tables are empty before inserting.
        let result = inner.import_vault_from_backup(&backup_path);
        assert!(result.is_err(), "import into non-empty vault should fail");

        // Verify existing data is unchanged after the failed import.
        let (cred, bf) = inner
            .get_credential(100, 1000)
            .expect("get credential after failed import")
            .expect("credential should still exist");
        assert_eq!(cred.issuer_schema_id(), 100);
        assert_eq!(bf.to_bytes(), blinding_factor.to_bytes());

        std::fs::remove_file(&backup_path).ok();
        cleanup_test_storage(&root);
        cleanup_test_storage(&export_dir);
    }

    #[test]
    fn test_import_vault_backup_missing_file_fails() {
        let root = temp_root_path();
        let provider = InMemoryStorageProvider::new(&root);
        let paths = provider.paths().as_ref().clone();
        let keystore = provider.keystore();
        let blob_store = provider.blob_store();

        let mut inner = CredentialStoreInner::new(paths, keystore, blob_store)
            .expect("create inner");
        inner.init(42, 1000).expect("init storage");

        let result = inner.import_vault_from_backup("/nonexistent/path/vault.sqlite");
        assert!(result.is_err(), "import from missing file should fail");

        cleanup_test_storage(&root);
    }

    #[test]
    fn test_import_vault_backup_transaction_atomicity() {
        use walletkit_db::cipher::BACKUP_TABLES;
        use walletkit_db::Connection;
        use world_id_core::Credential as CoreCredential;

        let root = temp_root_path();
        let provider = InMemoryStorageProvider::new(&root);
        let paths = provider.paths().as_ref().clone();
        let keystore = provider.keystore();
        let blob_store = provider.blob_store();

        let mut inner = CredentialStoreInner::new(paths, keystore, blob_store)
            .expect("create inner");
        inner.init(42, 1000).expect("init storage");

        let blinding_factor = FieldElement::from(7u64);
        let core_cred = CoreCredential::new()
            .issuer_schema_id(100u64)
            .genesis_issued_at(1000);
        let credential: Credential = core_cred.into();

        inner
            .store_credential(&credential, &blinding_factor, 9999, None, 1000)
            .expect("store credential");

        // Export a valid backup
        let export_dir = temp_root_path();
        std::fs::create_dir_all(&export_dir).expect("create export dir");
        let export_dir_str = export_dir.to_string_lossy().to_string();
        let backup_path = inner
            .export_vault_for_backup(&export_dir_str)
            .expect("export vault");

        // Corrupt the *last* table in BACKUP_TABLES inside the backup.
        // We target the last table so that earlier tables' INSERTs succeed
        // before this one fails, actually testing transaction rollback.
        // The backup tables have no constraints (CREATE TABLE AS SELECT),
        // so the NULL PK insert succeeds here but will be rejected by the
        // destination's NOT NULL PRIMARY KEY.
        assert_eq!(
            *BACKUP_TABLES.last().unwrap(),
            "blob_objects",
            "update this test if BACKUP_TABLES order changes"
        );
        let backup_conn = Connection::open(std::path::Path::new(&backup_path), false)
            .expect("open backup");
        backup_conn
            .execute(
                "INSERT INTO blob_objects (content_id, blob_kind, created_at, bytes)
                 VALUES (NULL, 1, 2000, X'CAFE')",
                &[],
            )
            .expect("insert corrupt row");
        drop(backup_conn);

        // Create a fresh destination vault and attempt the import
        let dst_root = temp_root_path();
        let dst_provider = InMemoryStorageProvider::new(&dst_root);
        let dst_paths = dst_provider.paths().as_ref().clone();
        let mut dst_inner = CredentialStoreInner::new(
            dst_paths,
            dst_provider.keystore(),
            dst_provider.blob_store(),
        )
        .expect("create dst inner");
        dst_inner.init(42, 1000).expect("init dst storage");

        let result = dst_inner.import_vault_from_backup(&backup_path);
        assert!(result.is_err(), "import with corrupt backup should fail");

        // Verify the destination vault is still empty — the transaction should
        // have rolled back the credential_records INSERT that succeeded before
        // blob_objects failed.
        let dst_list = dst_inner.list_credentials(None, 1000).expect("list dst");
        assert!(
            dst_list.is_empty(),
            "destination should be empty after failed import (transaction rolled back)"
        );

        std::fs::remove_file(&backup_path).ok();
        cleanup_test_storage(&root);
        cleanup_test_storage(&export_dir);
        cleanup_test_storage(&dst_root);
    }

    #[test]
    fn test_danger_delete_all_credentials() {
        use world_id_core::Credential as CoreCredential;

        let root = temp_root_path();
        let provider = InMemoryStorageProvider::new(&root);
        let paths = provider.paths().as_ref().clone();
        let keystore = provider.keystore();
        let blob_store = provider.blob_store();

        let mut inner = CredentialStoreInner::new(paths, keystore, blob_store)
            .expect("create inner");
        inner.init(42, 1000).expect("init storage");

        let blinding_factor = FieldElement::from(42u64);
        for issuer_id in [100u64, 200u64] {
            let cred: Credential = CoreCredential::new()
                .issuer_schema_id(issuer_id)
                .genesis_issued_at(1000)
                .into();
            inner
                .store_credential(&cred, &blinding_factor, 2000, None, 1000)
                .expect("store credential");
        }

        let deleted = inner.danger_delete_all_credentials().expect("delete all");
        assert_eq!(deleted, 2);

        let remaining = inner.list_credentials(None, 1000).expect("list");
        assert!(remaining.is_empty());

        cleanup_test_storage(&root);
    }

    #[test]
    fn test_danger_delete_all_credentials_empty() {
        let root = temp_root_path();
        let provider = InMemoryStorageProvider::new(&root);
        let paths = provider.paths().as_ref().clone();
        let keystore = provider.keystore();
        let blob_store = provider.blob_store();

        let mut inner = CredentialStoreInner::new(paths, keystore, blob_store)
            .expect("create inner");
        inner.init(42, 1000).expect("init storage");

        let deleted = inner
            .danger_delete_all_credentials()
            .expect("delete all on empty");
        assert_eq!(deleted, 0);

        cleanup_test_storage(&root);
    }

    #[test]
    fn test_danger_delete_all_credentials_then_store() {
        use world_id_core::Credential as CoreCredential;

        let root = temp_root_path();
        let provider = InMemoryStorageProvider::new(&root);
        let paths = provider.paths().as_ref().clone();
        let keystore = provider.keystore();
        let blob_store = provider.blob_store();

        let mut inner = CredentialStoreInner::new(paths, keystore, blob_store)
            .expect("create inner");
        inner.init(42, 1000).expect("init storage");

        let blinding_factor = FieldElement::from(42u64);
        let cred: Credential = CoreCredential::new()
            .issuer_schema_id(100u64)
            .genesis_issued_at(1000)
            .into();
        inner
            .store_credential(&cred, &blinding_factor, 2000, None, 1000)
            .expect("store credential");

        inner.danger_delete_all_credentials().expect("delete all");

        let new_cred: Credential = CoreCredential::new()
            .issuer_schema_id(200u64)
            .genesis_issued_at(1000)
            .into();
        inner
            .store_credential(&new_cred, &blinding_factor, 2000, None, 1000)
            .expect("store after delete");

        let list = inner.list_credentials(None, 1000).expect("list");
        assert_eq!(list.len(), 1);

        cleanup_test_storage(&root);
    }

    /// Mock backup manager that records each `on_vault_changed` call and
    /// whether the file existed at the time of the callback.
    struct MockBackupManager {
        export_dir: String,
        calls: Mutex<Vec<(String, bool)>>,
    }

    impl MockBackupManager {
        fn new(export_dir: String) -> Arc<Self> {
            Arc::new(Self {
                export_dir,
                calls: Mutex::new(Vec::new()),
            })
        }

        fn call_count(&self) -> usize {
            self.calls.lock().unwrap().len()
        }

        fn last_path(&self) -> Option<String> {
            self.calls.lock().unwrap().last().map(|(p, _)| p.clone())
        }

        fn last_file_existed(&self) -> bool {
            self.calls.lock().unwrap().last().is_some_and(|(_, e)| *e)
        }
    }

    impl WalletKitBackupManager for MockBackupManager {
        fn dest_dir(&self) -> String {
            self.export_dir.clone()
        }

        fn on_vault_changed(&self, vault_file_path: String) -> StorageResult<()> {
            let existed = std::path::Path::new(&vault_file_path).exists();
            self.calls.lock().unwrap().push((vault_file_path, existed));
            Ok(())
        }
    }

    /// Helper: create an initialized `CredentialStore` with a temp directory
    /// for backup exports.
    fn setup_store_with_backup(
    ) -> (CredentialStore, Arc<MockBackupManager>, PathBuf, PathBuf) {
        let root = temp_root_path();
        let provider = InMemoryStorageProvider::new(&root);
        let store = CredentialStore::from_provider(&provider).expect("create store");
        store.init(42, 1000).expect("init store");

        let export_dir = temp_root_path();
        std::fs::create_dir_all(&export_dir).expect("create export dir");

        let manager = MockBackupManager::new(export_dir.to_string_lossy().to_string());
        store
            .set_backup_manager(manager.clone())
            .expect("set backup manager");

        (store, manager, root, export_dir)
    }

    #[test]
    fn test_store_credential_triggers_backup_notification() {
        use world_id_core::Credential as CoreCredential;

        let (store, manager, root, export_dir) = setup_store_with_backup();

        let cred: Credential = CoreCredential::new()
            .issuer_schema_id(100)
            .genesis_issued_at(1000)
            .into();
        store
            .store_credential(&cred, &FieldElement::from(7u64), 9999, None, 1000)
            .expect("store credential");

        assert_eq!(manager.call_count(), 1);
        assert!(
            manager.last_file_existed(),
            "exported vault file should exist during the callback"
        );
        let path = manager.last_path().unwrap();
        assert!(
            !std::path::Path::new(&path).exists(),
            "exported vault file should be cleaned up after the callback"
        );

        cleanup_test_storage(&root);
        cleanup_test_storage(&export_dir);
    }

    #[test]
    fn test_no_backup_notification_without_manager() {
        use world_id_core::Credential as CoreCredential;

        let root = temp_root_path();
        let provider = InMemoryStorageProvider::new(&root);
        let store = CredentialStore::from_provider(&provider).expect("create store");
        store.init(42, 1000).expect("init store");

        // No backup manager registered — should not panic.
        let cred: Credential = CoreCredential::new()
            .issuer_schema_id(100)
            .genesis_issued_at(1000)
            .into();
        store
            .store_credential(&cred, &FieldElement::from(7u64), 9999, None, 1000)
            .expect("store credential");

        cleanup_test_storage(&root);
    }

    #[test]
    fn test_delete_all_triggers_backup_notification() {
        use world_id_core::Credential as CoreCredential;

        let (store, manager, root, export_dir) = setup_store_with_backup();

        let cred: Credential = CoreCredential::new()
            .issuer_schema_id(100)
            .genesis_issued_at(1000)
            .into();
        store
            .store_credential(&cred, &FieldElement::from(7u64), 9999, None, 1000)
            .expect("store credential");
        assert_eq!(manager.call_count(), 1);

        store.danger_delete_all_credentials().expect("delete all");
        assert_eq!(manager.call_count(), 2);

        cleanup_test_storage(&root);
        cleanup_test_storage(&export_dir);
    }

    #[test]
    fn test_delete_credential_triggers_backup_notification() {
        use world_id_core::Credential as CoreCredential;

        let (store, manager, root, export_dir) = setup_store_with_backup();

        let cred: Credential = CoreCredential::new()
            .issuer_schema_id(100)
            .genesis_issued_at(1000)
            .into();
        store
            .store_credential(&cred, &FieldElement::from(7u64), 9999, None, 1000)
            .expect("store credential");
        assert_eq!(manager.call_count(), 1);

        let credentials = store.list_credentials(None, 1000).expect("list");
        let credential_id = credentials[0].credential_id;

        store
            .delete_credential(credential_id)
            .expect("delete credential");
        assert_eq!(manager.call_count(), 2);

        cleanup_test_storage(&root);
        cleanup_test_storage(&export_dir);
    }

    #[test]
    fn test_delete_all_empty_skips_backup_notification() {
        let (store, manager, root, export_dir) = setup_store_with_backup();

        // No credentials stored — delete returns 0, no notification expected.
        let deleted = store
            .danger_delete_all_credentials()
            .expect("delete all on empty");
        assert_eq!(deleted, 0);
        assert_eq!(manager.call_count(), 0);

        cleanup_test_storage(&root);
        cleanup_test_storage(&export_dir);
    }

    #[test]
    fn test_multiple_stores_trigger_multiple_notifications() {
        use world_id_core::Credential as CoreCredential;

        let (store, manager, root, export_dir) = setup_store_with_backup();

        for schema_id in [100u64, 200, 300] {
            let cred: Credential = CoreCredential::new()
                .issuer_schema_id(schema_id)
                .genesis_issued_at(1000)
                .into();
            store
                .store_credential(&cred, &FieldElement::from(7u64), 9999, None, 1000)
                .expect("store credential");
        }

        assert_eq!(manager.call_count(), 3);

        cleanup_test_storage(&root);
        cleanup_test_storage(&export_dir);
    }
}
