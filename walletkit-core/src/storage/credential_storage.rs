//! Storage facade implementing the credential storage API.

#[cfg(not(target_arch = "wasm32"))]
use std::sync::mpsc;
use std::sync::{Arc, Mutex};

use world_id_core::FieldElement as CoreFieldElement;

use super::error::{StorageError, StorageResult};
use super::keys::StorageKeys;
use super::lock::{StorageLock, StorageLockGuard};
use super::paths::StoragePaths;
use super::traits::StorageProvider;
#[cfg(not(target_arch = "wasm32"))]
use super::traits::VaultChangedListener;
use super::traits::{AtomicBlobStore, DeviceKeystore};
use super::types::CredentialRecord;
use super::ACCOUNT_KEYS_FILENAME;
use super::{CacheDb, VaultDb};
use crate::{Credential, FieldElement};
use world_id_core::primitives::merkle::AccountInclusionProof;
use world_id_core::primitives::TREE_DEPTH;

/// Session seed TTL: ~6 months (182 days).
const SESSION_SEED_TTL_SECONDS: u64 = 182 * 86_400;

/// Filename prefix for temporary plaintext vault exports used during
/// backup export and import. A UUID is appended to avoid collisions.
#[cfg(not(target_arch = "wasm32"))]
const VAULT_BACKUP_TEMP_PREFIX: &str = "vault_backup_plaintext_";

/// RAII guard that deletes a sensitive plaintext file on drop — regardless
/// of whether we exit normally, return early, or panic.
#[cfg(not(target_arch = "wasm32"))]
struct CleanupFile(String);

#[cfg(not(target_arch = "wasm32"))]
impl Drop for CleanupFile {
    fn drop(&mut self) {
        if let Err(e) = std::fs::remove_file(&self.0) {
            tracing::error!(
                "Failed to delete plaintext vault temp file {}: {e}",
                self.0
            );
        }
    }
}

/// Removes a `SQLite` database file and its WAL/SHM sidecar files.
/// Best-effort: missing files are silently ignored, other errors are logged.
#[cfg(not(target_arch = "wasm32"))]
fn remove_db_files(db_path: &std::path::Path) {
    for ext in &["sqlite", "sqlite-wal", "sqlite-shm"] {
        let path = db_path.with_extension(ext);
        if let Err(e) = std::fs::remove_file(&path) {
            if e.kind() != std::io::ErrorKind::NotFound {
                tracing::error!("Failed to delete {}: {e}", path.display());
            }
        }
    }
}

/// Concrete storage implementation backed by `SQLCipher` databases.
#[cfg_attr(not(target_arch = "wasm32"), derive(uniffi::Object))]
pub struct CredentialStore {
    inner: Mutex<CredentialStoreInner>,
    /// Channel sender for the vault-changed notification thread.
    /// Kept outside `inner` so we can notify after releasing the storage mutex.
    #[cfg(not(target_arch = "wasm32"))]
    vault_changed_tx: Mutex<Option<mpsc::SyncSender<()>>>,
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
            #[cfg(not(target_arch = "wasm32"))]
            vault_changed_tx: Mutex::new(None),
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
            #[cfg(not(target_arch = "wasm32"))]
            vault_changed_tx: Mutex::new(None),
        })
    }

    /// Returns the storage paths used by this handle.
    ///
    /// # Errors
    ///
    /// Returns an error if the storage mutex is poisoned.
    pub fn storage_paths(&self) -> StorageResult<StoragePaths> {
        self.lock_inner().map(|inner| inner.paths.clone())
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
        let result = self.lock_inner()?.delete_credential(credential_id);
        if result.is_ok() {
            self.notify_vault_changed();
        }
        result
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
        let result = self.lock_inner()?.store_credential(
            credential,
            blinding_factor,
            expires_at,
            associated_data,
            now,
        );
        if result.is_ok() {
            self.notify_vault_changed();
        }
        result
    }

    /// Exports the current vault as an in-memory plaintext (unencrypted)
    /// `SQLite` database for backup.
    ///
    /// The host app is responsible for persisting or uploading the returned
    /// bytes
    ///
    /// # Errors
    ///
    /// Returns an error if the store is not initialized or the export fails.
    #[cfg(not(target_arch = "wasm32"))]
    #[expect(
        clippy::significant_drop_tightening,
        reason = "lock held intentionally for the full operation to prevent concurrent cleanup from deleting in-use temp files"
    )]
    pub fn export_vault_for_backup(&self) -> StorageResult<Vec<u8>> {
        let inner = self.lock_inner()?;
        inner.cleanup_stale_backup_files();
        let path = inner.export_vault_for_backup_to_file()?;
        let _cleanup = CleanupFile(path.clone());

        std::fs::read(&path).map_err(|e| {
            StorageError::VaultDb(format!("failed to read exported vault: {e}"))
        })
    }

    /// Imports credentials from an in-memory plaintext vault backup.
    ///
    /// The store must already be initialized via [`init`](Self::init).
    /// Intended for restore on a fresh install where the vault is empty.
    /// # Errors
    ///
    /// Returns an error if the store is not initialized or the import fails.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn import_vault_from_backup(&self, backup_bytes: &[u8]) -> StorageResult<()> {
        let inner = self.lock_inner()?;
        inner.cleanup_stale_backup_files();
        let path = inner.write_temp_backup_file(backup_bytes)?;
        let _cleanup = CleanupFile(path.clone());

        inner.import_vault_from_file(&path)
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
        self.lock_inner()?.danger_delete_all_credentials()
    }

    /// Permanently destroys all credential storage data.
    ///
    /// This removes the encryption key envelope, the vault database, and the
    /// cache database. After this call the store is left in an uninitialized
    /// state — any subsequent operation (other than re-initialization) will
    /// return [`StorageError::NotInitialized`].
    ///
    /// Intended for use when the user logs out or deletes their account.
    ///
    /// # Errors
    ///
    /// Returns an error if the storage lock cannot be acquired or the key
    /// envelope cannot be deleted from the blob store.
    pub fn destroy_storage(&self) -> StorageResult<()> {
        self.lock_inner()?.destroy_storage()
    }

    /// Registers a listener that is called after a credential is added or
    /// removed.
    ///
    /// Only one listener can be active at a time — calling this replaces any
    /// previously registered listener. The previous delivery thread shuts down
    /// automatically when the old sender is dropped.
    ///
    /// Delivery happens on a dedicated background thread to avoid re-entering
    /// the `UniFFI` call stack (see `logger.rs` for rationale).
    ///
    /// **Warning:** the listener **must not** call back into this
    /// `CredentialStore` — doing so will deadlock.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn set_vault_changed_listener(&self, listener: Arc<dyn VaultChangedListener>) {
        let (tx, rx) = mpsc::sync_channel(1);

        match std::thread::Builder::new()
            .name("walletkit-vault-notify".into())
            .spawn(move || {
                for () in rx {
                    listener.on_vault_changed();
                }
            }) {
            Ok(_) => {
                if let Ok(mut guard) = self.vault_changed_tx.lock() {
                    *guard = Some(tx);
                }
            }
            Err(e) => {
                tracing::error!("failed to spawn vault notification thread: {e}");
            }
        }
    }
}

/// Implementation not exposed to foreign bindings
impl CredentialStore {
    /// Stores a `session_id_r_seed` into the cache.
    ///
    /// # Errors
    ///
    /// Returns an error if the store is not initialized or the insert fails.
    pub fn store_session_seed(
        &self,
        oprf_seed: CoreFieldElement,
        session_id_r_seed: CoreFieldElement,
        now: u64,
    ) -> StorageResult<()> {
        self.lock_inner()?
            .store_session_seed(oprf_seed, session_id_r_seed, now)
    }

    /// Retrieves the `session_id_r_seed` for a given `oprf_seed`, if not expired.
    ///
    /// # Errors
    ///
    /// Returns an error if the store is not initialized or the query fails.
    pub fn get_session_seed(
        &self,
        oprf_seed: CoreFieldElement,
        now: u64,
    ) -> StorageResult<Option<CoreFieldElement>> {
        self.lock_inner()?.get_session_seed(oprf_seed, now)
    }

    /// Fetches a cached Merkle proof if it remains valid beyond `valid_before`.
    ///
    /// # Errors
    ///
    /// Returns an error if the cache lookup fails.
    pub fn merkle_cache_get(
        &self,
        valid_until: u64,
    ) -> StorageResult<Option<AccountInclusionProof<TREE_DEPTH>>> {
        self.lock_inner()?.merkle_cache_get(valid_until)
    }

    /// Inserts a cached Merkle proof with a TTL.
    ///
    /// # Errors
    ///
    /// Returns an error if the cache insert fails.
    pub fn merkle_cache_put(
        &self,
        account_inclusion_proof: &AccountInclusionProof<TREE_DEPTH>,
        now: u64,
        ttl_seconds: u64,
    ) -> StorageResult<()> {
        self.lock_inner()?
            .merkle_cache_put(account_inclusion_proof, now, ttl_seconds)
    }

    /// Best-effort notification to the registered vault-changed listener.
    /// No-op on wasm32 where the listener cannot be registered.
    ///
    /// Only call this when vault contents change in a way that warrants a new
    /// backup (i.e. credential added or removed). Do **not** call it for
    /// destructive operations like vault deletion or purge.
    fn notify_vault_changed(&self) {
        #[cfg(not(target_arch = "wasm32"))]
        if let Ok(guard) = self.vault_changed_tx.lock() {
            if let Some(tx) = guard.as_ref() {
                match tx.try_send(()) {
                    Ok(()) | Err(mpsc::TrySendError::Full(())) => {}
                    Err(mpsc::TrySendError::Disconnected(())) => {
                        tracing::warn!("vault-changed listener disconnected");
                    }
                }
            }
        }
    }

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
        let k_intermediate = keys.intermediate_key();
        let vault = VaultDb::new(&self.paths.vault_db_path(), k_intermediate, &guard)?;
        let cache = CacheDb::new(&self.paths.cache_db_path(), k_intermediate, &guard)?;
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

    fn store_session_seed(
        &mut self,
        oprf_seed: CoreFieldElement,
        session_id_r_seed: CoreFieldElement,
        now: u64,
    ) -> StorageResult<()> {
        let guard = self.guard()?;
        let state = self.state_mut()?;
        state.cache.session_seed_put(
            &guard,
            oprf_seed.to_be_bytes(),
            session_id_r_seed.to_be_bytes(),
            now,
            SESSION_SEED_TTL_SECONDS,
        )
    }

    fn get_session_seed(
        &self,
        oprf_seed: CoreFieldElement,
        now: u64,
    ) -> StorageResult<Option<CoreFieldElement>> {
        let state = self.state()?;
        let Some(bytes) = state.cache.session_seed_get(oprf_seed.to_be_bytes(), now)?
        else {
            return Ok(None);
        };
        let seed = CoreFieldElement::from_be_bytes(&bytes).map_err(|e| {
            StorageError::Serialization(format!(
                "failed to deserialize session_id_r_seed: {e}"
            ))
        })?;
        Ok(Some(seed))
    }

    fn merkle_cache_get(
        &self,
        valid_until: u64,
    ) -> StorageResult<Option<AccountInclusionProof<TREE_DEPTH>>> {
        let state = self.state()?;
        let bytes = state.cache.merkle_cache_get(valid_until)?;

        if let Some(bytes) = bytes {
            let result =
                serde_json::from_slice::<AccountInclusionProof<TREE_DEPTH>>(&bytes)
                    .ok();
            return Ok(result);
        }
        Ok(None)
    }

    fn merkle_cache_put(
        &mut self,
        account_inclusion_proof: &AccountInclusionProof<TREE_DEPTH>,
        now: u64,
        ttl_seconds: u64,
    ) -> StorageResult<()> {
        let guard = self.guard()?;
        let state = self.state_mut()?;
        // Use JSON for storage instead of CBOR because the `#[serde(flatten)]` property
        // causes the deserialization of `FieldElement`s to appear as human-readable
        let bytes = serde_json::to_vec(account_inclusion_proof).map_err(|_| {
            StorageError::Serialization(
                "unexpected. unable to serialize `account_inclusion_proof`".to_string(),
            )
        })?;

        state
            .cache
            .merkle_cache_put(&guard, bytes, now, ttl_seconds)
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

    /// Exports the vault to a temporary plaintext file in the worldid directory.
    /// Returns the path to the file. The caller is responsible for cleanup.
    #[cfg(not(target_arch = "wasm32"))]
    fn export_vault_for_backup_to_file(&self) -> StorageResult<String> {
        let guard = self.guard()?;
        let state = self.state()?;
        let dest = self.temp_backup_path();
        state.vault.export_plaintext(&dest, &guard)?;
        Ok(dest.to_string_lossy().to_string())
    }

    /// Writes raw bytes to a temporary file in the worldid directory.
    /// Returns the path. The caller is responsible for cleanup.
    #[cfg(not(target_arch = "wasm32"))]
    fn write_temp_backup_file(&self, bytes: &[u8]) -> StorageResult<String> {
        let dest = self.temp_backup_path();
        if let Err(e) = std::fs::write(&dest, bytes) {
            // Best-effort cleanup of any partial write to avoid leaking
            // plaintext data on disk (e.g. after ENOSPC).
            let _ = std::fs::remove_file(&dest);
            return Err(StorageError::VaultDb(format!(
                "failed to write temp backup file: {e}"
            )));
        }
        Ok(dest.to_string_lossy().to_string())
    }

    /// Imports from a plaintext vault file on disk.
    #[cfg(not(target_arch = "wasm32"))]
    fn import_vault_from_file(&self, backup_path: &str) -> StorageResult<()> {
        let guard = self.guard()?;
        let state = self.state()?;
        let source = std::path::Path::new(backup_path);
        state.vault.import_plaintext(source, &guard)
    }

    /// Removes any stale plaintext backup temp files left behind by a
    /// previous crash or hard kill. Best-effort — errors are logged.
    #[cfg(not(target_arch = "wasm32"))]
    fn cleanup_stale_backup_files(&self) {
        let dir = self.paths.worldid_dir();
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            if let Some(name) = entry.file_name().to_str() {
                if name.starts_with(VAULT_BACKUP_TEMP_PREFIX) {
                    if let Err(e) = std::fs::remove_file(entry.path()) {
                        tracing::error!(
                            "Failed to clean up stale backup file {}: {e}",
                            entry.path().display()
                        );
                    }
                }
            }
        }
    }

    /// Returns a unique temp file path in the worldid directory for backup operations.
    #[cfg(not(target_arch = "wasm32"))]
    fn temp_backup_path(&self) -> std::path::PathBuf {
        let filename = format!(
            "{}{}.sqlite",
            VAULT_BACKUP_TEMP_PREFIX,
            uuid::Uuid::new_v4()
        );
        self.paths.worldid_dir().join(filename)
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

    /// Permanently destroys all storage data: encryption keys, vault, and cache.
    fn destroy_storage(&mut self) -> StorageResult<()> {
        let _guard = self.guard()?;
        // Drop in-memory state: zeroizes keys, closes database connections.
        self.state = None;
        // Delete the encryption key envelope. Without this key the database
        // files are unreadable even if file deletion below fails.
        self.blob_store.delete(ACCOUNT_KEYS_FILENAME.to_string())?;
        // Best-effort removal of database files and their SQLite sidecar files.
        #[cfg(not(target_arch = "wasm32"))]
        {
            remove_db_files(&self.paths.vault_db_path());
            remove_db_files(&self.paths.cache_db_path());
        }
        Ok(())
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
            #[cfg(not(target_arch = "wasm32"))]
            vault_changed_tx: Mutex::new(None),
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
            #[cfg(not(target_arch = "wasm32"))]
            vault_changed_tx: Mutex::new(None),
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

    use std::sync::atomic::{AtomicU32, Ordering};

    struct TestVaultListener(Arc<AtomicU32>);

    impl VaultChangedListener for TestVaultListener {
        fn on_vault_changed(&self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

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

        let src_root = temp_root_path();
        let src_provider = InMemoryStorageProvider::new(&src_root);
        let src_store =
            CredentialStore::from_provider(&src_provider).expect("create src store");
        src_store.init(42, 1000).expect("init src storage");

        let issuer_schema_id = 100u64;
        let blinding_factor = FieldElement::from(7u64);
        let cred: Credential = CoreCredential::new()
            .issuer_schema_id(issuer_schema_id)
            .genesis_issued_at(1000)
            .into();

        src_store
            .store_credential(&cred, &blinding_factor, 9999, None, 1000)
            .expect("store credential");

        let bytes = src_store.export_vault_for_backup().expect("export vault");
        assert!(!bytes.is_empty());

        let dst_root = temp_root_path();
        let dst_provider = InMemoryStorageProvider::new(&dst_root);
        let dst_store =
            CredentialStore::from_provider(&dst_provider).expect("create dst store");
        dst_store.init(42, 1000).expect("init dst storage");

        dst_store
            .import_vault_from_backup(&bytes)
            .expect("import vault");

        let (imported_cred, imported_bf) = dst_store
            .get_credential(issuer_schema_id, 1000)
            .expect("get credential")
            .expect("imported credential should exist");
        assert_eq!(imported_cred.issuer_schema_id(), issuer_schema_id);
        assert_eq!(imported_bf.to_bytes(), blinding_factor.to_bytes());

        cleanup_test_storage(&src_root);
        cleanup_test_storage(&dst_root);
    }

    #[test]
    fn test_export_and_import_multiple_credentials_with_associated_data() {
        use world_id_core::Credential as CoreCredential;

        let src_root = temp_root_path();
        let src_provider = InMemoryStorageProvider::new(&src_root);
        let src_store =
            CredentialStore::from_provider(&src_provider).expect("create src store");
        src_store.init(42, 1000).expect("init src storage");

        // Store credential A (schema 100) without associated data
        let cred_a: Credential = CoreCredential::new()
            .issuer_schema_id(100)
            .genesis_issued_at(1000)
            .into();
        src_store
            .store_credential(&cred_a, &FieldElement::from(7u64), 9999, None, 1000)
            .expect("store cred A");

        // Store credential B (schema 200) with associated data
        let cred_b: Credential = CoreCredential::new()
            .issuer_schema_id(200)
            .genesis_issued_at(2000)
            .into();
        src_store
            .store_credential(
                &cred_b,
                &FieldElement::from(13u64),
                9999,
                Some(b"extra-payload-for-cred-b".to_vec()),
                2000,
            )
            .expect("store cred B");

        // Store credential C (schema 300) without associated data
        let cred_c: Credential = CoreCredential::new()
            .issuer_schema_id(300)
            .genesis_issued_at(3000)
            .into();
        src_store
            .store_credential(&cred_c, &FieldElement::from(42u64), 9999, None, 3000)
            .expect("store cred C");

        assert_eq!(src_store.list_credentials(None, 1000).unwrap().len(), 3);

        // Export and import into fresh store
        let bytes = src_store.export_vault_for_backup().expect("export vault");

        let dst_root = temp_root_path();
        let dst_provider = InMemoryStorageProvider::new(&dst_root);
        let dst_store =
            CredentialStore::from_provider(&dst_provider).expect("create dst store");
        dst_store.init(42, 1000).expect("init dst storage");

        dst_store
            .import_vault_from_backup(&bytes)
            .expect("import vault");

        assert_eq!(dst_store.list_credentials(None, 1000).unwrap().len(), 3);

        let (cred_a, bf_a) = dst_store
            .get_credential(100, 1000)
            .expect("get cred A")
            .expect("cred A should exist");
        assert_eq!(cred_a.issuer_schema_id(), 100);
        assert_eq!(bf_a.to_bytes(), FieldElement::from(7u64).to_bytes());

        let (cred_b, bf_b) = dst_store
            .get_credential(200, 2000)
            .expect("get cred B")
            .expect("cred B should exist");
        assert_eq!(cred_b.issuer_schema_id(), 200);
        assert_eq!(bf_b.to_bytes(), FieldElement::from(13u64).to_bytes());

        let (cred_c, bf_c) = dst_store
            .get_credential(300, 3000)
            .expect("get cred C")
            .expect("cred C should exist");
        assert_eq!(cred_c.issuer_schema_id(), 300);
        assert_eq!(bf_c.to_bytes(), FieldElement::from(42u64).to_bytes());

        cleanup_test_storage(&src_root);
        cleanup_test_storage(&dst_root);
    }

    #[test]
    fn test_import_vault_backup_into_non_empty_vault_fails() {
        use world_id_core::Credential as CoreCredential;

        let root = temp_root_path();
        let provider = InMemoryStorageProvider::new(&root);
        let store = CredentialStore::from_provider(&provider).expect("create store");
        store.init(42, 1000).expect("init storage");

        let blinding_factor = FieldElement::from(7u64);
        let cred: Credential = CoreCredential::new()
            .issuer_schema_id(100u64)
            .genesis_issued_at(1000)
            .into();

        store
            .store_credential(&cred, &blinding_factor, 9999, None, 1000)
            .expect("store credential");

        let bytes = store.export_vault_for_backup().expect("export vault");

        // Importing into a non-empty vault should fail.
        let result = store.import_vault_from_backup(&bytes);
        assert!(result.is_err(), "import into non-empty vault should fail");

        // Verify existing data is unchanged after the failed import.
        let (cred, bf) = store
            .get_credential(100, 1000)
            .expect("get credential after failed import")
            .expect("credential should still exist");
        assert_eq!(cred.issuer_schema_id(), 100);
        assert_eq!(bf.to_bytes(), blinding_factor.to_bytes());

        cleanup_test_storage(&root);
    }

    #[test]
    fn test_import_vault_backup_invalid_bytes_fails() {
        let root = temp_root_path();
        let provider = InMemoryStorageProvider::new(&root);
        let store = CredentialStore::from_provider(&provider).expect("create store");
        store.init(42, 1000).expect("init storage");

        let result = store.import_vault_from_backup(b"not a sqlite database");
        assert!(result.is_err(), "import from invalid bytes should fail");

        cleanup_test_storage(&root);
    }

    #[test]
    fn test_import_vault_backup_transaction_atomicity() {
        use walletkit_db::cipher::BACKUP_TABLES;
        use walletkit_db::Connection;
        use world_id_core::Credential as CoreCredential;

        let src_root = temp_root_path();
        let src_provider = InMemoryStorageProvider::new(&src_root);
        let src_store =
            CredentialStore::from_provider(&src_provider).expect("create src store");
        src_store.init(42, 1000).expect("init src storage");

        let cred: Credential = CoreCredential::new()
            .issuer_schema_id(100u64)
            .genesis_issued_at(1000)
            .into();
        src_store
            .store_credential(&cred, &FieldElement::from(7u64), 9999, None, 1000)
            .expect("store credential");

        // Export as bytes, write to a temp file so we can corrupt it.
        let bytes = src_store.export_vault_for_backup().expect("export vault");
        let corrupt_path = src_root.join("corrupt_backup.sqlite");
        std::fs::write(&corrupt_path, &bytes).expect("write backup");

        // Corrupt the *last* table in BACKUP_TABLES. Earlier INSERTs succeed
        // before this one fails, testing transaction rollback.
        assert_eq!(
            *BACKUP_TABLES.last().unwrap(),
            "blob_objects",
            "update this test if BACKUP_TABLES order changes"
        );
        let backup_conn = Connection::open(&corrupt_path, false).expect("open backup");
        backup_conn
            .execute(
                "INSERT INTO blob_objects (content_id, blob_kind, created_at, bytes)
                 VALUES (NULL, 1, 2000, X'CAFE')",
                &[],
            )
            .expect("insert corrupt row");
        drop(backup_conn);

        // Read corrupted file back as bytes
        let corrupt_bytes = std::fs::read(&corrupt_path).expect("read corrupt backup");

        let dst_root = temp_root_path();
        let dst_provider = InMemoryStorageProvider::new(&dst_root);
        let dst_store =
            CredentialStore::from_provider(&dst_provider).expect("create dst store");
        dst_store.init(42, 1000).expect("init dst storage");

        let result = dst_store.import_vault_from_backup(&corrupt_bytes);
        assert!(result.is_err(), "import with corrupt backup should fail");

        // The transaction should have rolled back — destination is still empty.
        let dst_list = dst_store.list_credentials(None, 1000).expect("list dst");
        assert!(
            dst_list.is_empty(),
            "destination should be empty after failed import (transaction rolled back)"
        );

        std::fs::remove_file(&corrupt_path).ok();
        cleanup_test_storage(&src_root);
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

    #[test]
    fn test_export_vault_for_backup_returns_bytes() {
        use world_id_core::Credential as CoreCredential;

        let root = temp_root_path();
        let provider = InMemoryStorageProvider::new(&root);
        let store = CredentialStore::from_provider(&provider).expect("create store");
        store.init(42, 1000).expect("init store");

        let cred: Credential = CoreCredential::new()
            .issuer_schema_id(100)
            .genesis_issued_at(1000)
            .into();
        store
            .store_credential(&cred, &FieldElement::from(7u64), 9999, None, 1000)
            .expect("store credential");

        let bytes = store.export_vault_for_backup().expect("export vault");
        assert!(
            bytes.len() >= 16,
            "exported vault too small to be a valid SQLite database"
        );

        // Verify the bytes are a valid SQLite database (magic header).
        assert_eq!(
            &bytes[..16],
            b"SQLite format 3\0",
            "exported bytes should be a valid SQLite database"
        );

        cleanup_test_storage(&root);
    }

    #[test]
    fn test_export_vault_for_backup_roundtrip() {
        use world_id_core::Credential as CoreCredential;

        let src_root = temp_root_path();
        let src_provider = InMemoryStorageProvider::new(&src_root);
        let src_store =
            CredentialStore::from_provider(&src_provider).expect("create store");
        src_store.init(42, 1000).expect("init store");

        let cred: Credential = CoreCredential::new()
            .issuer_schema_id(100)
            .genesis_issued_at(1000)
            .into();
        src_store
            .store_credential(&cred, &FieldElement::from(7u64), 9999, None, 1000)
            .expect("store credential");

        let bytes = src_store.export_vault_for_backup().expect("export vault");
        assert!(!bytes.is_empty(), "exported bytes should not be empty");

        // Import the raw bytes into a fresh store via the public API.
        let dst_root = temp_root_path();
        let dst_provider = InMemoryStorageProvider::new(&dst_root);
        let dst_store =
            CredentialStore::from_provider(&dst_provider).expect("create dst store");
        dst_store.init(42, 1000).expect("init dst store");

        dst_store
            .import_vault_from_backup(&bytes)
            .expect("import vault from bytes");

        let (imported_cred, imported_bf) = dst_store
            .get_credential(100, 1000)
            .expect("get credential")
            .expect("credential should exist");
        assert_eq!(imported_cred.issuer_schema_id(), 100);
        assert_eq!(imported_bf.to_bytes(), FieldElement::from(7u64).to_bytes());

        cleanup_test_storage(&src_root);
        cleanup_test_storage(&dst_root);
    }

    #[test]
    fn test_export_cleans_up_temp_file() {
        use world_id_core::Credential as CoreCredential;

        let root = temp_root_path();
        let provider = InMemoryStorageProvider::new(&root);
        let store = CredentialStore::from_provider(&provider).expect("create store");
        store.init(42, 1000).expect("init store");

        let cred: Credential = CoreCredential::new()
            .issuer_schema_id(100)
            .genesis_issued_at(1000)
            .into();
        store
            .store_credential(&cred, &FieldElement::from(7u64), 9999, None, 1000)
            .expect("store credential");

        let _bytes = store.export_vault_for_backup().expect("export vault");

        // After export, no temp files should remain in the worldid directory.
        let worldid_dir = store.storage_paths().unwrap().worldid_dir().to_path_buf();
        let stale: Vec<_> = std::fs::read_dir(&worldid_dir)
            .unwrap()
            .flatten()
            .filter(|e| {
                e.file_name()
                    .to_str()
                    .is_some_and(|n| n.starts_with(VAULT_BACKUP_TEMP_PREFIX))
            })
            .collect();
        assert!(
            stale.is_empty(),
            "temp backup files should be cleaned up after export, found: {stale:?}"
        );

        cleanup_test_storage(&root);
    }

    #[test]
    fn test_stale_backup_files_cleaned_on_next_operation() {
        use world_id_core::Credential as CoreCredential;

        let root = temp_root_path();
        let provider = InMemoryStorageProvider::new(&root);
        let store = CredentialStore::from_provider(&provider).expect("create store");
        store.init(42, 1000).expect("init store");

        let cred: Credential = CoreCredential::new()
            .issuer_schema_id(100)
            .genesis_issued_at(1000)
            .into();
        store
            .store_credential(&cred, &FieldElement::from(7u64), 9999, None, 1000)
            .expect("store credential");

        // Simulate stale temp files left by a previous crash.
        let worldid_dir = store.storage_paths().unwrap().worldid_dir().to_path_buf();
        let stale_path =
            worldid_dir.join(format!("{VAULT_BACKUP_TEMP_PREFIX}stale.sqlite"));
        std::fs::write(&stale_path, b"stale plaintext data").expect("write stale file");
        assert!(stale_path.exists(), "stale file should exist before export");

        // The next backup operation should clean up the stale file.
        let _bytes = store.export_vault_for_backup().expect("export vault");

        assert!(
            !stale_path.exists(),
            "stale backup file should be cleaned up during export"
        );

        // Also verify no other temp files linger.
        let remaining: Vec<_> = std::fs::read_dir(&worldid_dir)
            .unwrap()
            .flatten()
            .filter(|e| {
                e.file_name()
                    .to_str()
                    .is_some_and(|n| n.starts_with(VAULT_BACKUP_TEMP_PREFIX))
            })
            .collect();
        assert!(
            remaining.is_empty(),
            "no temp backup files should remain after export, found: {remaining:?}"
        );

        cleanup_test_storage(&root);
    }

    #[test]
    fn test_vault_changed_listener_notified_on_store() {
        use world_id_core::Credential as CoreCredential;

        let root = temp_root_path();
        let provider = InMemoryStorageProvider::new(&root);
        let store = CredentialStore::from_provider(&provider).expect("create store");
        store.init(42, 1000).expect("init storage");

        let count = Arc::new(AtomicU32::new(0));
        store.set_vault_changed_listener(Arc::new(TestVaultListener(Arc::clone(
            &count,
        ))));

        let cred: Credential = CoreCredential::new()
            .issuer_schema_id(100)
            .genesis_issued_at(1000)
            .into();
        store
            .store_credential(&cred, &FieldElement::from(7u64), 9999, None, 1000)
            .expect("store credential");

        // Give the delivery thread time to process.
        std::thread::sleep(std::time::Duration::from_millis(50));

        assert_eq!(
            count.load(Ordering::SeqCst),
            1,
            "listener should be notified once"
        );

        cleanup_test_storage(&root);
    }

    #[test]
    fn test_vault_changed_listener_notified_on_delete() {
        use world_id_core::Credential as CoreCredential;

        let root = temp_root_path();
        let provider = InMemoryStorageProvider::new(&root);
        let store = CredentialStore::from_provider(&provider).expect("create store");
        store.init(42, 1000).expect("init storage");

        let count = Arc::new(AtomicU32::new(0));
        store.set_vault_changed_listener(Arc::new(TestVaultListener(Arc::clone(
            &count,
        ))));

        let cred: Credential = CoreCredential::new()
            .issuer_schema_id(100)
            .genesis_issued_at(1000)
            .into();
        let id = store
            .store_credential(&cred, &FieldElement::from(7u64), 9999, None, 1000)
            .expect("store credential");

        store.delete_credential(id).expect("delete credential");

        std::thread::sleep(std::time::Duration::from_millis(50));

        // store + delete = 2 notifications
        assert_eq!(
            count.load(Ordering::SeqCst),
            2,
            "listener should be notified twice"
        );

        cleanup_test_storage(&root);
    }

    #[test]
    fn test_vault_changed_listener_not_notified_on_failure() {
        let root = temp_root_path();
        let provider = InMemoryStorageProvider::new(&root);
        let store = CredentialStore::from_provider(&provider).expect("create store");
        store.init(42, 1000).expect("init storage");

        let count = Arc::new(AtomicU32::new(0));
        store.set_vault_changed_listener(Arc::new(TestVaultListener(Arc::clone(
            &count,
        ))));

        // Deleting a non-existent credential should fail — no notification.
        let result = store.delete_credential(999);
        assert!(result.is_err());

        std::thread::sleep(std::time::Duration::from_millis(50));

        assert_eq!(
            count.load(Ordering::SeqCst),
            0,
            "listener should not be notified on failure"
        );

        cleanup_test_storage(&root);
    }

    #[test]
    fn test_no_listener_does_not_panic() {
        use world_id_core::Credential as CoreCredential;

        let root = temp_root_path();
        let provider = InMemoryStorageProvider::new(&root);
        let store = CredentialStore::from_provider(&provider).expect("create store");
        store.init(42, 1000).expect("init storage");

        // No listener registered — mutations should still work fine.
        let cred: Credential = CoreCredential::new()
            .issuer_schema_id(100)
            .genesis_issued_at(1000)
            .into();
        store
            .store_credential(&cred, &FieldElement::from(7u64), 9999, None, 1000)
            .expect("store without listener should succeed");

        cleanup_test_storage(&root);
    }

    #[test]
    fn test_destroy_storage() {
        use world_id_core::Credential as CoreCredential;

        let root = temp_root_path();
        let provider = InMemoryStorageProvider::new(&root);
        let store = CredentialStore::from_provider(&provider).expect("create store");
        store.init(42, 1000).expect("init storage");

        let cred: Credential = CoreCredential::new()
            .issuer_schema_id(100)
            .genesis_issued_at(1000)
            .into();
        store
            .store_credential(&cred, &FieldElement::from(7u64), 9999, None, 1000)
            .expect("store credential");

        // Destroy should succeed.
        store.destroy_storage().expect("destroy storage");

        // Database files should be removed from the storage directory.
        let paths = StoragePaths::new(&root);
        let remaining: Vec<_> = std::fs::read_dir(paths.worldid_dir())
            .expect("read worldid dir")
            .filter_map(|e| e.ok().map(|e| e.file_name()))
            .collect();
        // Only the lock file should remain.
        assert!(
            remaining.iter().all(|f| f == "lock"),
            "expected only lock file to remain, found: {remaining:?}"
        );

        // Subsequent operations should return NotInitialized.
        let err = store.list_credentials(None, 1000).unwrap_err();
        assert!(
            matches!(err, StorageError::NotInitialized),
            "expected NotInitialized, got: {err:?}"
        );

        // Re-initialization should work.
        store.init(42, 1000).expect("re-init storage");
        let list = store
            .list_credentials(None, 1000)
            .expect("list after re-init");
        assert!(
            list.is_empty(),
            "store should be empty after destroy + re-init"
        );

        cleanup_test_storage(&root);
    }

    #[test]
    fn test_destroy_storage_does_not_notify_vault_changed() {
        use world_id_core::Credential as CoreCredential;

        let root = temp_root_path();
        let provider = InMemoryStorageProvider::new(&root);
        let store = CredentialStore::from_provider(&provider).expect("create store");
        store.init(42, 1000).expect("init storage");

        let count = Arc::new(AtomicU32::new(0));
        store.set_vault_changed_listener(Arc::new(TestVaultListener(Arc::clone(
            &count,
        ))));

        let cred: Credential = CoreCredential::new()
            .issuer_schema_id(100)
            .genesis_issued_at(1000)
            .into();
        store
            .store_credential(&cred, &FieldElement::from(7u64), 9999, None, 1000)
            .expect("store credential");

        store.destroy_storage().expect("destroy storage");

        std::thread::sleep(std::time::Duration::from_millis(50));

        // Only the store should trigger a notification — destroy does not.
        assert_eq!(
            count.load(Ordering::SeqCst),
            1,
            "listener should only be notified for store, not destroy"
        );

        cleanup_test_storage(&root);
    }
}
