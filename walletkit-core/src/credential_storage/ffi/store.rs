//! FFI-safe store types for credential storage.
//!
//! This module provides the main entry points for using credential storage
//! from Swift and Kotlin.

use std::sync::{Arc, Mutex};

use super::error::{Result, StorageError};
use super::types::{
    AccountId, CredentialData, CredentialFilter, CredentialId, CredentialRecord,
    CredentialTransfer, ImportOutcome, PendingAction, ProvisioningEnvelope,
};
use crate::credential_storage::{
    account::{AccountHandle as InternalAccountHandle, WorldIdStore as InternalWorldIdStore},
    pending::StubOnpClient,
    CredentialTransferBytes, VaultProvisioningEnvelope,
};

#[cfg(feature = "platform-ios")]
use crate::credential_storage::platform::ios::{
    IosBlobStore, IosKeystore, IosLockManager, IosPlatform, IosVaultStore,
};

#[cfg(feature = "platform-ios")]
type PlatformKeystore = IosKeystore;
#[cfg(feature = "platform-ios")]
type PlatformBlobStore = IosBlobStore;
#[cfg(feature = "platform-ios")]
type PlatformVaultStore = IosVaultStore;
#[cfg(feature = "platform-ios")]
type PlatformLockManager = IosLockManager;
#[cfg(feature = "platform-ios")]
type Platform = IosPlatform;

// Fallback for when no platform is configured (compilation only, not functional)
#[cfg(not(any(feature = "platform-ios")))]
compile_error!("A platform feature must be enabled (e.g., platform-ios)");

/// World ID credential store.
///
/// This is the main entry point for credential storage from Swift/Kotlin.
/// It manages multiple accounts on a single device.
///
/// # Example (Swift)
///
/// ```swift
/// let store = try WorldIdStore(rootPath: appSupportPath)
/// let accounts = try store.listAccounts()
/// let handle = try store.createAccount()
/// ```
#[derive(uniffi::Object)]
pub struct WorldIdStore {
    #[cfg(feature = "platform-ios")]
    inner: InternalWorldIdStore<PlatformKeystore, Platform, PlatformLockManager>,
    #[cfg(feature = "platform-ios")]
    platform: Arc<Platform>,
}

#[cfg(feature = "platform-ios")]
#[uniffi::export]
impl WorldIdStore {
    /// Creates a new World ID store.
    ///
    /// # Arguments
    ///
    /// * `root_path` - The root directory for World ID data. On iOS, this
    ///   should typically be the Application Support directory.
    ///
    /// # Errors
    ///
    /// Returns an error if initialization fails.
    #[uniffi::constructor]
    pub fn new(root_path: String) -> Result<Arc<Self>> {
        let platform = IosPlatform::new(&root_path).map_err(StorageError::from)?;
        let platform = Arc::new(platform);

        let keystore = platform.keystore();
        let lock_manager = platform.lock_manager();

        let inner = InternalWorldIdStore::new(keystore, Arc::clone(&platform), lock_manager);

        Ok(Arc::new(Self { inner, platform }))
    }

    /// Lists all account IDs on this device.
    pub fn list_accounts(&self) -> Result<Vec<AccountId>> {
        let accounts = self.inner.list_accounts().map_err(StorageError::from)?;
        Ok(accounts.into_iter().map(AccountId::from).collect())
    }

    /// Creates a new account with fresh keys.
    ///
    /// # Returns
    ///
    /// A handle to the newly created account.
    pub fn create_account(self: &Arc<Self>) -> Result<Arc<AccountHandle>> {
        let handle = self.inner.create_account().map_err(StorageError::from)?;
        Ok(Arc::new(AccountHandle::new(handle)))
    }

    /// Opens an existing account.
    ///
    /// # Arguments
    ///
    /// * `account_id` - The account ID to open.
    pub fn open_account(self: &Arc<Self>, account_id: AccountId) -> Result<Arc<AccountHandle>> {
        let id = account_id.to_internal().map_err(|e| StorageError::InvalidInput {
            parameter: "account_id".to_string(),
            message: e,
        })?;

        let handle = self.inner.open_account(&id).map_err(StorageError::from)?;
        Ok(Arc::new(AccountHandle::new(handle)))
    }

    /// Imports an account from a provisioning envelope.
    ///
    /// This is used when setting up a new device with an existing account.
    ///
    /// # Arguments
    ///
    /// * `envelope` - The provisioning envelope from an existing device.
    /// * `device_secret_key` - This device's X25519 private key (32 bytes).
    pub fn import_provisioning_envelope(
        self: &Arc<Self>,
        envelope: ProvisioningEnvelope,
        device_secret_key: Vec<u8>,
    ) -> Result<Arc<AccountHandle>> {
        let env: VaultProvisioningEnvelope = envelope.into();
        let handle = self
            .inner
            .import_vault_provisioning_envelope(&env, &device_secret_key)
            .map_err(StorageError::from)?;
        Ok(Arc::new(AccountHandle::new(handle)))
    }

    /// Deletes an account and all its data.
    ///
    /// # Warning
    ///
    /// This operation is irreversible!
    pub fn delete_account(&self, account_id: AccountId) -> Result<()> {
        let id = account_id.to_internal().map_err(|e| StorageError::InvalidInput {
            parameter: "account_id".to_string(),
            message: e,
        })?;

        self.platform
            .delete_account(&id)
            .map_err(StorageError::from)
    }
}

/// Handle to a World ID account.
///
/// This provides all operations for a specific account including:
/// - Credential CRUD
/// - Nullifier protection
/// - Key derivation
/// - Credential transfer
///
/// # Example (Swift)
///
/// ```swift
/// let handle = try store.createAccount()
///
/// // Store a credential
/// try handle.storeCredential(
///     credentialId: generateCredentialId(),
///     credentialBlob: credData,
///     associatedData: nil
/// )
///
/// // List credentials
/// let creds = try handle.listCredentials(filter: CredentialFilter())
/// ```
#[derive(uniffi::Object)]
pub struct AccountHandle {
    #[cfg(feature = "platform-ios")]
    inner: Mutex<
        InternalAccountHandle<PlatformKeystore, PlatformBlobStore, PlatformVaultStore, PlatformLockManager>,
    >,
}

#[cfg(feature = "platform-ios")]
impl AccountHandle {
    fn new(
        handle: InternalAccountHandle<
            PlatformKeystore,
            PlatformBlobStore,
            PlatformVaultStore,
            PlatformLockManager,
        >,
    ) -> Self {
        Self {
            inner: Mutex::new(handle),
        }
    }
}

#[cfg(feature = "platform-ios")]
#[uniffi::export]
impl AccountHandle {
    /// Returns the account ID.
    pub fn account_id(&self) -> AccountId {
        let inner = self.inner.lock().unwrap();
        AccountId::from(inner.account_id())
    }

    /// Returns the device ID.
    pub fn device_id(&self) -> Vec<u8> {
        let inner = self.inner.lock().unwrap();
        inner.device_id().to_vec()
    }

    /// Stores a credential.
    ///
    /// # Arguments
    ///
    /// * `credential_id` - Unique identifier for this credential
    /// * `credential_blob` - The main credential data
    /// * `associated_data` - Optional associated metadata
    pub fn store_credential(
        &self,
        credential_id: CredentialId,
        credential_blob: Vec<u8>,
        associated_data: Option<Vec<u8>>,
    ) -> Result<()> {
        let cred_id = credential_id.to_internal().map_err(|e| StorageError::InvalidInput {
            parameter: "credential_id".to_string(),
            message: e,
        })?;

        let mut inner = self.inner.lock().unwrap();
        inner
            .put_credential(
                cred_id,
                0, // issuer_schema_id - default to 0 for simple API
                None,
                &credential_blob,
                associated_data.as_deref(),
            )
            .map_err(StorageError::from)
    }

    /// Stores or updates a credential with full metadata.
    ///
    /// # Arguments
    ///
    /// * `credential_id` - Unique identifier for this credential
    /// * `issuer_schema_id` - Schema identifier from the registry
    /// * `expires_at` - Optional Unix timestamp when the credential expires
    /// * `credential_blob` - The main credential data
    /// * `associated_data` - Optional associated metadata
    pub fn put_credential(
        &self,
        credential_id: CredentialId,
        issuer_schema_id: u64,
        expires_at: Option<u64>,
        credential_blob: Vec<u8>,
        associated_data: Option<Vec<u8>>,
    ) -> Result<()> {
        let cred_id = credential_id.to_internal().map_err(|e| StorageError::InvalidInput {
            parameter: "credential_id".to_string(),
            message: e,
        })?;

        let mut inner = self.inner.lock().unwrap();
        inner
            .put_credential(
                cred_id,
                issuer_schema_id,
                expires_at,
                &credential_blob,
                associated_data.as_deref(),
            )
            .map_err(StorageError::from)
    }

    /// Retrieves a credential's blob data.
    ///
    /// # Returns
    ///
    /// The credential blob and optional associated data.
    pub fn get_credential(&self, credential_id: CredentialId) -> Result<CredentialData> {
        let cred_id = credential_id.to_internal().map_err(|e| StorageError::InvalidInput {
            parameter: "credential_id".to_string(),
            message: e,
        })?;

        let inner = self.inner.lock().unwrap();
        let (credential_blob, associated_data) =
            inner.get_credential(cred_id).map_err(StorageError::from)?;

        Ok(CredentialData {
            credential_blob,
            associated_data,
        })
    }

    /// Gets a credential's metadata without reading blobs.
    pub fn get_credential_record(&self, credential_id: CredentialId) -> Result<CredentialRecord> {
        let cred_id = credential_id.to_internal().map_err(|e| StorageError::InvalidInput {
            parameter: "credential_id".to_string(),
            message: e,
        })?;

        let inner = self.inner.lock().unwrap();
        inner
            .get_credential_record(cred_id)
            .map(CredentialRecord::from)
            .map_err(StorageError::from)
    }

    /// Lists credentials matching a filter.
    ///
    /// # Arguments
    ///
    /// * `filter` - Filter criteria. Use `CredentialFilter()` for defaults
    ///   (all active, non-expired credentials).
    pub fn list_credentials(&self, filter: CredentialFilter) -> Result<Vec<CredentialRecord>> {
        let inner = self.inner.lock().unwrap();
        let records = inner
            .list_credentials(Some(filter.into()))
            .map_err(StorageError::from)?;

        Ok(records.into_iter().map(CredentialRecord::from).collect())
    }

    /// Marks a credential as retired (soft-delete).
    pub fn retire_credential(&self, credential_id: CredentialId) -> Result<()> {
        let cred_id = credential_id.to_internal().map_err(|e| StorageError::InvalidInput {
            parameter: "credential_id".to_string(),
            message: e,
        })?;

        let mut inner = self.inner.lock().unwrap();
        inner
            .retire_credential(cred_id)
            .map_err(StorageError::from)
    }

    /// Derives the issuer blinding factor for a schema.
    ///
    /// This is deterministic - the same input always produces the same output.
    pub fn derive_issuer_blind(&self, issuer_schema_id: u64) -> Vec<u8> {
        let inner = self.inner.lock().unwrap();
        inner.derive_issuer_blind(issuer_schema_id).to_vec()
    }

    /// Derives the session randomness for an action.
    ///
    /// # Arguments
    ///
    /// * `rp_id` - 32-byte relying party identifier
    /// * `action_id` - 32-byte action identifier
    pub fn derive_session_r(&self, rp_id: Vec<u8>, action_id: Vec<u8>) -> Result<Vec<u8>> {
        if rp_id.len() != 32 {
            return Err(StorageError::InvalidInput {
                parameter: "rp_id".to_string(),
                message: "Must be exactly 32 bytes".to_string(),
            });
        }
        if action_id.len() != 32 {
            return Err(StorageError::InvalidInput {
                parameter: "action_id".to_string(),
                message: "Must be exactly 32 bytes".to_string(),
            });
        }

        let mut rp_arr = [0u8; 32];
        rp_arr.copy_from_slice(&rp_id);
        let mut action_arr = [0u8; 32];
        action_arr.copy_from_slice(&action_id);

        let inner = self.inner.lock().unwrap();
        Ok(inner.derive_session_r(&rp_arr, &action_arr).to_vec())
    }

    /// Exports a credential for transfer to another device.
    pub fn export_credential(&self, credential_id: CredentialId) -> Result<CredentialTransfer> {
        let cred_id = credential_id.to_internal().map_err(|e| StorageError::InvalidInput {
            parameter: "credential_id".to_string(),
            message: e,
        })?;

        let inner = self.inner.lock().unwrap();
        inner
            .export_credential(cred_id)
            .map(CredentialTransfer::from)
            .map_err(StorageError::from)
    }

    /// Exports a retired credential as a tombstone.
    pub fn export_credential_tombstone(
        &self,
        credential_id: CredentialId,
    ) -> Result<CredentialTransfer> {
        let cred_id = credential_id.to_internal().map_err(|e| StorageError::InvalidInput {
            parameter: "credential_id".to_string(),
            message: e,
        })?;

        let inner = self.inner.lock().unwrap();
        inner
            .export_credential_tombstone(cred_id)
            .map(CredentialTransfer::from)
            .map_err(StorageError::from)
    }

    /// Imports a credential from transfer bytes.
    ///
    /// Import is idempotent - calling multiple times with the same transfer
    /// is safe. Conflict resolution is timestamp-based.
    pub fn import_credential(&self, transfer: CredentialTransfer) -> Result<ImportOutcome> {
        let bytes: CredentialTransferBytes = transfer.into();
        let mut inner = self.inner.lock().unwrap();
        inner
            .import_credential(&bytes)
            .map(ImportOutcome::from)
            .map_err(StorageError::from)
    }

    /// Exports all credentials for bulk transfer.
    pub fn export_all_credentials(&self) -> Result<Vec<CredentialTransfer>> {
        let inner = self.inner.lock().unwrap();
        let transfers = inner
            .export_all_credentials()
            .map_err(StorageError::from)?;

        Ok(transfers
            .into_iter()
            .map(CredentialTransfer::from)
            .collect())
    }

    /// Imports multiple credentials from transfer bytes.
    pub fn import_credentials(&self, transfers: Vec<CredentialTransfer>) -> Result<Vec<ImportOutcome>> {
        let bytes: Vec<CredentialTransferBytes> = transfers.into_iter().map(Into::into).collect();
        let mut inner = self.inner.lock().unwrap();
        let outcomes = inner
            .import_credentials(&bytes)
            .map_err(StorageError::from)?;

        Ok(outcomes.into_iter().map(ImportOutcome::from).collect())
    }

    /// Exports a provisioning envelope for a new device.
    ///
    /// # Arguments
    ///
    /// * `recipient_device_pubkey` - The new device's X25519 public key (32 bytes)
    ///
    /// # Security
    ///
    /// Only send this envelope over a secure channel or after verifying
    /// the recipient's identity out-of-band.
    pub fn export_provisioning_envelope(
        &self,
        recipient_device_pubkey: Vec<u8>,
    ) -> Result<ProvisioningEnvelope> {
        let inner = self.inner.lock().unwrap();
        inner
            .export_vault_provisioning_envelope(&recipient_device_pubkey)
            .map(ProvisioningEnvelope::from)
            .map_err(StorageError::from)
    }

    /// Begins action disclosure (nullifier protection).
    ///
    /// This stores the pending action and returns the proof package.
    /// Call `commitAction` after the RP verifies the proof, or
    /// `cancelAction` if the disclosure is abandoned.
    ///
    /// # Arguments
    ///
    /// * `rp_id` - 32-byte relying party identifier
    /// * `action_id` - 32-byte action identifier
    /// * `signed_request_bytes` - The signed proof request
    /// * `nullifier` - 32-byte nullifier being disclosed
    /// * `proof_package` - The complete proof package
    pub fn begin_action_disclosure(
        &self,
        rp_id: Vec<u8>,
        action_id: Vec<u8>,
        signed_request_bytes: Vec<u8>,
        nullifier: Vec<u8>,
        proof_package: Vec<u8>,
    ) -> Result<Vec<u8>> {
        if rp_id.len() != 32 {
            return Err(StorageError::InvalidInput {
                parameter: "rp_id".to_string(),
                message: "Must be exactly 32 bytes".to_string(),
            });
        }
        if action_id.len() != 32 {
            return Err(StorageError::InvalidInput {
                parameter: "action_id".to_string(),
                message: "Must be exactly 32 bytes".to_string(),
            });
        }
        if nullifier.len() != 32 {
            return Err(StorageError::InvalidInput {
                parameter: "nullifier".to_string(),
                message: "Must be exactly 32 bytes".to_string(),
            });
        }

        let mut rp_arr = [0u8; 32];
        rp_arr.copy_from_slice(&rp_id);
        let mut action_arr = [0u8; 32];
        action_arr.copy_from_slice(&action_id);
        let mut null_arr = [0u8; 32];
        null_arr.copy_from_slice(&nullifier);

        // For now, use stub ONP client. In production, this should be
        // injected or configured.
        let onp = StubOnpClient::new();

        let inner = self.inner.lock().unwrap();
        inner
            .begin_action_disclosure(
                &rp_arr,
                &action_arr,
                &signed_request_bytes,
                &null_arr,
                &proof_package,
                &onp,
            )
            .map_err(StorageError::from)
    }

    /// Commits an action after successful RP verification.
    pub fn commit_action(&self, rp_id: Vec<u8>, action_id: Vec<u8>) -> Result<()> {
        if rp_id.len() != 32 {
            return Err(StorageError::InvalidInput {
                parameter: "rp_id".to_string(),
                message: "Must be exactly 32 bytes".to_string(),
            });
        }
        if action_id.len() != 32 {
            return Err(StorageError::InvalidInput {
                parameter: "action_id".to_string(),
                message: "Must be exactly 32 bytes".to_string(),
            });
        }

        let mut rp_arr = [0u8; 32];
        rp_arr.copy_from_slice(&rp_id);
        let mut action_arr = [0u8; 32];
        action_arr.copy_from_slice(&action_id);

        let onp = StubOnpClient::new();

        let inner = self.inner.lock().unwrap();
        inner
            .commit_action(&rp_arr, &action_arr, &onp)
            .map_err(StorageError::from)
    }

    /// Cancels an action without consuming the nullifier.
    pub fn cancel_action(&self, rp_id: Vec<u8>, action_id: Vec<u8>) -> Result<()> {
        if rp_id.len() != 32 {
            return Err(StorageError::InvalidInput {
                parameter: "rp_id".to_string(),
                message: "Must be exactly 32 bytes".to_string(),
            });
        }
        if action_id.len() != 32 {
            return Err(StorageError::InvalidInput {
                parameter: "action_id".to_string(),
                message: "Must be exactly 32 bytes".to_string(),
            });
        }

        let mut rp_arr = [0u8; 32];
        rp_arr.copy_from_slice(&rp_id);
        let mut action_arr = [0u8; 32];
        action_arr.copy_from_slice(&action_id);

        let inner = self.inner.lock().unwrap();
        inner
            .cancel_action(&rp_arr, &action_arr)
            .map_err(StorageError::from)
    }

    /// Lists all pending actions.
    pub fn list_pending_actions(&self, prune_expired: bool) -> Result<Vec<PendingAction>> {
        let inner = self.inner.lock().unwrap();
        let actions = inner
            .list_pending_actions(prune_expired)
            .map_err(StorageError::from)?;

        Ok(actions.into_iter().map(PendingAction::from).collect())
    }

    /// Gets the cached leaf index.
    pub fn get_leaf_index_cache(&self) -> Result<Option<u64>> {
        let inner = self.inner.lock().unwrap();
        inner.get_leaf_index_cache().map_err(StorageError::from)
    }

    /// Sets the cached leaf index.
    pub fn set_leaf_index_cache(&self, leaf_index: u64) -> Result<()> {
        let mut inner = self.inner.lock().unwrap();
        inner
            .set_leaf_index_cache(leaf_index)
            .map_err(StorageError::from)
    }
}
