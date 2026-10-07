//! Storage paths, the credential store, activities, backups, and constraint checks.

use crate::native::{codec::Binary, error::Result};
use std::sync::Arc;
use walletkit_core::{
    proof_request_credential_constraints_check::{
        check_credentials_against_proof_request as check,
        CredentialConstraintsCheckResult,
    },
    requests::ProofRequest,
    storage::{
        credential_storage::CredentialStore,
        paths::StoragePaths,
        types::{ActivityEntry, ActivityQuery, CredentialRecord},
        ActivityChangedListener, AtomicBlobStore, DeviceKeystore, VaultChangedListener,
    },
    Credential, FieldElement,
};
#[cfg(feature = "jni")]
use walletkit_jni_macros::jni_export;

/// `StoragePaths.fromRoot`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn storage_paths_from_root(root: String) -> Arc<StoragePaths> {
    Arc::new(StoragePaths::from_root(root))
}

macro_rules! path_strings {
    ($($name:ident => $method:ident),* $(,)?) => {$(
        #[doc = concat!("`StoragePaths.", stringify!($method), "`.")]
        #[cfg_attr(feature = "jni", jni_export)]
        pub fn $name(paths: Arc<StoragePaths>) -> String {
            paths.$method()
        }
    )*};
}

path_strings! {
    storage_paths_root_path_string => root_path_string,
    storage_paths_worldid_dir_path_string => worldid_dir_path_string,
    storage_paths_vault_db_path_string => vault_db_path_string,
    storage_paths_cache_db_path_string => cache_db_path_string,
    storage_paths_lock_path_string => lock_path_string,
    storage_paths_groth16_dir_path_string => groth16_dir_path_string,
    storage_paths_query_zkey_path_string => query_zkey_path_string,
    storage_paths_nullifier_zkey_path_string => nullifier_zkey_path_string,
    storage_paths_query_graph_path_string => query_graph_path_string,
    storage_paths_nullifier_graph_path_string => nullifier_graph_path_string,
}

/// `CredentialStore.newWithComponents`. The callbacks are retained by the store.
#[cfg_attr(feature = "jni", jni_export)]
pub fn credential_store_new_with_components(
    paths: Arc<StoragePaths>,
    keystore: Arc<dyn DeviceKeystore>,
    blob_store: Arc<dyn AtomicBlobStore>,
) -> Result<Arc<CredentialStore>> {
    Ok(Arc::new(CredentialStore::new_with_components(
        paths, keystore, blob_store,
    )?))
}

/// `CredentialStore.storagePaths`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn credential_store_storage_paths(
    store: Arc<CredentialStore>,
) -> Result<Arc<StoragePaths>> {
    Ok(Arc::new(store.storage_paths()?))
}

/// `CredentialStore.initialize`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn credential_store_initialize(
    store: Arc<CredentialStore>,
    leaf_index: u64,
    now: u64,
) -> Result<()> {
    Ok(store.init(leaf_index, now)?)
}

/// `CredentialStore.listCredentials`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn credential_store_list_credentials(
    store: Arc<CredentialStore>,
    issuer_schema_id: Option<u64>,
    now: u64,
) -> Result<Binary<Vec<CredentialRecord>>> {
    Ok(Binary(store.list_credentials(issuer_schema_id, now)?))
}

/// `CredentialStore.fetchCredential`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn credential_store_fetch_credential(
    store: Arc<CredentialStore>,
    issuer_schema_id: u64,
    now: u64,
) -> Result<Option<Arc<Credential>>> {
    Ok(store.fetch_credential(issuer_schema_id, now)?)
}

/// `CredentialStore.deleteCredential`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn credential_store_delete_credential(
    store: Arc<CredentialStore>,
    credential_id: u64,
) -> Result<()> {
    Ok(store.delete_credential(credential_id)?)
}

/// `CredentialStore.storeCredential`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn credential_store_store_credential(
    store: Arc<CredentialStore>,
    credential: Arc<Credential>,
    blinding_factor: Arc<FieldElement>,
    expires_at: u64,
    associated_data: Option<Vec<u8>>,
    now: u64,
) -> Result<u64> {
    Ok(store.store_credential(
        &credential,
        &blinding_factor,
        expires_at,
        associated_data,
        now,
    )?)
}

/// `CredentialStore.dangerDeleteAllCredentials`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn credential_store_danger_delete_all_credentials(
    store: Arc<CredentialStore>,
) -> Result<u64> {
    Ok(store.danger_delete_all_credentials()?)
}

/// `CredentialStore.recordActivity`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn credential_store_record_activity(
    store: Arc<CredentialStore>,
    entry: Binary<ActivityEntry>,
    now: u64,
) -> Result<u64> {
    Ok(store.record_activity(&entry.0, now)?)
}

/// `CredentialStore.listActivities`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn credential_store_list_activities(
    store: Arc<CredentialStore>,
    issuer_schema_id: Option<u64>,
    limit: u32,
    offset: u32,
) -> Result<Binary<Vec<ActivityEntry>>> {
    let query = issuer_schema_id.map_or_else(ActivityQuery::new, |id| {
        ActivityQuery::new().with_issuer_schema_id(id)
    });
    Ok(Binary(store.list_activities(&query, limit, offset)?))
}

/// `CredentialStore.activityMetadata`: the total activity count.
#[cfg_attr(feature = "jni", jni_export)]
pub fn credential_store_activity_metadata(store: Arc<CredentialStore>) -> Result<u64> {
    Ok(store.activity_metadata()?.total_count)
}

/// `CredentialStore.clearActivities`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn credential_store_clear_activities(store: Arc<CredentialStore>) -> Result<u64> {
    Ok(store.clear_activities()?)
}

/// `CredentialStore.destroyStorage`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn credential_store_destroy_storage(store: Arc<CredentialStore>) -> Result<()> {
    Ok(store.destroy_storage()?)
}

/// `CredentialStore.exportVaultForBackup`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn credential_store_export_vault_for_backup(
    store: Arc<CredentialStore>,
) -> Result<Vec<u8>> {
    Ok(store.export_vault_for_backup()?)
}

/// `CredentialStore.importVaultFromBackup`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn credential_store_import_vault_from_backup(
    store: Arc<CredentialStore>,
    backup_bytes: Vec<u8>,
) -> Result<()> {
    Ok(store.import_vault_from_backup(&backup_bytes)?)
}

/// `CredentialStore.mergeVaultFromBackup`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn credential_store_merge_vault_from_backup(
    store: Arc<CredentialStore>,
    backup_bytes: Vec<u8>,
) -> Result<u64> {
    Ok(store.merge_vault_from_backup(&backup_bytes)?)
}

/// `CredentialStore.setVaultChangedListener`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn credential_store_set_vault_changed_listener(
    store: Arc<CredentialStore>,
    listener: Arc<dyn VaultChangedListener>,
) {
    store.set_vault_changed_listener(listener);
}

/// `CredentialStore.setActivityChangedListener`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn credential_store_set_activity_changed_listener(
    store: Arc<CredentialStore>,
    listener: Arc<dyn ActivityChangedListener>,
) {
    store.set_activity_changed_listener(listener);
}

/// `checkCredentialsAgainstProofRequest`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn check_credentials_against_proof_request(
    request: Arc<ProofRequest>,
    store: Arc<CredentialStore>,
    now: u64,
) -> Result<Binary<CredentialConstraintsCheckResult>> {
    Ok(Binary(check(&request, &store, now)?))
}
