//! Encrypted credential storage, backed by the browser's OPFS pool.

use std::{str::FromStr, sync::Arc};

use js_sys::BigInt;
use walletkit_core::storage::{
    initialize_persistent_storage, ActivityEntry, ActivityFailureReason,
    ActivityOutcome, ActivityQuery, CredentialRecord, CredentialStore, ProtocolVersion,
    StorageKeys, StoragePaths,
};
use wasm_bindgen::prelude::*;

use crate::{
    error::{invalid_argument, to_js},
    js,
    values::{JsCredential, JsFieldElement},
};

/// Acquires the OPFS storage pool for this worker.
///
/// Must be awaited once before a [`JsCredentialStore`] is created.
///
/// # Errors
/// Rejects outside a dedicated worker or when another context owns the pool.
#[wasm_bindgen(js_name = initializePersistentStorage, unchecked_return_type = "Promise<void>")]
pub fn initialize_persistent_storage_js() -> js_sys::Promise {
    js::promise(async {
        initialize_persistent_storage().await.map_err(to_js)?;
        Ok(JsValue::UNDEFINED)
    })
}

/// The 32-byte database key that encrypts the credential store.
#[wasm_bindgen(js_name = StorageKeys)]
pub struct JsStorageKeys(Arc<StorageKeys>);

#[wasm_bindgen(js_class = StorageKeys)]
impl JsStorageKeys {
    /// Wraps the resolved database key.
    ///
    /// # Errors
    /// Throws a `StorageError` when the key is not 32 bytes.
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(database_key: Vec<u8>) -> Result<Self, JsValue> {
        StorageKeys::from_bytes(database_key)
            .map(|keys| Self(Arc::new(keys)))
            .map_err(to_js)
    }
}

/// The location of the credential store inside the OPFS pool.
#[wasm_bindgen(js_name = StoragePaths)]
pub struct JsStoragePaths(Arc<StoragePaths>);

#[wasm_bindgen(js_class = StoragePaths)]
impl JsStoragePaths {
    /// Derives every storage path from `root`, for example `/walletkit/<account>`.
    #[wasm_bindgen(js_name = fromRoot)]
    #[must_use]
    pub fn from_root(root: String) -> Self {
        Self(Arc::new(StoragePaths::from_root(root)))
    }

    #[wasm_bindgen(js_name = rootPathString)]
    #[must_use]
    pub fn root_path_string(&self) -> String {
        self.0.root_path_string()
    }

    #[wasm_bindgen(js_name = worldidDirPathString)]
    #[must_use]
    pub fn worldid_dir_path_string(&self) -> String {
        self.0.worldid_dir_path_string()
    }

    #[wasm_bindgen(js_name = vaultDbPathString)]
    #[must_use]
    pub fn vault_db_path_string(&self) -> String {
        self.0.vault_db_path_string()
    }

    #[wasm_bindgen(js_name = cacheDbPathString)]
    #[must_use]
    pub fn cache_db_path_string(&self) -> String {
        self.0.cache_db_path_string()
    }

    #[wasm_bindgen(js_name = lockPathString)]
    #[must_use]
    pub fn lock_path_string(&self) -> String {
        self.0.lock_path_string()
    }

    #[wasm_bindgen(js_name = groth16DirPathString)]
    #[must_use]
    pub fn groth16_dir_path_string(&self) -> String {
        self.0.groth16_dir_path_string()
    }

    #[wasm_bindgen(js_name = queryZkeyPathString)]
    #[must_use]
    pub fn query_zkey_path_string(&self) -> String {
        self.0.query_zkey_path_string()
    }

    #[wasm_bindgen(js_name = nullifierZkeyPathString)]
    #[must_use]
    pub fn nullifier_zkey_path_string(&self) -> String {
        self.0.nullifier_zkey_path_string()
    }

    #[wasm_bindgen(js_name = queryGraphPathString)]
    #[must_use]
    pub fn query_graph_path_string(&self) -> String {
        self.0.query_graph_path_string()
    }

    #[wasm_bindgen(js_name = nullifierGraphPathString)]
    #[must_use]
    pub fn nullifier_graph_path_string(&self) -> String {
        self.0.nullifier_graph_path_string()
    }
}

/// Filters for [`JsCredentialStore::list_activities`], built like the native builder.
#[wasm_bindgen(js_name = ActivityQuery)]
pub struct JsActivityQuery(ActivityQuery);

#[wasm_bindgen(js_class = ActivityQuery)]
impl JsActivityQuery {
    /// A query without filters.
    #[wasm_bindgen(js_name = new)]
    #[must_use]
    pub fn new() -> Self {
        Self(ActivityQuery::new())
    }

    /// Restricts the query to activity that disclosed `issuer_schema_id`.
    ///
    /// # Errors
    /// Throws a `TypeError` when `issuer_schema_id` is not a bigint in the `u64` range.
    #[wasm_bindgen(js_name = withIssuerSchemaId)]
    pub fn with_issuer_schema_id(
        &self,
        issuer_schema_id: BigInt,
    ) -> Result<Self, JsValue> {
        let issuer_schema_id = js::u64_arg("issuerSchemaId", issuer_schema_id)?;
        Ok(Self(self.0.with_issuer_schema_id(issuer_schema_id)))
    }
}

impl Default for JsActivityQuery {
    fn default() -> Self {
        Self::new()
    }
}

/// The encrypted store of credentials and activity.
#[wasm_bindgen(js_name = CredentialStore)]
pub struct JsCredentialStore(pub(crate) Arc<CredentialStore>);

#[wasm_bindgen(js_class = CredentialStore)]
impl JsCredentialStore {
    /// Opens (or creates) the encrypted store at `paths`.
    ///
    /// # Errors
    /// Throws a `StorageError` when the store cannot be opened, for example with the
    /// wrong key or before `initializePersistentStorage` completed.
    #[wasm_bindgen(js_name = new)]
    pub fn new(paths: &JsStoragePaths, keys: &JsStorageKeys) -> Result<Self, JsValue> {
        CredentialStore::with_keys(paths.0.as_ref().clone(), Arc::clone(&keys.0))
            .map(|store| Self(Arc::new(store)))
            .map_err(to_js)
    }

    /// # Errors
    /// Throws a `StorageError` when the store is unavailable.
    #[wasm_bindgen(js_name = storagePaths)]
    pub fn storage_paths(&self) -> Result<JsStoragePaths, JsValue> {
        self.0
            .storage_paths()
            .map(|paths| JsStoragePaths(Arc::new(paths)))
            .map_err(to_js)
    }

    /// Binds the store to the account's `leaf_index`.
    ///
    /// # Errors
    /// Throws a `StorageError` when the store belongs to a different account.
    pub fn init(&self, leaf_index: BigInt, now: BigInt) -> Result<(), JsValue> {
        let leaf_index = js::u64_arg("leafIndex", leaf_index)?;
        self.0
            .init(leaf_index, js::u64_arg("now", now)?)
            .map_err(to_js)
    }

    /// Adds credentials from a plaintext vault backup, preserving local credentials.
    /// Returns the number added; replaying the same backup returns zero.
    /// The caller must authenticate the backup as belonging to this account.
    ///
    /// # Errors
    /// Throws a `StorageError` if the store is uninitialized, the backup is invalid,
    /// or the database operation fails. Invalid backups leave the vault unchanged.
    #[wasm_bindgen(js_name = mergeVaultFromBackup)]
    pub fn merge_vault_from_backup(&self, backup_bytes: &[u8]) -> Result<u64, JsValue> {
        self.0.merge_vault_from_backup(backup_bytes).map_err(to_js)
    }

    /// # Errors
    /// Throws a `StorageError` when the vault cannot be read.
    #[wasm_bindgen(js_name = listCredentials, unchecked_return_type = "CredentialRecord[]")]
    pub fn list_credentials(
        &self,
        issuer_schema_id: Option<BigInt>,
        now: BigInt,
    ) -> Result<JsValue, JsValue> {
        let issuer_schema_id =
            js::optional_u64_arg("issuerSchemaId", issuer_schema_id)?;
        let now = js::u64_arg("now", now)?;
        let records = self
            .0
            .list_credentials(issuer_schema_id, now)
            .map_err(to_js)?;
        let records = records
            .iter()
            .map(credential_record)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(js::array(records))
    }

    /// # Errors
    /// Throws a `StorageError` when the vault cannot be read.
    #[wasm_bindgen(js_name = fetchCredential)]
    pub fn fetch_credential(
        &self,
        issuer_schema_id: BigInt,
        now: BigInt,
    ) -> Result<Option<JsCredential>, JsValue> {
        let issuer_schema_id = js::u64_arg("issuerSchemaId", issuer_schema_id)?;
        let now = js::u64_arg("now", now)?;
        let credential = self
            .0
            .fetch_credential(issuer_schema_id, now)
            .map_err(to_js)?;
        Ok(credential.map(|credential| JsCredential((*credential).clone())))
    }

    /// # Errors
    /// Throws a `StorageError` when the credential does not exist.
    #[wasm_bindgen(js_name = deleteCredential)]
    pub fn delete_credential(&self, credential_id: BigInt) -> Result<(), JsValue> {
        self.0
            .delete_credential(js::u64_arg("credentialId", credential_id)?)
            .map_err(to_js)
    }

    /// Stores `credential` with its blinding factor and returns the new credential ID.
    ///
    /// # Errors
    /// Throws a `StorageError` when the store is not initialized or the write fails.
    #[wasm_bindgen(js_name = storeCredential)]
    pub fn store_credential(
        &self,
        credential: &JsCredential,
        blinding_factor: &JsFieldElement,
        expires_at: BigInt,
        associated_data: Option<Vec<u8>>,
        now: BigInt,
    ) -> Result<u64, JsValue> {
        let expires_at = js::u64_arg("expiresAt", expires_at)?;
        let now = js::u64_arg("now", now)?;
        self.0
            .store_credential(
                &credential.0,
                &blinding_factor.0,
                expires_at,
                associated_data,
                now,
            )
            .map_err(to_js)
    }

    /// # Errors
    /// Throws a `StorageError` when the vault cannot be written.
    #[wasm_bindgen(js_name = dangerDeleteAllCredentials)]
    pub fn danger_delete_all_credentials(&self) -> Result<u64, JsValue> {
        self.0.danger_delete_all_credentials().map_err(to_js)
    }

    /// # Errors
    /// Throws a `TypeError` for a malformed entry, or a `StorageError` when the write fails.
    #[wasm_bindgen(js_name = recordActivity)]
    pub fn record_activity(
        &self,
        #[wasm_bindgen(unchecked_param_type = "ActivityEntry")] entry: &JsValue,
        now: BigInt,
    ) -> Result<u64, JsValue> {
        let now = js::u64_arg("now", now)?;
        self.0
            .record_activity(&parse_activity_entry(entry)?, now)
            .map_err(to_js)
    }

    /// # Errors
    /// Throws a `StorageError` when the activity log cannot be read.
    #[wasm_bindgen(js_name = listActivities, unchecked_return_type = "ActivityEntry[]")]
    pub fn list_activities(
        &self,
        query: &JsActivityQuery,
        #[wasm_bindgen(unchecked_param_type = "number")] limit: f64,
        #[wasm_bindgen(unchecked_param_type = "number")] offset: f64,
    ) -> Result<JsValue, JsValue> {
        let (limit, offset) =
            (js::u32_arg("limit", limit)?, js::u32_arg("offset", offset)?);
        let entries = self
            .0
            .list_activities(&query.0, limit, offset)
            .map_err(to_js)?;
        let entries = entries
            .iter()
            .map(activity_entry)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(js::array(entries))
    }

    /// # Errors
    /// Throws a `StorageError` when the activity log cannot be read.
    #[wasm_bindgen(js_name = activityMetadata, unchecked_return_type = "ActivityMetadata")]
    pub fn activity_metadata(&self) -> Result<JsValue, JsValue> {
        let metadata = self.0.activity_metadata().map_err(to_js)?;
        js::object(&[("totalCount", metadata.total_count.into())])
    }

    /// Deletes the given activity entries and returns how many were removed.
    ///
    /// # Errors
    /// Throws a `TypeError` for malformed ids, or a `StorageError` when the write fails.
    #[wasm_bindgen(js_name = deleteActivities)]
    pub fn delete_activities(
        &self,
        #[wasm_bindgen(unchecked_param_type = "bigint[]")] entry_ids: &JsValue,
    ) -> Result<u64, JsValue> {
        let entry_ids = js::u64_array_arg("entryIds", entry_ids)?;
        self.0.delete_activities(entry_ids).map_err(to_js)
    }

    /// # Errors
    /// Throws a `StorageError` when the activity log cannot be written.
    #[wasm_bindgen(js_name = clearActivities)]
    pub fn clear_activities(&self) -> Result<u64, JsValue> {
        self.0.clear_activities().map_err(to_js)
    }

    /// Deletes the vault and cache files.
    ///
    /// # Errors
    /// Throws a `StorageError` when a file cannot be deleted.
    #[wasm_bindgen(js_name = destroyStorage)]
    pub fn destroy_storage(&self) -> Result<(), JsValue> {
        self.0.destroy_storage().map_err(to_js)
    }
}

fn credential_record(record: &CredentialRecord) -> Result<JsValue, JsValue> {
    js::object(&[
        ("credentialId", record.credential_id.into()),
        ("issuerSchemaId", record.issuer_schema_id.into()),
        ("genesisIssuedAt", record.genesis_issued_at.into()),
        ("expiresAt", record.expires_at.into()),
        ("isExpired", record.is_expired.into()),
    ])
}

fn activity_entry(entry: &ActivityEntry) -> Result<JsValue, JsValue> {
    js::object(&[
        ("id", entry.id.into()),
        ("rpId", entry.rp_id.into()),
        ("appIdentifier", entry.app_identifier.as_str().into()),
        ("clientId", entry.client_id.as_str().into()),
        ("protocol", f64::from(entry.protocol as u8).into()),
        ("timestamp", entry.timestamp.into()),
        ("outcome", entry.outcome.to_string().into()),
        (
            "issuerSchemaIds",
            js::array(entry.issuer_schema_ids.iter().map(|id| (*id).into())),
        ),
        (
            "failureReason",
            entry
                .failure_reason
                .map_or(JsValue::UNDEFINED, |reason| reason.to_string().into()),
        ),
    ])
}

fn parse_activity_entry(entry: &JsValue) -> Result<ActivityEntry, JsValue> {
    let protocol = match js::number_field(entry, "protocol")? {
        3.0 => ProtocolVersion::V3,
        4.0 => ProtocolVersion::V4,
        _ => return Err(invalid_argument("`protocol` must be 3 or 4")),
    };
    let outcome = js::string_field(entry, "outcome")?;
    let outcome = ActivityOutcome::from_str(&outcome)
        .map_err(|_| invalid_argument(&format!("Unknown outcome: {outcome}")))?;
    let failure_reason = js::optional_string_field(entry, "failureReason")?
        .map(|reason| {
            ActivityFailureReason::from_str(&reason).map_err(|_| {
                invalid_argument(&format!("Unknown failureReason: {reason}"))
            })
        })
        .transpose()?;

    Ok(ActivityEntry {
        id: js::optional_u64_field(entry, "id")?,
        rp_id: js::u64_field(entry, "rpId")?,
        app_identifier: js::string_field(entry, "appIdentifier")?,
        client_id: js::string_field(entry, "clientId")?,
        protocol,
        timestamp: js::optional_u64_field(entry, "timestamp")?,
        outcome,
        issuer_schema_ids: js::u64_array_field(entry, "issuerSchemaIds")?,
        failure_reason,
    })
}
