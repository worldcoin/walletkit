//! Encrypted vault database for credential storage.

mod helpers;
mod schema;
#[cfg(test)]
mod tests;

use std::path::Path;

use walletkit_db::cipher;
use walletkit_db::{params, Connection, StepResult, Value};
use crate::storage::error::{StorageError, StorageResult};
use crate::storage::lock::StorageLockGuard;
use crate::storage::types::{BlobKind, CredentialRecord};
use helpers::{
    compute_content_id, map_db_err, map_record, to_i64, to_u64,
};
use schema::{ensure_schema, VAULT_SCHEMA_VERSION};

/// Encrypted vault database wrapper.
#[derive(Debug)]
pub struct VaultDb {
    conn: Connection,
}

impl VaultDb {
    /// Opens or creates the encrypted vault database at `path`.
    ///
    /// # Errors
    ///
    /// Returns an error if the database cannot be opened, keyed, or initialized.
    pub fn new(
        path: &Path,
        k_intermediate: [u8; 32],
        _lock: &StorageLockGuard,
    ) -> StorageResult<Self> {
        let conn = cipher::open_encrypted(path, k_intermediate, false)
            .map_err(|e| map_db_err(&e))?;
        ensure_schema(&conn)?;
        let db = Self { conn };
        if !db.check_integrity()? {
            return Err(StorageError::CorruptedVault(
                "integrity_check failed".to_string(),
            ));
        }
        Ok(db)
    }

    /// Initializes or validates the leaf index for this vault.
    ///
    /// The leaf index is the account's position in the registry tree and must be
    /// consistent for all subsequent operations. A mismatch returns an error.
    ///
    /// # Errors
    ///
    /// Returns an error if the stored leaf index does not match.
    pub fn init_leaf_index(
        &mut self,
        _lock: &StorageLockGuard,
        leaf_index: u64,
        now: u64,
    ) -> StorageResult<()> {
        let leaf_index_i64 = to_i64(leaf_index, "leaf_index")?;
        let now_i64 = to_i64(now, "now")?;
        let tx = self.conn.transaction().map_err(|err| map_db_err(&err))?;
        let stored = tx
            .query_row(
                "INSERT INTO vault_meta (schema_version, leaf_index, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?3)
                 ON CONFLICT(schema_version) DO UPDATE SET
                     leaf_index = CASE
                         WHEN vault_meta.leaf_index IS NULL
                         THEN excluded.leaf_index
                         ELSE vault_meta.leaf_index
                     END
                 RETURNING leaf_index",
                params![
                    VAULT_SCHEMA_VERSION,
                    leaf_index_i64,
                    now_i64,
                ],
                |stmt| Ok(stmt.column_i64(0)),
            )
            .map_err(|err| map_db_err(&err))?;
        if stored != leaf_index_i64 {
            let expected = to_u64(stored, "leaf_index")?;
            return Err(StorageError::InvalidLeafIndex {
                expected,
                provided: leaf_index,
            });
        }
        tx.commit().map_err(|err| map_db_err(&err))?;
        Ok(())
    }

    /// Stores a credential and optional associated data.
    ///
    /// Blob content is deduplicated by content id to avoid storing identical
    /// payloads multiple times.
    ///
    /// # Errors
    ///
    /// Returns an error if any insert fails.
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::needless_pass_by_value)]
    pub fn store_credential(
        &mut self,
        _lock: &StorageLockGuard,
        issuer_schema_id: u64,
        subject_blinding_factor: [u8; 32],
        genesis_issued_at: u64,
        expires_at: u64,
        credential_blob: Vec<u8>,
        associated_data: Option<Vec<u8>>,
        now: u64,
    ) -> StorageResult<u64> {
        let credential_blob_id =
            compute_content_id(BlobKind::CredentialBlob, &credential_blob);
        let associated_data_id = associated_data
            .as_ref()
            .map(|bytes| compute_content_id(BlobKind::AssociatedData, bytes));
        let now_i64 = to_i64(now, "now")?;
        let issuer_schema_id_i64 = to_i64(issuer_schema_id, "issuer_schema_id")?;
        let genesis_issued_at_i64 = to_i64(genesis_issued_at, "genesis_issued_at")?;
        let expires_at_i64 = to_i64(expires_at, "expires_at")?;

        let tx = self.conn.transaction().map_err(|err| map_db_err(&err))?;
        tx.execute(
            "INSERT OR IGNORE INTO blob_objects (content_id, blob_kind, created_at, bytes)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                credential_blob_id.as_ref(),
                BlobKind::CredentialBlob.as_i64(),
                now_i64,
                credential_blob.as_slice(),
            ],
        )
        .map_err(|err| map_db_err(&err))?;

        if let Some(data) = associated_data {
            let cid = associated_data_id.as_ref().ok_or_else(|| {
                StorageError::VaultDb("associated data CID must be present".to_string())
            })?;
            tx.execute(
                "INSERT OR IGNORE INTO blob_objects (content_id, blob_kind, created_at, bytes)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    cid.as_ref(),
                    BlobKind::AssociatedData.as_i64(),
                    now_i64,
                    data.as_slice(),
                ],
            )
            .map_err(|err| map_db_err(&err))?;
        }

        let ad_cid_value: Value = associated_data_id
            .as_ref()
            .map_or(Value::Null, |cid| Value::Blob(cid.to_vec()));

        let credential_id = tx
            .query_row(
                "INSERT INTO credential_records (
                    issuer_schema_id,
                    subject_blinding_factor,
                    genesis_issued_at,
                    expires_at,
                    updated_at,
                    credential_blob_cid,
                    associated_data_cid
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                RETURNING credential_id",
                params![
                    issuer_schema_id_i64,
                    subject_blinding_factor.as_ref(),
                    genesis_issued_at_i64,
                    expires_at_i64,
                    now_i64,
                    credential_blob_id.as_ref(),
                    ad_cid_value,
                ],
                |stmt| Ok(stmt.column_i64(0)),
            )
            .map_err(|err| map_db_err(&err))?;

        tx.commit().map_err(|err| map_db_err(&err))?;
        to_u64(credential_id, "credential_id")
    }

    /// Lists active credential metadata, optionally filtered by issuer schema.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub fn list_credentials(
        &self,
        issuer_schema_id: Option<u64>,
        now: u64,
    ) -> StorageResult<Vec<CredentialRecord>> {
        let expires = to_i64(now, "now")?;
        let issuer_schema_id_i64 = issuer_schema_id
            .map(|value| to_i64(value, "issuer_schema_id"))
            .transpose()?;

        let mut records = Vec::new();

        if let Some(issuer_id) = issuer_schema_id_i64 {
            let sql = "SELECT
                    cr.credential_id,
                    cr.issuer_schema_id,
                    cr.expires_at
                 FROM credential_records cr
                 WHERE cr.expires_at > ?1
                   AND cr.issuer_schema_id = ?2
                 ORDER BY cr.updated_at DESC";
            let stmt = self.conn.prepare(sql).map_err(|err| map_db_err(&err))?;
            stmt.bind_values(params![expires, issuer_id])
            .map_err(|err| map_db_err(&err))?;
            while let StepResult::Row(row) =
                stmt.step().map_err(|err| map_db_err(&err))?
            {
                records.push(map_record(&row)?);
            }
        } else {
            let sql = "SELECT
                    cr.credential_id,
                    cr.issuer_schema_id,
                    cr.expires_at
                 FROM credential_records cr
                 WHERE cr.expires_at > ?1
                 ORDER BY cr.updated_at DESC";
            let stmt = self.conn.prepare(sql).map_err(|err| map_db_err(&err))?;
            stmt.bind_values(params![expires])
                .map_err(|err| map_db_err(&err))?;
            while let StepResult::Row(row) =
                stmt.step().map_err(|err| map_db_err(&err))?
            {
                records.push(map_record(&row)?);
            }
        }
        Ok(records)
    }

    /// Runs an integrity check on the vault database.
    ///
    /// # Errors
    ///
    /// Returns an error if the check cannot be executed.
    pub fn check_integrity(&self) -> StorageResult<bool> {
        cipher::integrity_check(&self.conn).map_err(|e| map_db_err(&e))
    }
}
