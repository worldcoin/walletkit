//! Additive backup recovery. Row IDs are local database keys, not credential identities.
//! Absence from a snapshot is not a deletion instruction: preserve receiver-only credentials.

use std::path::Path;

use super::{map_db_err, CredentialVault};
use crate::storage::error::{StorageError, StorageResult};
use walletkit_db::blobs::compute_content_id;
use walletkit_sqlite::{params, Connection, StepResult};

impl CredentialVault {
    /// Atomically merges a plaintext backup, returning the number of added records.
    /// Existing IDs and credentials are preserved; replaying the same snapshot is a no-op.
    /// Source IDs are deliberately ignored because independently written vaults reuse them.
    /// Each distinct version, including its `updated_at`, is retained. The issuer, subject,
    /// and genesis fields do not uniquely identify a stored version: normal writes append
    /// records and reads select the most recent non-expired one. Recovery does not compact
    /// that history or replace receiver rows.
    ///
    /// Callers must keep the source file stable until the merge completes. Callers that
    /// need cross-process exclusion around backup-file creation/cleanup must hold
    /// [`crate::storage::StorageLock`] themselves, as [`super::CredentialVault::import_plaintext`]
    /// requires. Prefer [`crate::storage::CredentialStore::merge_vault_from_backup`], which
    /// holds the lock for the complete temporary-file lifetime.
    ///
    /// # Errors
    /// Returns an error for malformed backup contents, unavailable storage, or a failed transaction.
    pub fn merge_plaintext(&self, source: &Path) -> StorageResult<u64> {
        if !source.is_file() {
            return Err(invalid_backup());
        }
        let conn = self.vault.connection();
        let source_path = source.to_string_lossy().replace('\'', "''");
        conn.execute_batch(&format!(
            "ATTACH DATABASE '{source_path}' AS incoming KEY '';"
        ))
        .map_err(|e| map_db_err(&e))?;
        let result = merge_attached(conn);
        let detached = conn.execute_batch("DETACH DATABASE incoming;");
        let added = result?;
        detached.map_err(|e| map_db_err(&e))?;
        Ok(added)
    }
}

fn invalid_backup() -> StorageError {
    StorageError::VaultDb("invalid credential backup contents".to_owned())
}

fn merge_attached(conn: &Connection) -> StorageResult<u64> {
    let tx = conn.transaction_immediate().map_err(|e| map_db_err(&e))?;
    // Exports made with CREATE TABLE AS have no NOT NULL or type constraints.
    // Validate before using SQLite's permissive getters or writing destination data.
    let invalid: i64 = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM incoming.blob_objects WHERE
            typeof(content_id) != 'blob' OR length(content_id) != 32 OR
            typeof(blob_kind) != 'integer' OR blob_kind NOT IN (1, 2) OR
            typeof(created_at) != 'integer' OR created_at < 0 OR typeof(bytes) != 'blob')
         OR EXISTS(SELECT 1 FROM incoming.credential_records r WHERE
            typeof(issuer_schema_id) != 'integer' OR issuer_schema_id < 0 OR
            typeof(subject_blinding_factor) != 'blob' OR length(subject_blinding_factor) != 32 OR
            typeof(genesis_issued_at) != 'integer' OR genesis_issued_at < 0 OR
            typeof(expires_at) != 'integer' OR expires_at < 0 OR
            typeof(updated_at) != 'integer' OR updated_at < 0 OR
            typeof(credential_blob_cid) != 'blob' OR
            NOT EXISTS(SELECT 1 FROM incoming.blob_objects b WHERE b.content_id = r.credential_blob_cid AND b.blob_kind = 1) OR
            (associated_data_cid IS NOT NULL AND (typeof(associated_data_cid) != 'blob' OR
             NOT EXISTS(SELECT 1 FROM incoming.blob_objects b WHERE b.content_id = r.associated_data_cid AND b.blob_kind = 2))))",
        &[], |row| Ok(row.column_i64(0)),
    ).map_err(|e| map_db_err(&e))?;
    if invalid != 0 {
        return Err(invalid_backup());
    }

    {
        let mut blobs = tx
            .prepare("SELECT content_id, blob_kind, bytes FROM incoming.blob_objects")
            .map_err(|e| map_db_err(&e))?;
        while let StepResult::Row(row) = blobs.step().map_err(|e| map_db_err(&e))? {
            let kind = u8::try_from(row.column_i64(1)).map_err(|_| invalid_backup())?;
            if row.column_blob(0) != compute_content_id(kind, &row.column_blob(2)) {
                return Err(invalid_backup());
            }
        }
    }
    tx.execute_batch(
        "INSERT INTO blob_objects(content_id, blob_kind, created_at, bytes)
         SELECT content_id, blob_kind, MIN(created_at), bytes FROM incoming.blob_objects
         WHERE true GROUP BY content_id ON CONFLICT(content_id) DO NOTHING;",
    )
    .map_err(|e| map_db_err(&e))?;

    let mut added = 0;
    {
        let mut records = tx.prepare(
            "SELECT issuer_schema_id, subject_blinding_factor, genesis_issued_at, expires_at,
                    updated_at, credential_blob_cid, associated_data_cid
             FROM incoming.credential_records ORDER BY updated_at DESC",
        ).map_err(|e| map_db_err(&e))?;
        while let StepResult::Row(row) = records.step().map_err(|e| map_db_err(&e))? {
            let associated = if row.is_column_null(6) {
                walletkit_sqlite::Value::Null
            } else {
                walletkit_sqlite::Value::Blob(row.column_blob(6))
            };
            let count = tx.execute(
                "INSERT INTO credential_records(issuer_schema_id, subject_blinding_factor,
                    genesis_issued_at, expires_at, updated_at, credential_blob_cid, associated_data_cid)
                 SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7 WHERE NOT EXISTS (
                    SELECT 1 FROM credential_records WHERE issuer_schema_id = ?1
                    AND subject_blinding_factor = ?2 AND genesis_issued_at = ?3 AND expires_at = ?4
                    AND updated_at = ?5
                    AND credential_blob_cid = ?6 AND associated_data_cid IS ?7)",
                params![row.column_i64(0), row.column_blob(1), row.column_i64(2), row.column_i64(3),
                        row.column_i64(4), row.column_blob(5), associated],
            ).map_err(|e| map_db_err(&e))?;
            added += count as u64;
        }
    }
    tx.commit().map_err(|e| map_db_err(&e))?;
    Ok(added)
}

#[cfg(test)]
mod tests;
