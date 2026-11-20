//! Frozen v0.30.0 importer (70ecb13ae7eec13b6ba73082cba851a6fbc5951d).
//! <https://github.com/worldcoin/walletkit/blob/70ecb13ae7eec13b6ba73082cba851a6fbc5951d/crates/walletkit-core/src/storage/credential_vault/merge.rs>
//! Only the method name differs, to coexist with the current importer.

//! Additive backup recovery. Row IDs are local database keys, not credential identities.
//! Absence from a snapshot is not a deletion instruction: preserve receiver-only credentials.

use super::{map_db_err, CredentialVault, CREDENTIAL_VERSION_ORDER};
use crate::storage::error::{StorageError, StorageResult};
use walletkit_db::blobs::compute_content_id;
use walletkit_sqlite::{
    cipher::ensure_temp_store_memory, params, Connection, StepResult,
};

impl CredentialVault {
    /// Atomically merges a plaintext backup, returning the number of added records.
    /// Existing IDs and credentials are preserved; replaying the same snapshot is a no-op.
    /// Source IDs are deliberately ignored because independently written vaults reuse them.
    /// Each distinct version, including its `updated_at`, is retained. The issuer, subject,
    /// and genesis fields do not uniquely identify a stored version: normal writes append
    /// records and reads select the most recent non-expired one. Recovery does not compact
    /// that history or replace receiver rows.
    /// The semantic version set is an idempotent union. Equal timestamps use a
    /// content-based total order for both insertion and selection, so merge order
    /// cannot change the selected credential. Row IDs and blob creation metadata
    /// stay local; database bytes are not a portable identity or convergence test.
    /// Only INSERT is used: no existing credential, timestamp, or blob is updated
    /// or deleted. Invalid snapshots roll back the entire transaction.
    ///
    /// The source is copied into a read-only in-memory database on every platform.
    /// A separate source connection isolates malformed schemas from the vault.
    ///
    /// # Errors
    /// Returns an error for malformed backup contents, unavailable storage, or a failed transaction.
    pub(crate) fn merge_plaintext_bytes_v0_30_0(
        &self,
        bytes: &[u8],
    ) -> StorageResult<u64> {
        let incoming =
            Connection::open(":memory:", false).map_err(|e| map_db_err(&e))?;
        ensure_temp_store_memory(&incoming).map_err(|e| map_db_err(&e))?;
        incoming
            .deserialize_readonly("main", bytes)
            .map_err(|e| map_db_err(&e))?;
        merge_from(self.vault.connection(), &incoming)
    }
}

fn merge_from(destination: &Connection, incoming: &Connection) -> StorageResult<u64> {
    validate_incoming(incoming)?;
    let tx = destination
        .transaction_immediate()
        .map_err(|e| map_db_err(&e))?;
    {
        let mut blobs = incoming.prepare(
            "SELECT content_id, blob_kind, MIN(created_at), bytes FROM blob_objects GROUP BY content_id",
        ).map_err(|e| map_db_err(&e))?;
        while let StepResult::Row(row) = blobs.step().map_err(|e| map_db_err(&e))? {
            tx.execute(
                "INSERT INTO blob_objects(content_id, blob_kind, created_at, bytes)
                 VALUES (?1, ?2, ?3, ?4) ON CONFLICT(content_id) DO NOTHING;",
                params![
                    row.column_blob(0),
                    row.column_i64(1),
                    row.column_i64(2),
                    row.column_blob(3)
                ],
            )
            .map_err(|e| map_db_err(&e))?;
        }
    }

    let mut added_records = 0;
    {
        let mut records = incoming.prepare(&format!(
            "SELECT issuer_schema_id, subject_blinding_factor, genesis_issued_at, expires_at,
                    updated_at, credential_blob_cid, associated_data_cid
             FROM credential_records ORDER BY {CREDENTIAL_VERSION_ORDER}",
        )).map_err(|e| map_db_err(&e))?;
        while let StepResult::Row(row) = records.step().map_err(|e| map_db_err(&e))? {
            let associated_data_cid = if row.is_column_null(6) {
                walletkit_sqlite::Value::Null
            } else {
                walletkit_sqlite::Value::Blob(row.column_blob(6))
            };
            let inserted = tx.execute(
                "INSERT INTO credential_records(issuer_schema_id, subject_blinding_factor,
                    genesis_issued_at, expires_at, updated_at, credential_blob_cid, associated_data_cid)
                 SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7 WHERE NOT EXISTS (
                    SELECT 1 FROM credential_records WHERE issuer_schema_id = ?1
                    AND subject_blinding_factor = ?2 AND genesis_issued_at = ?3 AND expires_at = ?4
                    AND updated_at = ?5
                    AND credential_blob_cid = ?6 AND associated_data_cid IS ?7)",
                params![row.column_i64(0), row.column_blob(1), row.column_i64(2), row.column_i64(3),
                        row.column_i64(4), row.column_blob(5), associated_data_cid],
            ).map_err(|e| map_db_err(&e))?;
            added_records += inserted as u64;
        }
    }
    tx.commit().map_err(|e| map_db_err(&e))?;
    Ok(added_records)
}

fn validate_incoming(incoming: &Connection) -> StorageResult<()> {
    // Exports made with CREATE TABLE AS have no NOT NULL or type constraints.
    // Validate before using SQLite's permissive getters or writing destination data.
    let has_invalid_rows = incoming.query_row(
        "SELECT EXISTS(SELECT 1 FROM blob_objects WHERE
            typeof(content_id) != 'blob' OR length(content_id) != 32 OR
            typeof(blob_kind) != 'integer' OR blob_kind NOT IN (1, 2) OR
            typeof(created_at) != 'integer' OR created_at < 0 OR typeof(bytes) != 'blob')
         OR EXISTS(SELECT 1 FROM credential_records r WHERE
            typeof(issuer_schema_id) != 'integer' OR issuer_schema_id < 0 OR
            typeof(subject_blinding_factor) != 'blob' OR length(subject_blinding_factor) != 32 OR
            typeof(genesis_issued_at) != 'integer' OR genesis_issued_at < 0 OR
            typeof(expires_at) != 'integer' OR expires_at < 0 OR
            typeof(updated_at) != 'integer' OR updated_at < 0 OR
            typeof(credential_blob_cid) != 'blob' OR
            NOT EXISTS(SELECT 1 FROM blob_objects b WHERE b.content_id = r.credential_blob_cid AND b.blob_kind = 1) OR
            (associated_data_cid IS NOT NULL AND (typeof(associated_data_cid) != 'blob' OR
             NOT EXISTS(SELECT 1 FROM blob_objects b WHERE b.content_id = r.associated_data_cid AND b.blob_kind = 2))))",
        &[], |row| Ok(row.column_i64(0) != 0),
    ).map_err(|e| map_db_err(&e))?;
    if has_invalid_rows {
        return Err(invalid_backup());
    }

    {
        let mut blobs = incoming
            .prepare("SELECT content_id, blob_kind, bytes FROM blob_objects")
            .map_err(|e| map_db_err(&e))?;
        while let StepResult::Row(row) = blobs.step().map_err(|e| map_db_err(&e))? {
            let kind = u8::try_from(row.column_i64(1)).map_err(|_| invalid_backup())?;
            if row.column_blob(0) != compute_content_id(kind, &row.column_blob(2)) {
                return Err(invalid_backup());
            }
        }
    }
    Ok(())
}

fn invalid_backup() -> StorageError {
    StorageError::VaultDb("invalid credential backup contents".to_owned())
}
