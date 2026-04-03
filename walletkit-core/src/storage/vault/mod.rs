//! Encrypted vault database for credential storage.

mod helpers;
mod schema;
#[cfg(test)]
mod tests;

use std::path::Path;

use crate::storage::error::{StorageError, StorageResult};
use crate::storage::lock::StorageLockGuard;
use crate::storage::types::{BlobKind, CredentialRecord};
use helpers::{compute_content_id, map_db_err, map_record, to_i64, to_u64};
use schema::{ensure_schema, VAULT_SCHEMA_VERSION};
use walletkit_db::cipher;
use walletkit_db::{params, Connection, StepResult, Value};
use zeroize::Zeroizing;

const SECONDS_PER_DAY: u64 = 86_400;

/// Session seed TTL: ~6 months (182 days).
const SESSION_SEED_TTL_SECONDS: u64 = 182 * SECONDS_PER_DAY;

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
        k_intermediate: &Zeroizing<[u8; 32]>,
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
        subject_blinding_factor: Vec<u8>,
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
                    subject_blinding_factor,
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

    /// Lists credential metadata, optionally filtered by issuer schema.
    ///
    /// Results include both active and expired credentials. Expiry status is
    /// reported via [`CredentialRecord::is_expired`] and uses
    /// `now >= expires_at` semantics.
    ///
    /// Results are ordered by `updated_at` descending (most recent first).
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub fn list_credentials(
        &self,
        issuer_schema_id: Option<u64>,
        now: u64,
    ) -> StorageResult<Vec<CredentialRecord>> {
        let now_i64 = to_i64(now, "now")?;
        let issuer_schema_id_i64 = issuer_schema_id
            .map(|value| to_i64(value, "issuer_schema_id"))
            .transpose()?;

        let mut records = Vec::new();
        let issuer_filter = issuer_schema_id_i64.map_or(Value::Null, Value::Integer);

        let sql = "SELECT
                cr.credential_id,
                cr.issuer_schema_id,
                cr.expires_at,
                CASE WHEN cr.expires_at <= ?1 THEN 1 ELSE 0 END AS is_expired
             FROM credential_records cr
             WHERE (?2 IS NULL OR cr.issuer_schema_id = ?2)
             ORDER BY cr.updated_at DESC";

        let mut stmt = self.conn.prepare(sql).map_err(|err| map_db_err(&err))?;
        stmt.bind_values(&[Value::Integer(now_i64), issuer_filter])
            .map_err(|err| map_db_err(&err))?;
        while let StepResult::Row(row) = stmt.step().map_err(|err| map_db_err(&err))? {
            records.push(map_record(&row)?);
        }

        Ok(records)
    }

    /// Deletes a credential record by ID.
    ///
    /// Deleting a credential also removes orphaned `credential_blob_cid` and
    /// `associated_data_cid` blobs when no records reference them.
    ///
    /// # Errors
    ///
    /// Returns an error if the delete query fails or the credential ID does not
    /// exist.
    pub fn delete_credential(
        &mut self,
        _lock: &StorageLockGuard,
        credential_id: u64,
    ) -> StorageResult<()> {
        let credential_id_i64 = to_i64(credential_id, "credential_id")?;
        let tx = self.conn.transaction().map_err(|err| map_db_err(&err))?;

        let deleted = tx
            .execute(
                "DELETE FROM credential_records WHERE credential_id = ?1",
                params![credential_id_i64],
            )
            .map_err(|err| map_db_err(&err))?;

        if deleted == 0 {
            return Err(StorageError::CredentialIdNotFound { credential_id });
        }

        // Delete orphaned credential blobs
        tx.execute(
            "DELETE FROM blob_objects
             WHERE blob_kind = ?1
               AND NOT EXISTS (
                   SELECT 1
                   FROM credential_records cr
                   WHERE cr.credential_blob_cid = blob_objects.content_id
               )",
            params![BlobKind::CredentialBlob.as_i64()],
        )
        .map_err(|err| map_db_err(&err))?;

        // Delete orphaned associated data blobs
        tx.execute(
            "DELETE FROM blob_objects
             WHERE blob_kind = ?1
               AND NOT EXISTS (
                   SELECT 1
                   FROM credential_records cr
                   WHERE cr.associated_data_cid = blob_objects.content_id
               )",
            params![BlobKind::AssociatedData.as_i64()],
        )
        .map_err(|err| map_db_err(&err))?;

        tx.commit().map_err(|err| map_db_err(&err))?;
        Ok(())
    }

    /// Retrieves the credential bytes and blinding factor by issuer schema ID.
    ///
    /// Returns the most recent non-expired credential matching the issuer schema ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub fn fetch_credential_and_blinding_factor(
        &self,
        issuer_schema_id: u64,
        now: u64,
    ) -> StorageResult<Option<(Vec<u8>, Vec<u8>)>> {
        let expires = to_i64(now, "now")?;
        let issuer_schema_id_i64 = to_i64(issuer_schema_id, "issuer_schema_id")?;

        let sql = "SELECT
                cr.subject_blinding_factor,
                blob.bytes as credential_blob
             FROM credential_records cr
             INNER JOIN blob_objects blob ON cr.credential_blob_cid = blob.content_id
             WHERE cr.expires_at > ?1 AND cr.issuer_schema_id = ?2
             ORDER BY cr.updated_at DESC
             LIMIT 1";

        let mut stmt = self.conn.prepare(sql).map_err(|err| map_db_err(&err))?;
        stmt.bind_values(params![expires, issuer_schema_id_i64])
            .map_err(|err| map_db_err(&err))?;
        match stmt.step().map_err(|err| map_db_err(&err))? {
            StepResult::Row(row) => {
                let blinding_factor = row.column_blob(0);
                let credential_blob = row.column_blob(1);
                Ok(Some((credential_blob, blinding_factor)))
            }
            StepResult::Done => Ok(None),
        }
    }

    /// Stores a session seed pair in the vault.
    ///
    /// `created_at` is floored to midnight (00:00:00 UTC) for privacy.
    /// The seed expires after [`SESSION_SEED_TTL_SECONDS`].
    ///
    /// # Errors
    ///
    /// Returns an error if the insert fails.
    pub fn store_session_seed(
        &mut self,
        _lock: &StorageLockGuard,
        oprf_seed: &[u8; 32],
        session_id_r_seed: &[u8; 32],
        now: u64,
    ) -> StorageResult<()> {
        // Floor to date to store less metadata
        let created_at = now - (now % SECONDS_PER_DAY);
        let created_at_i64 = to_i64(created_at, "created_at")?;
        self.conn
            .execute(
                "INSERT OR REPLACE INTO session_seeds
                     (oprf_seed, session_id_r_seed, created_at)
                 VALUES (?1, ?2, ?3)",
                params![
                    oprf_seed.as_slice(),
                    session_id_r_seed.as_slice(),
                    created_at_i64,
                ],
            )
            .map_err(|err| map_db_err(&err))?;
        Ok(())
    }

    /// Retrieves the most recent non-expired session seed.
    ///
    /// Returns `None` if no valid session seed exists.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub fn get_session_seed(
        &self,
        now: u64,
    ) -> StorageResult<Option<([u8; 32], [u8; 32])>> {
        let now_i64 = to_i64(now, "now")?;
        let ttl_i64 = to_i64(SESSION_SEED_TTL_SECONDS, "ttl")?;

        let sql = "SELECT oprf_seed, session_id_r_seed
                   FROM session_seeds
                   WHERE created_at + ?1 > ?2
                   ORDER BY created_at DESC
                   LIMIT 1";

        let mut stmt = self.conn.prepare(sql).map_err(|err| map_db_err(&err))?;
        stmt.bind_values(params![ttl_i64, now_i64])
            .map_err(|err| map_db_err(&err))?;

        match stmt.step().map_err(|err| map_db_err(&err))? {
            StepResult::Row(row) => {
                let oprf = row.column_blob(0);
                let session = row.column_blob(1);
                let oprf: [u8; 32] = oprf.try_into().map_err(|_| {
                    StorageError::VaultDb("oprf_seed not 32 bytes".to_string())
                })?;
                let session: [u8; 32] = session.try_into().map_err(|_| {
                    StorageError::VaultDb("session_id_r_seed not 32 bytes".to_string())
                })?;
                Ok(Some((oprf, session)))
            }
            StepResult::Done => Ok(None),
        }
    }

    /// **Development only.** Permanently deletes all credentials and their
    /// associated blob data from the vault.
    ///
    /// This is a destructive, unrecoverable operation. Do not call in production.
    /// Vault metadata (leaf index, schema version) is preserved.
    ///
    /// # Errors
    ///
    /// Returns an error if the delete operation fails.
    pub fn danger_delete_all_credentials(
        &mut self,
        _lock: &StorageLockGuard,
    ) -> StorageResult<u64> {
        let tx = self.conn.transaction().map_err(|err| map_db_err(&err))?;

        let deleted = tx
            .execute("DELETE FROM credential_records", &[])
            .map_err(|err| map_db_err(&err))?;

        tx.execute("DELETE FROM blob_objects", &[])
            .map_err(|err| map_db_err(&err))?;

        tx.commit().map_err(|err| map_db_err(&err))?;
        Ok(deleted as u64)
    }

    /// Runs an integrity check on the vault database.
    ///
    /// # Errors
    ///
    /// Returns an error if the check cannot be executed.
    pub fn check_integrity(&self) -> StorageResult<bool> {
        cipher::integrity_check(&self.conn).map_err(|e| map_db_err(&e))
    }

    /// Exports a plaintext (unencrypted) copy of the vault to `dest`.
    ///
    /// The caller is responsible for deleting the exported file after use.
    ///
    /// # Errors
    ///
    /// Returns an error if the export fails.
    pub fn export_plaintext(
        &self,
        dest: &Path,
        _lock: &StorageLockGuard,
    ) -> StorageResult<()> {
        // Remove any stale export from a previous failed run.
        if dest.exists() {
            std::fs::remove_file(dest).map_err(|e| {
                StorageError::VaultDb(format!("failed to remove stale backup: {e}"))
            })?;
        }
        cipher::export_plaintext_copy(&self.conn, dest).map_err(|e| map_db_err(&e))
    }

    /// Imports credentials from a plaintext (unencrypted) vault backup into
    /// an empty vault. Intended for restore on a fresh install.
    ///
    /// The caller is responsible for deleting the source file after the
    /// import completes.
    ///
    /// # Errors
    ///
    /// Returns an error if the import fails.
    pub fn import_plaintext(
        &self,
        source: &Path,
        _lock: &StorageLockGuard,
    ) -> StorageResult<()> {
        cipher::import_plaintext_copy(&self.conn, source).map_err(|e| map_db_err(&e))
    }
}
