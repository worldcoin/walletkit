//! Encrypted vault database for credential storage.

mod helpers;
mod schema;
#[cfg(test)]
mod tests;

use std::path::Path;

use rusqlite::{params, Connection, OptionalExtension};
use uuid::Uuid;

use super::error::{StorageError, StorageResult};
use super::lock::StorageLockGuard;
use super::sqlcipher;
use super::types::{BlobKind, CredentialId, CredentialRecord, CredentialStatus};
use helpers::{
    compute_content_id, map_db_err, map_record, map_sqlcipher_err, to_i64, to_u64,
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
        let conn = sqlcipher::open_connection(path).map_err(map_sqlcipher_err)?;
        sqlcipher::apply_key(&conn, k_intermediate).map_err(map_sqlcipher_err)?;
        sqlcipher::configure_connection(&conn).map_err(map_sqlcipher_err)?;
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
        let existing = tx
            .query_row("SELECT leaf_index FROM vault_meta LIMIT 1", [], |row| {
                row.get::<_, Option<i64>>(0)
            })
            .optional()
            .map_err(|err| map_db_err(&err))?;
        match existing {
            None => {
                tx.execute(
                    "INSERT INTO vault_meta (schema_version, leaf_index, created_at, updated_at)
                     VALUES (?1, ?2, ?3, ?4)",
                    params![
                        VAULT_SCHEMA_VERSION,
                        leaf_index_i64,
                        now_i64,
                        now_i64
                    ],
                )
                .map_err(|err| map_db_err(&err))?;
            }
            Some(None) => {
                tx.execute(
                    "UPDATE vault_meta SET leaf_index = ?1, updated_at = ?2",
                    params![leaf_index_i64, now_i64],
                )
                .map_err(|err| map_db_err(&err))?;
            }
            Some(Some(stored)) => {
                if stored != leaf_index_i64 {
                    let expected = to_u64(stored, "leaf_index")?;
                    return Err(StorageError::InvalidLeafIndex {
                        expected,
                        provided: leaf_index,
                    });
                }
                tx.execute("UPDATE vault_meta SET updated_at = ?1", params![now_i64])
                    .map_err(|err| map_db_err(&err))?;
            }
        }
        tx.commit().map_err(|err| map_db_err(&err))?;
        Ok(())
    }

    /// Stores a credential and optional associated data.
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
        status: CredentialStatus,
        subject_blinding_factor: [u8; 32],
        genesis_issued_at: u64,
        expires_at: Option<u64>,
        credential_blob: Vec<u8>,
        associated_data: Option<Vec<u8>>,
        now: u64,
    ) -> StorageResult<CredentialId> {
        let credential_id = *Uuid::new_v4().as_bytes();
        let credential_blob_id =
            compute_content_id(BlobKind::CredentialBlob, &credential_blob);
        let associated_data_id = associated_data
            .as_ref()
            .map(|bytes| compute_content_id(BlobKind::AssociatedData, bytes));
        let now_i64 = to_i64(now, "now")?;
        let issuer_schema_id_i64 = to_i64(issuer_schema_id, "issuer_schema_id")?;
        let genesis_issued_at_i64 = to_i64(genesis_issued_at, "genesis_issued_at")?;
        let expires_at_i64 = expires_at
            .map(|value| to_i64(value, "expires_at"))
            .transpose()?;

        let tx = self.conn.transaction().map_err(|err| map_db_err(&err))?;
        tx.execute(
            "INSERT OR IGNORE INTO blob_objects (content_id, blob_kind, created_at, bytes)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                credential_blob_id.as_ref(),
                BlobKind::CredentialBlob.as_i64(),
                now_i64,
                credential_blob
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
                    data
                ],
            )
            .map_err(|err| map_db_err(&err))?;
        }

        tx.execute(
            "INSERT INTO credential_records (
                credential_id,
                issuer_schema_id,
                subject_blinding_factor,
                genesis_issued_at,
                expires_at,
                status,
                updated_at,
                credential_blob_cid,
                associated_data_cid
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                credential_id.as_ref(),
                issuer_schema_id_i64,
                subject_blinding_factor.as_ref(),
                genesis_issued_at_i64,
                expires_at_i64,
                status.as_i64(),
                now_i64,
                credential_blob_id.as_ref(),
                associated_data_id.as_ref().map(AsRef::as_ref)
            ],
        )
        .map_err(|err| map_db_err(&err))?;

        tx.commit().map_err(|err| map_db_err(&err))?;
        Ok(credential_id)
    }

    /// Lists active credentials, optionally filtered by issuer schema.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub fn list_credentials(
        &self,
        issuer_schema_id: Option<u64>,
        now: u64,
    ) -> StorageResult<Vec<CredentialRecord>> {
        let mut records = Vec::new();
        let status = CredentialStatus::Active.as_i64();
        let expires = to_i64(now, "now")?;
        if let Some(issuer_schema_id) = issuer_schema_id {
            let issuer_schema_id_i64 = to_i64(issuer_schema_id, "issuer_schema_id")?;
            let mut stmt = self
                .conn
                .prepare(
                    "SELECT
                        cr.credential_id,
                        cr.issuer_schema_id,
                        cr.status,
                        cr.subject_blinding_factor,
                        cr.genesis_issued_at,
                        cr.expires_at,
                        cr.updated_at,
                        cb.bytes,
                        ad.bytes
                     FROM credential_records cr
                     JOIN blob_objects cb ON cb.content_id = cr.credential_blob_cid
                     LEFT JOIN blob_objects ad ON ad.content_id = cr.associated_data_cid
                     WHERE cr.status = ?1
                       AND (cr.expires_at IS NULL OR cr.expires_at > ?2)
                       AND cr.issuer_schema_id = ?3
                     ORDER BY cr.updated_at DESC",
                )
                .map_err(|err| map_db_err(&err))?;
            let mut rows = stmt
                .query(params![status, expires, issuer_schema_id_i64])
                .map_err(|err| map_db_err(&err))?;
            while let Some(row) = rows.next().map_err(|err| map_db_err(&err))? {
                records.push(map_record(row)?);
            }
        } else {
            let mut stmt = self
                .conn
                .prepare(
                    "SELECT
                        cr.credential_id,
                        cr.issuer_schema_id,
                        cr.status,
                        cr.subject_blinding_factor,
                        cr.genesis_issued_at,
                        cr.expires_at,
                        cr.updated_at,
                        cb.bytes,
                        ad.bytes
                     FROM credential_records cr
                     JOIN blob_objects cb ON cb.content_id = cr.credential_blob_cid
                     LEFT JOIN blob_objects ad ON ad.content_id = cr.associated_data_cid
                     WHERE cr.status = ?1
                       AND (cr.expires_at IS NULL OR cr.expires_at > ?2)
                     ORDER BY cr.updated_at DESC",
                )
                .map_err(|err| map_db_err(&err))?;
            let mut rows = stmt
                .query(params![status, expires])
                .map_err(|err| map_db_err(&err))?;
            while let Some(row) = rows.next().map_err(|err| map_db_err(&err))? {
                records.push(map_record(row)?);
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
        sqlcipher::integrity_check(&self.conn).map_err(map_sqlcipher_err)
    }
}
