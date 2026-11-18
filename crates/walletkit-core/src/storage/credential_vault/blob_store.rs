//! Content-addressed blobs. Linked data participates in recovery; legacy aliases stay local.

use std::sync::Arc;

use rand::{rngs::OsRng, RngCore};
use walletkit_sqlite::{params, Row, StepResult, Value};

use super::{map_db_err, to_i64, to_u64, CredentialVault};
use crate::storage::{
    blob_id::compute_blob_id, BlobId, BlobRecord, StorageError, StorageResult,
    StoredBlob,
};

impl CredentialVault {
    pub(crate) fn put_blob(
        &self,
        kind: &str,
        data: &[u8],
        legacy_path: Option<&str>,
        now: u64,
    ) -> StorageResult<(BlobId, bool)> {
        let legacy_path = legacy_path.map(legacy_blob_path).transpose()?;
        let now = to_i64(now, "now")?;
        let blob_id = compute_blob_id(data);
        let initial_revision = initial_revision()?;
        let tx = self
            .vault
            .connection()
            .transaction_immediate()
            .map_err(|err| map_db_err(&err))?;
        // Data is content-addressed, so only a new row or a new kind changes an export.
        let previous_kind = tx
            .query_row_optional(
                "SELECT kind FROM blobs WHERE blob_id = ?1",
                params![blob_id.as_bytes().as_slice()],
                |row| Ok(row.column_text(0)),
            )
            .map_err(|err| map_db_err(&err))?;
        tx.execute(
            "INSERT INTO blobs (blob_id, kind, data, revision, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?5, ?4, ?4)
             ON CONFLICT(blob_id) DO UPDATE SET
                kind = excluded.kind, data = excluded.data,
                revision = blobs.revision + 1, updated_at = excluded.updated_at",
            params![
                blob_id.as_bytes().as_slice(),
                kind,
                data,
                now,
                initial_revision
            ],
        )
        .map_err(|err| map_db_err(&err))?;
        if let Some(legacy_path) = legacy_path {
            tx.execute(
                "INSERT INTO legacy_blob_paths (legacy_path, blob_id) VALUES (?1, ?2)
                 ON CONFLICT(legacy_path) DO UPDATE SET blob_id = excluded.blob_id",
                params![legacy_path, blob_id.as_bytes().as_slice()],
            )
            .map_err(|err| map_db_err(&err))?;
        }
        let exported_changed = previous_kind.as_deref() != Some(kind)
            && tx
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM credential_blob_refs WHERE blob_id = ?1)",
                    params![blob_id.as_bytes().as_slice()],
                    |row| Ok(row.column_i64(0) != 0),
                )
                .map_err(|err| map_db_err(&err))?;
        tx.commit().map_err(|err| map_db_err(&err))?;
        Ok((blob_id, exported_changed))
    }

    pub(crate) fn get_blob(
        &self,
        blob_id: &BlobId,
    ) -> StorageResult<Option<StoredBlob>> {
        self.vault
            .connection()
            .query_row_optional(
                "SELECT blob_id, kind, metadata, revision, created_at, updated_at, data
             FROM blobs WHERE blob_id = ?1",
                params![blob_id.as_bytes().as_slice()],
                |row| Ok(read_blob(row)),
            )
            .map_err(|err| map_db_err(&err))?
            .transpose()
    }

    pub(crate) fn get_blob_by_legacy_path(
        &self,
        legacy_path: &str,
    ) -> StorageResult<Option<StoredBlob>> {
        let legacy_path = legacy_blob_path(legacy_path)?;
        self.vault.connection().query_row_optional(
            "SELECT b.blob_id, b.kind, b.metadata, b.revision, b.created_at, b.updated_at, b.data
             FROM blobs b JOIN legacy_blob_paths p ON p.blob_id = b.blob_id WHERE p.legacy_path = ?1",
            params![legacy_path],
            |row| Ok(read_blob(row)),
        ).map_err(|err| map_db_err(&err))?.transpose()
    }

    pub(crate) fn list_legacy_blob_paths(
        &self,
        prefix: &str,
    ) -> StorageResult<Vec<String>> {
        let mut normalized = normalize_relative_path(prefix)?;
        if prefix.ends_with('/') && !normalized.is_empty() {
            normalized.push('/');
        }
        let mut stmt = self.vault.connection().prepare(
            "SELECT legacy_path FROM legacy_blob_paths WHERE substr(legacy_path, 1, length(?1)) = ?1 ORDER BY legacy_path",
        ).map_err(|err| map_db_err(&err))?;
        stmt.bind_values(params![normalized])
            .map_err(|err| map_db_err(&err))?;
        let mut paths = Vec::new();
        while let StepResult::Row(row) = stmt.step().map_err(|err| map_db_err(&err))? {
            paths.push(row.column_text(0));
        }
        Ok(paths)
    }

    pub(crate) fn list_blobs(
        &self,
        kind: Option<&str>,
    ) -> StorageResult<Vec<BlobRecord>> {
        let mut stmt = self
            .vault
            .connection()
            .prepare(
                "SELECT blob_id, kind, metadata, revision, created_at, updated_at
             FROM blobs WHERE (?1 IS NULL OR kind = ?1) ORDER BY blob_id",
            )
            .map_err(|err| map_db_err(&err))?;
        let kind = kind.map_or(Value::Null, |kind| Value::Text(kind.to_owned()));
        stmt.bind_values(&[kind]).map_err(|err| map_db_err(&err))?;
        let mut records = Vec::new();
        while let StepResult::Row(row) = stmt.step().map_err(|err| map_db_err(&err))? {
            records.push(read_record(&row)?);
        }
        Ok(records)
    }

    pub(crate) fn update_blob_metadata(
        &self,
        blob_id: &BlobId,
        metadata: Option<&[u8]>,
        expected_revision: u64,
        now: u64,
    ) -> StorageResult<u64> {
        let expected_revision = to_i64(expected_revision, "expected_revision")?;
        let now = to_i64(now, "now")?;
        let metadata = metadata.map_or(Value::Null, |data| Value::Blob(data.to_vec()));
        let tx = self
            .vault
            .connection()
            .transaction_immediate()
            .map_err(|err| map_db_err(&err))?;
        let revision = tx.query_row_optional(
            "UPDATE blobs SET metadata = ?1, revision = revision + 1, updated_at = ?2
             WHERE blob_id = ?3 AND revision = ?4 RETURNING revision",
            params![metadata, now, blob_id.as_bytes().as_slice(), expected_revision],
            |row| Ok(row.column_i64(0)),
        ).map_err(|err| map_db_err(&err))?.ok_or(StorageError::BlobRevisionConflict)?;
        tx.commit().map_err(|err| map_db_err(&err))?;
        to_u64(revision, "revision")
    }

    pub(crate) fn delete_legacy_blob_path(
        &self,
        legacy_path: &str,
    ) -> StorageResult<bool> {
        let legacy_path = legacy_blob_path(legacy_path)?;
        let deleted = self
            .vault
            .connection()
            .execute(
                "DELETE FROM legacy_blob_paths WHERE legacy_path = ?1",
                params![legacy_path],
            )
            .map_err(|err| map_db_err(&err))?;
        Ok(deleted != 0)
    }

    pub(crate) fn delete_blob(&self, blob_id: &BlobId) -> StorageResult<bool> {
        let deleted = self
            .vault
            .connection()
            .execute(
                "DELETE FROM blobs WHERE blob_id = ?1",
                params![blob_id.as_bytes().as_slice()],
            )
            .map_err(|err| map_db_err(&err))?;
        Ok(deleted != 0)
    }
}

/// Randomize each incarnation's counter, leaving about 2^62 increments before
/// overflow. Even for identical data, a fresh seed reduces the chance that a
/// stale metadata CAS matches after a blob is deleted and recreated.
pub(super) fn initial_revision() -> StorageResult<i64> {
    let mut bytes = [0; 8];
    OsRng.try_fill_bytes(&mut bytes).map_err(|_| {
        StorageError::Crypto("blob revision generation failed".to_owned())
    })?;
    Ok((i64::from_be_bytes(bytes) & (i64::MAX >> 1)) + 1)
}

fn read_blob(row: &Row<'_, '_>) -> StorageResult<StoredBlob> {
    Ok(StoredBlob {
        record: read_record(row)?,
        data: row.column_blob(6),
    })
}

fn read_record(row: &Row<'_, '_>) -> StorageResult<BlobRecord> {
    Ok(BlobRecord {
        blob_id: Arc::new(BlobId::from_bytes(row.column_blob(0))?),
        kind: row.column_text(1),
        metadata: (!row.is_column_null(2)).then(|| row.column_blob(2)),
        revision: to_u64(row.column_i64(3), "revision")?,
        created_at: to_u64(row.column_i64(4), "created_at")?,
        updated_at: to_u64(row.column_i64(5), "updated_at")?,
    })
}

fn legacy_blob_path(legacy_path: &str) -> StorageResult<String> {
    let normalized = normalize_relative_path(legacy_path)?;
    if normalized.is_empty() {
        return Err(StorageError::InvalidInput(
            "legacy blob path must name a file".to_owned(),
        ));
    }
    Ok(normalized)
}

fn normalize_relative_path(legacy_path: &str) -> StorageResult<String> {
    if legacy_path.starts_with('/') || legacy_path.contains(['\\', ':', '\0']) {
        return Err(StorageError::InvalidInput(
            "legacy blob path must be relative".to_owned(),
        ));
    }
    let mut parts = Vec::new();
    for part in legacy_path.split('/') {
        match part {
            ".." => {
                return Err(StorageError::InvalidInput(
                    "legacy blob path must not contain parent traversal".to_owned(),
                ))
            }
            "" | "." => {}
            _ => parts.push(part),
        }
    }
    Ok(parts.join("/"))
}
