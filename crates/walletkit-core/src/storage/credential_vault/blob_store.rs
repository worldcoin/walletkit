//! Local-only blob storage. Neither data nor aliases participate in vault recovery.

use std::sync::Arc;

use rand::{rngs::OsRng, RngCore};
use walletkit_sqlite::{params, Row, StepResult, Value};

use super::{map_db_err, to_i64, to_u64, CredentialVault};
use crate::storage::{BlobId, BlobRecord, StorageError, StorageResult, StoredBlob};

impl CredentialVault {
    pub(crate) fn put_blob(
        &self,
        content_id: &BlobId,
        kind: &str,
        data: &[u8],
        path: Option<&str>,
        now: u64,
    ) -> StorageResult<u64> {
        let path = path.map(blob_path).transpose()?;
        let now = to_i64(now, "now")?;
        let initial_revision = initial_revision()?;
        let tx = self
            .vault
            .connection()
            .transaction_immediate()
            .map_err(|err| map_db_err(&err))?;
        let revision = tx.query_row(
            "INSERT INTO blobs (content_id, kind, data, revision, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?5, ?4, ?4)
             ON CONFLICT(content_id) DO UPDATE SET
                kind = excluded.kind, data = excluded.data,
                revision = blobs.revision + 1, updated_at = excluded.updated_at
             RETURNING revision",
            params![content_id.as_bytes().as_slice(), kind, data, now, initial_revision],
            |row| Ok(row.column_i64(0)),
        ).map_err(|err| map_db_err(&err))?;
        if let Some(path) = path {
            tx.execute(
                "INSERT INTO blob_paths (path, content_id) VALUES (?1, ?2)
                 ON CONFLICT(path) DO UPDATE SET content_id = excluded.content_id",
                params![path, content_id.as_bytes().as_slice()],
            )
            .map_err(|err| map_db_err(&err))?;
        }
        tx.commit().map_err(|err| map_db_err(&err))?;
        to_u64(revision, "revision")
    }

    pub(crate) fn get_blob(
        &self,
        content_id: &BlobId,
    ) -> StorageResult<Option<StoredBlob>> {
        self.vault.connection().query_row_optional(
            "SELECT content_id, kind, metadata, revision, created_at, updated_at, data
             FROM blobs WHERE content_id = ?1",
            params![content_id.as_bytes().as_slice()],
            |row| Ok(read_blob(row)),
        ).map_err(|err| map_db_err(&err))?.transpose()
    }

    pub(crate) fn get_blob_by_path(
        &self,
        path: &str,
    ) -> StorageResult<Option<StoredBlob>> {
        let path = blob_path(path)?;
        self.vault.connection().query_row_optional(
            "SELECT b.content_id, b.kind, b.metadata, b.revision, b.created_at, b.updated_at, b.data
             FROM blobs b JOIN blob_paths p ON p.content_id = b.content_id WHERE p.path = ?1",
            params![path],
            |row| Ok(read_blob(row)),
        ).map_err(|err| map_db_err(&err))?.transpose()
    }

    pub(crate) fn list_blob_paths(&self, prefix: &str) -> StorageResult<Vec<String>> {
        let mut normalized = normalize_relative_path(prefix)?;
        if prefix.ends_with('/') && !normalized.is_empty() {
            normalized.push('/');
        }
        let mut stmt = self.vault.connection().prepare(
            "SELECT path FROM blob_paths WHERE substr(path, 1, length(?1)) = ?1 ORDER BY path",
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
                "SELECT content_id, kind, metadata, revision, created_at, updated_at
             FROM blobs WHERE (?1 IS NULL OR kind = ?1) ORDER BY content_id",
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
        content_id: &BlobId,
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
             WHERE content_id = ?3 AND revision = ?4 RETURNING revision",
            params![metadata, now, content_id.as_bytes().as_slice(), expected_revision],
            |row| Ok(row.column_i64(0)),
        ).map_err(|err| map_db_err(&err))?.ok_or(StorageError::BlobRevisionConflict)?;
        tx.commit().map_err(|err| map_db_err(&err))?;
        to_u64(revision, "revision")
    }

    pub(crate) fn delete_blob_path(&self, path: &str) -> StorageResult<bool> {
        let path = blob_path(path)?;
        let deleted = self
            .vault
            .connection()
            .execute("DELETE FROM blob_paths WHERE path = ?1", params![path])
            .map_err(|err| map_db_err(&err))?;
        Ok(deleted != 0)
    }

    pub(crate) fn delete_blob(&self, content_id: &BlobId) -> StorageResult<bool> {
        let deleted = self
            .vault
            .connection()
            .execute(
                "DELETE FROM blobs WHERE content_id = ?1",
                params![content_id.as_bytes().as_slice()],
            )
            .map_err(|err| map_db_err(&err))?;
        Ok(deleted != 0)
    }
}

/// Randomize each incarnation's counter, leaving about 2^62 increments before
/// overflow. Revision equality is an opaque CAS token, not a write count.
fn initial_revision() -> StorageResult<i64> {
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
        content_id: Arc::new(BlobId::from_bytes(row.column_blob(0))?),
        kind: row.column_text(1),
        metadata: (!row.is_column_null(2)).then(|| row.column_blob(2)),
        revision: to_u64(row.column_i64(3), "revision")?,
        created_at: to_u64(row.column_i64(4), "created_at")?,
        updated_at: to_u64(row.column_i64(5), "updated_at")?,
    })
}

fn blob_path(path: &str) -> StorageResult<String> {
    let normalized = normalize_relative_path(path)?;
    if normalized.is_empty() {
        return Err(StorageError::InvalidInput(
            "blob path must name a file".to_owned(),
        ));
    }
    Ok(normalized)
}

fn normalize_relative_path(path: &str) -> StorageResult<String> {
    if path.starts_with('/') || path.contains(['\\', ':', '\0']) {
        return Err(StorageError::InvalidInput(
            "blob path must be relative".to_owned(),
        ));
    }
    let mut parts = Vec::new();
    for part in path.split('/') {
        match part {
            ".." => {
                return Err(StorageError::InvalidInput(
                    "blob path must not contain parent traversal".to_owned(),
                ))
            }
            "" | "." => {}
            _ => parts.push(part),
        }
    }
    Ok(parts.join("/"))
}
