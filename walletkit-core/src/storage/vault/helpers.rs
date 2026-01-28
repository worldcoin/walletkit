use rusqlite::Row;
use sha2::{Digest, Sha256};

use crate::storage::error::{StorageError, StorageResult};
use crate::storage::sqlcipher::SqlcipherError;
use crate::storage::types::{BlobKind, ContentId, CredentialRecord};

const CONTENT_ID_PREFIX: &[u8] = b"worldid:blob";

pub(super) fn compute_content_id(blob_kind: BlobKind, plaintext: &[u8]) -> ContentId {
    let mut hasher = Sha256::new();
    hasher.update(CONTENT_ID_PREFIX);
    hasher.update([blob_kind as u8]);
    hasher.update(plaintext);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

pub(super) fn map_record(row: &Row<'_>) -> StorageResult<CredentialRecord> {
    let credential_id: i64 = row.get(0).map_err(|err| map_db_err(&err))?;
    let issuer_schema_id: i64 = row.get(1).map_err(|err| map_db_err(&err))?;
    let expires_at: i64 = row.get(2).map_err(|err| map_db_err(&err))?;
    Ok(CredentialRecord {
        credential_id: to_u64(credential_id, "credential_id")?,
        issuer_schema_id: to_u64(issuer_schema_id, "issuer_schema_id")?,
        expires_at: to_u64(expires_at, "expires_at")?,
    })
}

pub(super) fn to_i64(value: u64, label: &str) -> StorageResult<i64> {
    i64::try_from(value).map_err(|_| {
        StorageError::VaultDb(format!("{label} out of range for i64: {value}"))
    })
}

pub(super) fn to_u64(value: i64, label: &str) -> StorageResult<u64> {
    u64::try_from(value).map_err(|_| {
        StorageError::VaultDb(format!("{label} out of range for u64: {value}"))
    })
}

pub(super) fn map_db_err(err: &rusqlite::Error) -> StorageError {
    StorageError::VaultDb(err.to_string())
}

pub(super) fn map_sqlcipher_err(err: SqlcipherError) -> StorageError {
    match err {
        SqlcipherError::Sqlite(err) => StorageError::VaultDb(err.to_string()),
        SqlcipherError::CipherUnavailable => StorageError::VaultDb(err.to_string()),
    }
}
