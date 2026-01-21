use rusqlite::Row;
use sha2::{Digest, Sha256};

use crate::storage::error::{StorageError, StorageResult};
use crate::storage::sqlcipher::SqlcipherError;
use crate::storage::types::{BlobKind, ContentId, CredentialRecord, CredentialStatus};

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
    let credential_id_bytes: Vec<u8> = row.get(0).map_err(|err| map_db_err(&err))?;
    let issuer_schema_id: i64 = row.get(1).map_err(|err| map_db_err(&err))?;
    let status_raw: i64 = row.get(2).map_err(|err| map_db_err(&err))?;
    let subject_blinding_factor_bytes: Vec<u8> =
        row.get(3).map_err(|err| map_db_err(&err))?;
    let genesis_issued_at: i64 = row.get(4).map_err(|err| map_db_err(&err))?;
    let expires_at: Option<i64> = row.get(5).map_err(|err| map_db_err(&err))?;
    let updated_at: i64 = row.get(6).map_err(|err| map_db_err(&err))?;
    let credential_blob: Vec<u8> = row.get(7).map_err(|err| map_db_err(&err))?;
    let associated_data: Option<Vec<u8>> =
        row.get(8).map_err(|err| map_db_err(&err))?;

    let credential_id = parse_fixed_bytes::<16>(&credential_id_bytes, "credential_id")?;
    let subject_blinding_factor = parse_fixed_bytes::<32>(
        &subject_blinding_factor_bytes,
        "subject_blinding_factor",
    )?;
    let status = CredentialStatus::try_from(status_raw)?;

    Ok(CredentialRecord {
        credential_id,
        issuer_schema_id: to_u64(issuer_schema_id, "issuer_schema_id")?,
        status,
        subject_blinding_factor,
        genesis_issued_at: to_u64(genesis_issued_at, "genesis_issued_at")?,
        expires_at: expires_at
            .map(|value| to_u64(value, "expires_at"))
            .transpose()?,
        updated_at: to_u64(updated_at, "updated_at")?,
        credential_blob,
        associated_data,
    })
}

pub(super) fn parse_fixed_bytes<const N: usize>(
    bytes: &[u8],
    label: &str,
) -> StorageResult<[u8; N]> {
    if bytes.len() != N {
        return Err(StorageError::VaultDb(format!(
            "{label} length mismatch: expected {N}, got {}",
            bytes.len()
        )));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(bytes);
    Ok(out)
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
