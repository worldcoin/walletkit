//! Vault database helpers for type conversion and row mapping.

use crate::storage::error::{StorageError, StorageResult};
use crate::storage::types::CredentialRecord;
use walletkit_db::{DbError, Row};

pub(super) fn map_record(row: &Row<'_, '_>) -> StorageResult<CredentialRecord> {
    let credential_id = row.column_i64(0);
    let issuer_schema_id = row.column_i64(1);
    let expires_at = row.column_i64(2);
    let is_expired = row.column_i64(3);
    Ok(CredentialRecord {
        credential_id: to_u64(credential_id, "credential_id")?,
        issuer_schema_id: to_u64(issuer_schema_id, "issuer_schema_id")?,
        expires_at: to_u64(expires_at, "expires_at")?,
        is_expired: is_expired != 0,
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

pub(super) fn map_db_err(err: &DbError) -> StorageError {
    StorageError::VaultDb(err.to_string())
}
