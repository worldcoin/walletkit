//! Shared helpers for cache database operations.

use std::io;

use crate::storage::error::{StorageError, StorageResult};
use crate::storage::sqlcipher::SqlcipherError;

pub(super) fn map_db_err(err: rusqlite::Error) -> StorageError {
    StorageError::CacheDb(err.to_string())
}

pub(super) fn map_sqlcipher_err(err: SqlcipherError) -> StorageError {
    match err {
        SqlcipherError::Sqlite(err) => StorageError::CacheDb(err.to_string()),
        SqlcipherError::CipherUnavailable => StorageError::CacheDb(err.to_string()),
    }
}

pub(super) fn map_io_err(err: io::Error) -> StorageError {
    StorageError::CacheDb(err.to_string())
}

pub(super) fn parse_fixed_bytes<const N: usize>(
    bytes: &[u8],
    label: &str,
) -> StorageResult<[u8; N]> {
    if bytes.len() != N {
        return Err(StorageError::CacheDb(format!(
            "{label} length mismatch: expected {N}, got {}",
            bytes.len()
        )));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(bytes);
    Ok(out)
}

pub(super) fn expiry_timestamp(now: u64, ttl_seconds: u64) -> u64 {
    now.saturating_add(ttl_seconds)
}
