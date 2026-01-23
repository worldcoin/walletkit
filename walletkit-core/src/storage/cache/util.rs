//! Shared helpers for cache database operations.

use std::io;

use crate::storage::error::{StorageError, StorageResult};
use crate::storage::sqlcipher::SqlcipherError;

pub(super) fn map_db_err(err: &rusqlite::Error) -> StorageError {
    StorageError::CacheDb(err.to_string())
}

pub(super) fn map_sqlcipher_err(err: SqlcipherError) -> StorageError {
    match err {
        SqlcipherError::Sqlite(err) => StorageError::CacheDb(err.to_string()),
        SqlcipherError::CipherUnavailable => StorageError::CacheDb(err.to_string()),
    }
}

pub(super) fn map_io_err(err: &io::Error) -> StorageError {
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

pub(super) const CACHE_KEY_PREFIX_MERKLE: u8 = 0x01;
pub(super) const CACHE_KEY_PREFIX_SESSION: u8 = 0x02;
pub(super) const CACHE_KEY_PREFIX_REPLAY_REQUEST: u8 = 0x03;
pub(super) const CACHE_KEY_PREFIX_REPLAY_NULLIFIER: u8 = 0x04;

fn cache_key_with_prefix(prefix: u8, payload: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(1 + payload.len());
    key.push(prefix);
    key.extend_from_slice(payload);
    key
}

pub(super) fn merkle_cache_key(
    registry_kind: u8,
    root: [u8; 32],
    leaf_index: u64,
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(1 + 32 + 8);
    payload.push(registry_kind);
    payload.extend_from_slice(root.as_ref());
    payload.extend_from_slice(&leaf_index.to_be_bytes());
    cache_key_with_prefix(CACHE_KEY_PREFIX_MERKLE, &payload)
}

pub(super) fn session_cache_key(rp_id: [u8; 32]) -> Vec<u8> {
    cache_key_with_prefix(CACHE_KEY_PREFIX_SESSION, rp_id.as_ref())
}

pub(super) fn replay_request_key(request_id: [u8; 32]) -> Vec<u8> {
    cache_key_with_prefix(CACHE_KEY_PREFIX_REPLAY_REQUEST, request_id.as_ref())
}

pub(super) fn replay_nullifier_key(nullifier: [u8; 32]) -> Vec<u8> {
    cache_key_with_prefix(CACHE_KEY_PREFIX_REPLAY_NULLIFIER, nullifier.as_ref())
}

pub(super) const fn expiry_timestamp(now: u64, ttl_seconds: u64) -> u64 {
    now.saturating_add(ttl_seconds)
}

pub(super) fn to_i64(value: u64, label: &str) -> StorageResult<i64> {
    i64::try_from(value).map_err(|_| {
        StorageError::CacheDb(format!("{label} out of range for i64: {value}"))
    })
}
