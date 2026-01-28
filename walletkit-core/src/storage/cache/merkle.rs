//! Merkle proof cache helpers.

use rusqlite::Connection;

use crate::storage::error::StorageResult;

use super::util::{
    cache_entry_times, get_cache_entry, merkle_cache_key, prune_expired_entries,
    upsert_cache_entry,
};

/// Fetches a cached Merkle proof if it is still valid.
///
/// # Errors
///
/// Returns an error if the query or conversion fails.
pub(super) fn get(
    conn: &Connection,
    registry_kind: u8,
    root: [u8; 32],
    leaf_index: u64,
    valid_before: u64,
) -> StorageResult<Option<Vec<u8>>> {
    let key = merkle_cache_key(registry_kind, root, leaf_index);
    get_cache_entry(conn, key.as_slice(), valid_before)
}

/// Inserts or replaces a cached Merkle proof with a TTL.
///
/// # Errors
///
/// Returns an error if pruning or insert fails.
pub(super) fn put(
    conn: &Connection,
    registry_kind: u8,
    root: [u8; 32],
    leaf_index: u64,
    proof_bytes: &[u8],
    now: u64,
    ttl_seconds: u64,
) -> StorageResult<()> {
    prune_expired_entries(conn, now)?;
    let key = merkle_cache_key(registry_kind, root, leaf_index);
    let times = cache_entry_times(now, ttl_seconds)?;
    upsert_cache_entry(conn, key.as_slice(), proof_bytes, times)
}
