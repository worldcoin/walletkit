//! Merkle proof cache helpers.

use rusqlite::Connection;

use crate::storage::{cache::util::CACHE_KEY_PREFIX_MERKLE, error::StorageResult};

use super::util::{
    cache_entry_times, get_cache_entry, prune_expired_entries, upsert_cache_entry,
};

/// Fetches a cached Merkle proof if it is still valid.
///
/// # Errors
///
/// Returns an error if the query or conversion fails.
pub(super) fn get(
    conn: &Connection,
    valid_until: u64,
) -> StorageResult<Option<Vec<u8>>> {
    get_cache_entry(conn, &[CACHE_KEY_PREFIX_MERKLE], valid_until, None)
}

/// Inserts or replaces a cached Merkle proof with a TTL.
///
/// # Errors
///
/// Returns an error if pruning or insert fails.
pub(super) fn put(
    conn: &Connection,
    proof_bytes: &[u8],
    now: u64,
    ttl_seconds: u64,
) -> StorageResult<()> {
    prune_expired_entries(conn, now)?;
    let times = cache_entry_times(now, ttl_seconds)?;
    upsert_cache_entry(conn, &[CACHE_KEY_PREFIX_MERKLE], proof_bytes, times)
}
