//! Merkle proof cache helpers.

use rusqlite::{params, Connection, OptionalExtension};

use crate::storage::error::StorageResult;

use super::util::{
    cache_entry_times, map_db_err, merkle_cache_key, prune_expired_entries, to_i64,
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
    let valid_before_i64 = to_i64(valid_before, "valid_before")?;
    let key = merkle_cache_key(registry_kind, root, leaf_index);
    let proof = conn
        .query_row(
            "SELECT value_bytes
             FROM cache_entries
             WHERE key_bytes = ?1
               AND expires_at > ?2",
            params![key, valid_before_i64],
            |row| row.get(0),
        )
        .optional()
        .map_err(|err| map_db_err(&err))?;
    Ok(proof)
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
