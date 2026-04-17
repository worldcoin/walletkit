//! Session seed cache helpers.

use crate::storage::error::StorageResult;
use walletkit_db::Connection;

use super::util::{
    cache_entry_times, get_cache_entry, parse_fixed_bytes, prune_expired_entries,
    session_cache_key, upsert_cache_entry,
};

/// Fetches a cached `session_id_r_seed` for the given `oprf_seed`, if still valid.
///
/// # Errors
///
/// Returns an error if the query fails or the cached bytes are malformed.
pub(super) fn get(
    conn: &Connection,
    oprf_seed: [u8; 32],
    now: u64,
) -> StorageResult<Option<[u8; 32]>> {
    let key = session_cache_key(oprf_seed);
    let raw = get_cache_entry(conn, key.as_slice(), now, None)?;
    match raw {
        Some(bytes) => Ok(Some(parse_fixed_bytes::<32>(&bytes, "session_id_r_seed")?)),
        None => Ok(None),
    }
}

/// Stores a `session_id_r_seed` keyed by `oprf_seed` with a TTL.
///
/// # Errors
///
/// Returns an error if pruning or insert fails.
pub(super) fn put(
    conn: &Connection,
    oprf_seed: [u8; 32],
    session_id_r_seed: [u8; 32],
    now: u64,
    ttl_seconds: u64,
) -> StorageResult<()> {
    let key = session_cache_key(oprf_seed);
    prune_expired_entries(conn, now)?;
    let times = cache_entry_times(now, ttl_seconds)?;
    upsert_cache_entry(conn, key.as_slice(), session_id_r_seed.as_ref(), times)
}
