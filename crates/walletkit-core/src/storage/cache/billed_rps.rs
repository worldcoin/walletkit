//! Billed RP snapshot cache helpers (WIP-107 §4.2).

use walletkit_sqlite::Connection;

use crate::storage::{
    cache::util::{get_cache_entry, upsert_cache_entry_until},
    error::StorageResult,
};

/// Fetches the encoded snapshot cached under `key`, if it has not expired.
///
/// # Errors
///
/// Returns an error if the query fails.
pub(super) fn get(
    conn: &Connection,
    key: &[u8],
    now: u64,
) -> StorageResult<Option<Vec<u8>>> {
    get_cache_entry(conn, key, now, None)
}

/// Stores the encoded `snapshot` under `key` until `expires_at`, exclusive, replacing the previous
/// one. Stores nothing if `expires_at` has passed.
///
/// # Errors
///
/// Returns an error if pruning or the insert fails.
pub(super) fn put(
    conn: &Connection,
    key: &[u8],
    snapshot: &[u8],
    now: u64,
    expires_at: u64,
) -> StorageResult<()> {
    upsert_cache_entry_until(conn, key, snapshot, now, expires_at)
}
