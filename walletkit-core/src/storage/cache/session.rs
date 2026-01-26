//! Session key cache helpers.

use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection, OptionalExtension};

use crate::storage::error::{StorageError, StorageResult};

use super::util::{
    cache_entry_times, map_db_err, parse_fixed_bytes, prune_expired_entries,
    session_cache_key, to_i64, upsert_cache_entry,
};

/// Fetches a cached session key if it is still valid.
///
/// # Errors
///
/// Returns an error if the query fails or the cached bytes are malformed.
pub(super) fn get(
    conn: &Connection,
    rp_id: [u8; 32],
) -> StorageResult<Option<[u8; 32]>> {
    let now = current_unix_timestamp()?;
    let now_i64 = to_i64(now, "now")?;
    let key = session_cache_key(rp_id);
    let raw: Option<Vec<u8>> = conn
        .query_row(
            "SELECT value_bytes
             FROM cache_entries
             WHERE key_bytes = ?1
               AND expires_at > ?2",
            params![key, now_i64],
            |row| row.get(0),
        )
        .optional()
        .map_err(|err| map_db_err(&err))?;
    match raw {
        Some(bytes) => Ok(Some(parse_fixed_bytes::<32>(&bytes, "k_session")?)),
        None => Ok(None),
    }
}

/// Stores a session key with a TTL.
///
/// # Errors
///
/// Returns an error if pruning or insert fails.
pub(super) fn put(
    conn: &Connection,
    rp_id: [u8; 32],
    k_session: [u8; 32],
    ttl_seconds: u64,
) -> StorageResult<()> {
    let now = current_unix_timestamp()?;
    let key = session_cache_key(rp_id);
    prune_expired_entries(conn, now)?;
    let times = cache_entry_times(now, ttl_seconds)?;
    upsert_cache_entry(conn, key.as_slice(), k_session.as_ref(), times)
}

/// Returns the current unix timestamp in seconds.
///
/// # Errors
///
/// Returns an error if system time is before the unix epoch.
fn current_unix_timestamp() -> StorageResult<u64> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| {
            StorageError::CacheDb(format!("system time before unix epoch: {err}"))
        })?;
    Ok(duration.as_secs())
}
