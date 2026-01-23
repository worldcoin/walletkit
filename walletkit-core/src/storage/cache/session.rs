//! Session key cache helpers.

use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection, OptionalExtension};

use crate::storage::error::{StorageError, StorageResult};

use super::util::{
    expiry_timestamp, map_db_err, parse_fixed_bytes, session_cache_key, to_i64,
};

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

pub(super) fn put(
    conn: &Connection,
    rp_id: [u8; 32],
    k_session: [u8; 32],
    ttl_seconds: u64,
) -> StorageResult<()> {
    let now = current_unix_timestamp()?;
    prune_expired(conn, now)?;
    let expires_at = expiry_timestamp(now, ttl_seconds);
    let key = session_cache_key(rp_id);
    let inserted_at_i64 = to_i64(now, "now")?;
    let expires_at_i64 = to_i64(expires_at, "expires_at")?;
    conn.execute(
        "INSERT OR REPLACE INTO cache_entries (
            key_bytes,
            value_bytes,
            inserted_at,
            expires_at
         ) VALUES (?1, ?2, ?3, ?4)",
        params![key, k_session.as_ref(), inserted_at_i64, expires_at_i64],
    )
    .map_err(|err| map_db_err(&err))?;
    Ok(())
}

fn prune_expired(conn: &Connection, now: u64) -> StorageResult<()> {
    let now_i64 = to_i64(now, "now")?;
    conn.execute(
        "DELETE FROM cache_entries WHERE expires_at <= ?1",
        params![now_i64],
    )
    .map_err(|err| map_db_err(&err))?;
    Ok(())
}

fn current_unix_timestamp() -> StorageResult<u64> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| {
            StorageError::CacheDb(format!("system time before unix epoch: {err}"))
        })?;
    Ok(duration.as_secs())
}
