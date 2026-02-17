//! Shared helpers for cache database operations.

use std::io;

use crate::storage::db::{params, Connection, DbError, Transaction, Value};
use crate::storage::error::{StorageError, StorageResult};

/// Maps a database error into a cache storage error.
pub(super) fn map_db_err(err: &DbError) -> StorageError {
    StorageError::CacheDb(err.to_string())
}

/// Maps an IO error into a cache storage error.
pub(super) fn map_io_err(err: &io::Error) -> StorageError {
    StorageError::CacheDb(err.to_string())
}

/// Parses a fixed-length array from the provided bytes.
///
/// # Errors
///
/// Returns an error if the input length does not match `N`.
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
pub(super) const CACHE_KEY_PREFIX_REPLAY_NULLIFIER: u8 = 0x03;

/// Timestamps for cache entry insertion and expiry.
#[derive(Clone, Copy, Debug)]
pub(super) struct CacheEntryTimes {
    pub inserted_at: i64,
    pub expires_at: i64,
}

/// Builds timestamps for cache entry inserts.
///
/// # Errors
///
/// Returns an error if timestamps do not fit into `i64`.
pub(super) fn cache_entry_times(
    now: u64,
    ttl_seconds: u64,
) -> StorageResult<CacheEntryTimes> {
    let expires_at = expiry_timestamp(now, ttl_seconds);
    Ok(CacheEntryTimes {
        inserted_at: to_i64(now, "now")?,
        expires_at: to_i64(expires_at, "expires_at")?,
    })
}

/// Removes expired cache entries before inserting new ones.
///
/// # Errors
///
/// Returns an error if the deletion fails.
pub(super) fn prune_expired_entries(conn: &Connection, now: u64) -> StorageResult<()> {
    let now_i64 = to_i64(now, "now")?;
    conn.execute(
        "DELETE FROM cache_entries WHERE expires_at <= ?1",
        params![Value::Integer(now_i64)],
    )
    .map_err(|err| map_db_err(&err))?;
    Ok(())
}

/// Prunes expired cache entries within a transaction.
pub(super) fn prune_expired_entries_tx(
    tx: &Transaction<'_>,
    now: u64,
) -> StorageResult<()> {
    let now_i64 = to_i64(now, "now")?;
    tx.execute(
        "DELETE FROM cache_entries WHERE expires_at <= ?1",
        params![Value::Integer(now_i64)],
    )
    .map_err(|err| map_db_err(&err))?;
    Ok(())
}

/// Inserts or replaces a cache entry row.
///
/// # Errors
///
/// Returns an error if the insert fails.
pub(super) fn upsert_cache_entry(
    conn: &Connection,
    key: &[u8],
    value: &[u8],
    times: CacheEntryTimes,
) -> StorageResult<()> {
    conn.execute(
        "INSERT OR REPLACE INTO cache_entries (
            key_bytes,
            value_bytes,
            inserted_at,
            expires_at
         ) VALUES (?1, ?2, ?3, ?4)",
        params![
            key,
            value,
            Value::Integer(times.inserted_at),
            Value::Integer(times.expires_at),
        ],
    )
    .map_err(|err| map_db_err(&err))?;
    Ok(())
}

/// Inserts a cache entry row within a transaction.
///
/// # Errors
///
/// Returns an error if the insert fails.
pub(super) fn insert_cache_entry_tx(
    tx: &Transaction<'_>,
    key: &[u8],
    value: &[u8],
    times: CacheEntryTimes,
) -> StorageResult<()> {
    tx.execute(
        "INSERT INTO cache_entries (
            key_bytes,
            value_bytes,
            inserted_at,
            expires_at
         ) VALUES (?1, ?2, ?3, ?4)",
        params![
            key,
            value,
            Value::Integer(times.inserted_at),
            Value::Integer(times.expires_at),
        ],
    )
    .map_err(|err| map_db_err(&err))?;
    Ok(())
}

/// Fetches a cache entry if it is still valid.
///
/// Optionally, filters out entries that were inserted before a specific time (`insertion_before`).
///
/// # Errors
///
/// Returns an error if the query or conversion fails.
pub(super) fn get_cache_entry(
    conn: &Connection,
    key: &[u8],
    now: u64,
    insertion_before: Option<u64>,
) -> StorageResult<Option<Vec<u8>>> {
    let now = to_i64(now, "now")?;

    if let Some(insertion_before) = insertion_before {
        let insertion_before = to_i64(insertion_before, "insertion_before")?;
        conn.query_row_optional(
            "SELECT value_bytes FROM cache_entries WHERE key_bytes = ?1 AND expires_at > ?2 AND inserted_at < ?3",
            params![key, Value::Integer(now), Value::Integer(insertion_before)],
            |stmt| Ok(stmt.column_blob(0)),
        )
        .map_err(|err| map_db_err(&err))
    } else {
        conn.query_row_optional(
            "SELECT value_bytes FROM cache_entries WHERE key_bytes = ?1 AND expires_at > ?2",
            params![key, Value::Integer(now)],
            |stmt| Ok(stmt.column_blob(0)),
        )
        .map_err(|err| map_db_err(&err))
    }
}

/// Fetches a cache entry within a transaction.
pub(super) fn get_cache_entry_tx(
    tx: &Transaction<'_>,
    key: &[u8],
    now: u64,
    insertion_before: Option<u64>,
) -> StorageResult<Option<Vec<u8>>> {
    let now = to_i64(now, "now")?;

    if let Some(insertion_before) = insertion_before {
        let insertion_before = to_i64(insertion_before, "insertion_before")?;
        let stmt = tx.prepare(
            "SELECT value_bytes FROM cache_entries WHERE key_bytes = ?1 AND expires_at > ?2 AND inserted_at < ?3",
        ).map_err(|err| map_db_err(&err))?;
        stmt.bind_values(params![
            key,
            Value::Integer(now),
            Value::Integer(insertion_before)
        ])
        .map_err(|err| map_db_err(&err))?;
        match stmt.step().map_err(|err| map_db_err(&err))? {
            crate::storage::db::StepResult::Row => Ok(Some(stmt.column_blob(0))),
            crate::storage::db::StepResult::Done => Ok(None),
        }
    } else {
        let stmt = tx.prepare(
            "SELECT value_bytes FROM cache_entries WHERE key_bytes = ?1 AND expires_at > ?2",
        ).map_err(|err| map_db_err(&err))?;
        stmt.bind_values(params![key, Value::Integer(now)])
            .map_err(|err| map_db_err(&err))?;
        match stmt.step().map_err(|err| map_db_err(&err))? {
            crate::storage::db::StepResult::Row => Ok(Some(stmt.column_blob(0))),
            crate::storage::db::StepResult::Done => Ok(None),
        }
    }
}

/// Builds a cache key by prefixing the payload with a type byte.
fn cache_key_with_prefix(prefix: u8, payload: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(1 + payload.len());
    key.push(prefix);
    key.extend_from_slice(payload);
    key
}

/// Builds the cache key for a session key entry.
pub(super) fn session_cache_key(rp_id: [u8; 32]) -> Vec<u8> {
    cache_key_with_prefix(CACHE_KEY_PREFIX_SESSION, rp_id.as_ref())
}

/// Builds the cache key for a replay-guard nullifier entry.
pub(super) fn replay_nullifier_key(nullifier: [u8; 32]) -> Vec<u8> {
    cache_key_with_prefix(CACHE_KEY_PREFIX_REPLAY_NULLIFIER, nullifier.as_ref())
}

/// Computes an expiry timestamp using saturating addition.
pub(super) const fn expiry_timestamp(now: u64, ttl_seconds: u64) -> u64 {
    now.saturating_add(ttl_seconds)
}

/// Converts a `u64` into `i64` for `SQLite` parameter bindings.
///
/// # Errors
///
/// Returns an error if the value cannot fit into `i64`.
pub(super) fn to_i64(value: u64, label: &str) -> StorageResult<i64> {
    i64::try_from(value).map_err(|_| {
        StorageError::CacheDb(format!("{label} out of range for i64: {value}"))
    })
}
