//! Merkle proof cache helpers.

use rusqlite::{params, Connection, OptionalExtension};

use crate::storage::error::StorageResult;

use super::util::{expiry_timestamp, map_db_err, merkle_cache_key, to_i64};

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

pub(super) fn put(
    conn: &Connection,
    registry_kind: u8,
    root: [u8; 32],
    leaf_index: u64,
    proof_bytes: &[u8],
    now: u64,
    ttl_seconds: u64,
) -> StorageResult<()> {
    prune_expired(conn, now)?;
    let expires_at = expiry_timestamp(now, ttl_seconds);
    let key = merkle_cache_key(registry_kind, root, leaf_index);
    let inserted_at_i64 = to_i64(now, "now")?;
    let expires_at_i64 = to_i64(expires_at, "expires_at")?;
    conn.execute(
        "INSERT OR REPLACE INTO cache_entries (
            key_bytes,
            value_bytes,
            inserted_at,
            expires_at
         ) VALUES (?1, ?2, ?3, ?4)",
        params![key, proof_bytes, inserted_at_i64, expires_at_i64],
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
