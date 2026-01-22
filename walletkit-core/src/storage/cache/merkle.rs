//! Merkle proof cache helpers.

use rusqlite::{params, Connection, OptionalExtension};

use crate::storage::error::StorageResult;

use super::util::{expiry_timestamp, map_db_err, to_i64};

pub(super) fn get(
    conn: &Connection,
    registry_kind: u8,
    root: [u8; 32],
    leaf_index: u64,
    valid_before: u64,
) -> StorageResult<Option<Vec<u8>>> {
    let leaf_index_i64 = to_i64(leaf_index, "leaf_index")?;
    let valid_before_i64 = to_i64(valid_before, "valid_before")?;
    let proof = conn
        .query_row(
            "SELECT proof_bytes
             FROM merkle_proof_cache
             WHERE registry_kind = ?1
               AND root = ?2
               AND leaf_index = ?3
               AND expires_at > ?4",
            params![
                i64::from(registry_kind),
                root.as_ref(),
                leaf_index_i64,
                valid_before_i64
            ],
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
    let leaf_index_i64 = to_i64(leaf_index, "leaf_index")?;
    let now_i64 = to_i64(now, "now")?;
    let expires_at_i64 = to_i64(expires_at, "expires_at")?;
    conn.execute(
        "INSERT OR REPLACE INTO merkle_proof_cache (
            registry_kind,
            root,
            leaf_index,
            proof_bytes,
            inserted_at,
            expires_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            i64::from(registry_kind),
            root.as_ref(),
            leaf_index_i64,
            proof_bytes,
            now_i64,
            expires_at_i64
        ],
    )
    .map_err(|err| map_db_err(&err))?;
    Ok(())
}

fn prune_expired(conn: &Connection, now: u64) -> StorageResult<()> {
    let now_i64 = to_i64(now, "now")?;
    conn.execute(
        "DELETE FROM merkle_proof_cache WHERE expires_at <= ?1",
        params![now_i64],
    )
    .map_err(|err| map_db_err(&err))?;
    Ok(())
}
