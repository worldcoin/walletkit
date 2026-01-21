//! Session key cache helpers.

use rusqlite::{params, Connection, OptionalExtension};

use crate::storage::error::StorageResult;

use super::util::{expiry_timestamp, map_db_err, parse_fixed_bytes};

pub(super) fn get(
    conn: &Connection,
    rp_id: [u8; 32],
    now: u64,
) -> StorageResult<Option<[u8; 32]>> {
    let raw: Option<Vec<u8>> = conn
        .query_row(
            "SELECT k_session
             FROM session_keys
             WHERE rp_id = ?1
               AND expires_at > ?2",
            params![rp_id.as_ref(), now as i64],
            |row| row.get(0),
        )
        .optional()
        .map_err(map_db_err)?;
    match raw {
        Some(bytes) => Ok(Some(parse_fixed_bytes::<32>(&bytes, "k_session")?)),
        None => Ok(None),
    }
}

pub(super) fn put(
    conn: &Connection,
    rp_id: [u8; 32],
    k_session: [u8; 32],
    now: u64,
    ttl_seconds: u64,
) -> StorageResult<()> {
    prune_expired(conn, now)?;
    let expires_at = expiry_timestamp(now, ttl_seconds);
    conn.execute(
        "INSERT OR REPLACE INTO session_keys (
            rp_id,
            k_session,
            expires_at
         ) VALUES (?1, ?2, ?3)",
        params![rp_id.as_ref(), k_session.as_ref(), expires_at as i64],
    )
    .map_err(map_db_err)?;
    Ok(())
}

fn prune_expired(conn: &Connection, now: u64) -> StorageResult<()> {
    conn.execute(
        "DELETE FROM session_keys WHERE expires_at <= ?1",
        params![now as i64],
    )
    .map_err(map_db_err)?;
    Ok(())
}
