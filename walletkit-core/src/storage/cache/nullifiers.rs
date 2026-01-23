//! Used-nullifier cache helpers for replay protection.
//!
//! Tracks request ids and nullifiers to enforce single-use disclosures while
//! remaining idempotent for retries within the TTL window.

use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

use crate::storage::error::{StorageError, StorageResult};
use crate::storage::types::{ReplayGuardKind, ReplayGuardResult};

use super::util::{
    expiry_timestamp, map_db_err, replay_nullifier_key, replay_request_key, to_i64,
};

pub(super) fn replay_guard_bytes_for_request_id(
    conn: &Connection,
    request_id: [u8; 32],
    now: u64,
) -> StorageResult<Option<Vec<u8>>> {
    let now_i64 = to_i64(now, "now")?;
    let key = replay_request_key(request_id);
    conn.query_row(
        "SELECT value_bytes
         FROM cache_entries
         WHERE key_bytes = ?1
           AND expires_at > ?2",
        params![key, now_i64],
        |row| row.get(0),
    )
    .optional()
    .map_err(|err| map_db_err(&err))
}

pub(super) fn begin_replay_guard(
    conn: &mut Connection,
    request_id: [u8; 32],
    nullifier: [u8; 32],
    proof_bytes: Vec<u8>,
    now: u64,
    ttl_seconds: u64,
) -> StorageResult<ReplayGuardResult> {
    let now_i64 = to_i64(now, "now")?;
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|err| map_db_err(&err))?;
    tx.execute(
        "DELETE FROM cache_entries WHERE expires_at <= ?1",
        params![now_i64],
    )
    .map_err(|err| map_db_err(&err))?;

    let request_key = replay_request_key(request_id);
    let existing_proof: Option<Vec<u8>> = tx
        .query_row(
            "SELECT value_bytes
             FROM cache_entries
             WHERE key_bytes = ?1
               AND expires_at > ?2",
            params![request_key.as_slice(), now_i64],
            |row| row.get(0),
        )
        .optional()
        .map_err(|err| map_db_err(&err))?;
    if let Some(bytes) = existing_proof {
        tx.commit().map_err(|err| map_db_err(&err))?;
        return Ok(ReplayGuardResult {
            kind: ReplayGuardKind::Replay,
            bytes,
        });
    }

    let nullifier_key = replay_nullifier_key(nullifier);
    let existing_request: Option<Vec<u8>> = tx
        .query_row(
            "SELECT value_bytes
             FROM cache_entries
             WHERE key_bytes = ?1
               AND expires_at > ?2",
            params![nullifier_key.as_slice(), now_i64],
            |row| row.get(0),
        )
        .optional()
        .map_err(|err| map_db_err(&err))?;
    if existing_request.is_some() {
        return Err(StorageError::NullifierAlreadyDisclosed);
    }

    let expires_at = expiry_timestamp(now, ttl_seconds);
    let expires_at_i64 = to_i64(expires_at, "expires_at")?;
    let inserted_at_i64 = to_i64(now, "now")?;
    tx.execute(
        "INSERT INTO cache_entries (key_bytes, value_bytes, inserted_at, expires_at)
         VALUES (?1, ?2, ?3, ?4)",
        params![
            request_key.as_slice(),
            proof_bytes,
            inserted_at_i64,
            expires_at_i64
        ],
    )
    .map_err(|err| map_db_err(&err))?;
    tx.execute(
        "INSERT INTO cache_entries (key_bytes, value_bytes, inserted_at, expires_at)
         VALUES (?1, ?2, ?3, ?4)",
        params![
            nullifier_key.as_slice(),
            request_id.as_ref(),
            inserted_at_i64,
            expires_at_i64
        ],
    )
    .map_err(|err| map_db_err(&err))?;
    tx.commit().map_err(|err| map_db_err(&err))?;
    Ok(ReplayGuardResult {
        kind: ReplayGuardKind::Fresh,
        bytes: proof_bytes,
    })
}
