//! Used-nullifier cache helpers for replay protection.
//!
//! Tracks request ids and nullifiers to enforce single-use disclosures while
//! remaining idempotent for retries within the TTL window.

use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

use crate::storage::error::{StorageError, StorageResult};
use crate::storage::types::{ReplayGuardKind, ReplayGuardResult};

use super::util::{
    cache_entry_times, insert_cache_entry, map_db_err, prune_expired_entries,
    replay_nullifier_key, replay_request_key, to_i64,
};

/// Fetches stored proof bytes for a request id if still valid.
///
/// # Errors
///
/// Returns an error if the query or conversion fails.
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

/// Enforces replay-safety for disclosures within a single transaction.
///
/// # Errors
///
/// Returns an error if the nullifier was already disclosed or on DB failures.
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
    prune_expired_entries(&tx, now)?;

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

    let times = cache_entry_times(now, ttl_seconds)?;
    insert_cache_entry(&tx, request_key.as_slice(), proof_bytes.as_ref(), times)?;
    insert_cache_entry(&tx, nullifier_key.as_slice(), request_id.as_ref(), times)?;
    tx.commit().map_err(|err| map_db_err(&err))?;
    Ok(ReplayGuardResult {
        kind: ReplayGuardKind::Fresh,
        bytes: proof_bytes,
    })
}
