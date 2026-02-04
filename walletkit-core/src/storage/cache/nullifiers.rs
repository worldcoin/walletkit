//! Used-nullifier cache helpers for replay protection.
//!
//! Tracks request ids and nullifiers to enforce single-use disclosures while
//! remaining idempotent for retries within the TTL window.

use rusqlite::{Connection, TransactionBehavior};

use crate::storage::error::{StorageError, StorageResult};
use crate::storage::types::{ReplayGuardKind, ReplayGuardResult};

use super::util::{
    cache_entry_times, commit_transaction, get_cache_entry, insert_cache_entry,
    map_db_err, prune_expired_entries, replay_nullifier_key, replay_request_key,
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
    let key = replay_request_key(request_id);
    get_cache_entry(conn, key.as_slice(), now)
}

/// Enforces replay-safety for disclosures within a single transaction.
///
/// # Errors
///
/// Returns an error if the nullifier was already disclosed or on DB failures.
pub(super) fn begin_replay_guard(
    conn: &mut Connection,
    nullifier: [u8; 32],
    now: u64,
    ttl_seconds: u64,
) -> StorageResult<ReplayGuardResult> {
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|err| map_db_err(&err))?;
    prune_expired_entries(&tx, now)?;

    let nullifier_key = replay_nullifier_key(nullifier);
    let existing_request = get_cache_entry(&tx, nullifier_key.as_slice(), now)?;
    if existing_request.is_some() {
        return Err(StorageError::NullifierAlreadyDisclosed);
    }

    // FIXME: start enforcing after x minutes
    let times = cache_entry_times(now, ttl_seconds)?;
    insert_cache_entry(&tx, nullifier_key.as_slice(), request_id.as_ref(), times)?;
    commit_transaction(tx)?;
    Ok(ReplayGuardResult {
        kind: ReplayGuardKind::Fresh,
        bytes: proof_bytes,
    })
}
