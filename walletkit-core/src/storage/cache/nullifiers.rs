//! Used-nullifier cache helpers for replay protection.
//!
//! Tracks request ids and nullifiers to enforce single-use disclosures while
//! remaining idempotent for retries within the TTL window.

use crate::storage::db::Connection;
use crate::storage::error::StorageResult;

use super::util::{
    cache_entry_times, get_cache_entry, get_cache_entry_tx, insert_cache_entry_tx,
    map_db_err, prune_expired_entries_tx, replay_nullifier_key,
};

/// The time to wait before a replayed request starts being enforced.
///
/// This delay in enforcement of non-replay nullifiers allows for issues
/// that may cause proofs not to reach RPs and prevent users from getting locked out
/// of performing a particular action.
///
/// FUTURE: Parametrize this as a configuration option.
const REPLAY_REQUEST_NBF_SECONDS: u64 = 600; // 10 minutes

static REPLAY_REQUEST_TTL_SECONDS: u64 = 60 * 60 * 24 * 365; // 1 year

/// Checks whether a replay guard entry exists for the given nullifier.
///
/// # Returns
/// - bool: true if a replay guard entry exists (hence signalling a nullifier replay), false otherwise.
///
/// # Errors
///
/// Returns an error if the query to the cache unexpectedly fails.
pub(super) fn is_nullifier_replay(
    conn: &Connection,
    nullifier: [u8; 32],
    now: u64,
) -> StorageResult<bool> {
    let key = replay_nullifier_key(nullifier);
    let nbf = now.saturating_sub(REPLAY_REQUEST_NBF_SECONDS);
    let result = get_cache_entry(conn, key.as_slice(), now, Some(nbf))?;
    Ok(result.is_some())
}

/// After a proof has been successfully generated, creates a replay guard entry
/// locally to avoid future replays of the same nullifier.
///
/// This operation is idempotent - if an entry already exists and hasn't expired,
/// it will not be re-inserted (maintains the original insertion time).
pub(super) fn replay_guard_set(
    conn: &Connection,
    nullifier: [u8; 32],
    now: u64,
) -> StorageResult<()> {
    let tx = conn
        .transaction_immediate()
        .map_err(|err| map_db_err(&err))?;
    prune_expired_entries_tx(&tx, now)?;

    let key = replay_nullifier_key(nullifier);

    // Check if entry already exists (idempotency check)
    let existing = get_cache_entry_tx(&tx, key.as_slice(), now, None)?;
    if existing.is_some() {
        // Entry already exists and hasn't expired - this is idempotent, just return success
        tx.commit().map_err(|err| map_db_err(&err))?;
        return Ok(());
    }

    // Insert new entry
    let times = cache_entry_times(now, REPLAY_REQUEST_TTL_SECONDS)?;
    insert_cache_entry_tx(&tx, key.as_slice(), &[0x1], times)?;
    tx.commit().map_err(|err| map_db_err(&err))?;
    Ok(())
}
