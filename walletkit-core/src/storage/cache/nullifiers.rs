//! Used-nullifier cache helpers (Phase 4 hooks).

use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

use crate::storage::error::{StorageError, StorageResult};
use crate::storage::types::ProofDisclosureResult;

use super::util::{expiry_timestamp, map_db_err};

pub(crate) fn begin_proof_disclosure(
    conn: &mut Connection,
    request_id: [u8; 32],
    nullifier: [u8; 32],
    proof_bytes: Vec<u8>,
    now: u64,
    ttl_seconds: u64,
) -> StorageResult<ProofDisclosureResult> {
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(map_db_err)?;
    tx.execute(
        "DELETE FROM used_nullifiers WHERE expires_at <= ?1",
        params![now as i64],
    )
    .map_err(map_db_err)?;

    let existing_proof: Option<Vec<u8>> = tx
        .query_row(
            "SELECT proof_bytes
             FROM used_nullifiers
             WHERE request_id = ?1
               AND expires_at > ?2",
            params![request_id.as_ref(), now as i64],
            |row| row.get(0),
        )
        .optional()
        .map_err(map_db_err)?;
    if let Some(bytes) = existing_proof {
        tx.commit().map_err(map_db_err)?;
        return Ok(ProofDisclosureResult::Replay(bytes));
    }

    let existing_request: Option<Vec<u8>> = tx
        .query_row(
            "SELECT request_id
             FROM used_nullifiers
             WHERE nullifier = ?1
               AND expires_at > ?2",
            params![nullifier.as_ref(), now as i64],
            |row| row.get(0),
        )
        .optional()
        .map_err(map_db_err)?;
    if existing_request.is_some() {
        return Err(StorageError::NullifierAlreadyDisclosed);
    }

    let expires_at = expiry_timestamp(now, ttl_seconds);
    tx.execute(
        "INSERT INTO used_nullifiers (request_id, nullifier, expires_at, proof_bytes)
         VALUES (?1, ?2, ?3, ?4)",
        params![
            request_id.as_ref(),
            nullifier.as_ref(),
            expires_at as i64,
            proof_bytes
        ],
    )
    .map_err(map_db_err)?;
    tx.commit().map_err(map_db_err)?;
    Ok(ProofDisclosureResult::Fresh(proof_bytes))
}
