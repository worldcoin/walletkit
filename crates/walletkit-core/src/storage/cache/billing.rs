//! Billing witness cache helpers (WIP-107 §4.6).

use walletkit_sqlite::{params, Connection};

use crate::storage::{
    cache::util::{
        cache_entry_times, get_cache_entry, map_db_err, parse_fixed_bytes,
        prune_expired_entries, upsert_cache_entry,
    },
    error::StorageResult,
};

/// `billing_action || billing_nullifier || R.x || R.y`, each a 32-byte big-endian field element.
pub(super) const BILLING_WITNESS_LEN: usize = 128;

/// Fetches the billing witness cached under `key`, if it has not expired.
///
/// # Errors
///
/// Returns an error if the query fails or the cached bytes are malformed.
pub(super) fn get(
    conn: &Connection,
    key: &[u8],
    now: u64,
) -> StorageResult<Option<[u8; BILLING_WITNESS_LEN]>> {
    get_cache_entry(conn, key, now, None)?
        .map(|bytes| {
            parse_fixed_bytes::<BILLING_WITNESS_LEN>(&bytes, "billing_witness")
        })
        .transpose()
}

/// Stores `witness` under `key` until `expires_at`, exclusive. Stores nothing if `expires_at` has
/// passed.
///
/// # Errors
///
/// Returns an error if pruning or the insert fails.
pub(super) fn put(
    conn: &Connection,
    key: &[u8],
    witness: &[u8; BILLING_WITNESS_LEN],
    now: u64,
    expires_at: u64,
) -> StorageResult<()> {
    prune_expired_entries(conn, now)?;
    if expires_at <= now {
        return Ok(());
    }
    // Cache entries stay valid through their `expires_at`; the billing period's end is exclusive.
    let times = cache_entry_times(now, expires_at - now - 1)?;
    upsert_cache_entry(conn, key, witness, times)
}

/// Removes the billing witness cached under `key`, if any.
///
/// # Errors
///
/// Returns an error if the delete fails.
pub(super) fn remove(conn: &Connection, key: &[u8]) -> StorageResult<()> {
    conn.execute(
        "DELETE FROM cache_entries WHERE key_bytes = ?1",
        params![key],
    )
    .map_err(|err| map_db_err(&err))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use secrecy::SecretBox;

    use super::BILLING_WITNESS_LEN;
    use crate::storage::{cache::util::billing_witness_key, CacheDb};

    const CHAIN_ID: [u8; 32] = [0x01; 32];
    const CONTRACT: [u8; 20] = [0x02; 20];
    const OPRF_KEY_ID: [u8; 20] = [0x03; 20];

    fn cache(dir: &tempfile::TempDir) -> CacheDb {
        let key = SecretBox::init_with(|| [0x11; 32]);
        CacheDb::new(&dir.path().join("cache.sqlite"), &key).expect("cache")
    }

    #[test]
    fn billing_witness_key_layout_is_frozen() {
        let key = billing_witness_key(CHAIN_ID, CONTRACT, 0x2a, 0x0102, OPRF_KEY_ID);

        let mut expected = vec![0x04];
        expected.extend_from_slice(&CHAIN_ID);
        expected.extend_from_slice(&CONTRACT);
        expected.extend_from_slice(&0x2a_u64.to_be_bytes());
        expected.extend_from_slice(&0x0102_u64.to_be_bytes());
        expected.extend_from_slice(&OPRF_KEY_ID);
        assert_eq!(key, expected);
        assert_eq!(key.len(), 1 + 32 + 20 + 8 + 8 + 20);
    }

    #[test]
    fn billing_witnesses_are_isolated_by_context_and_expire() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = cache(&dir);
        let witness = [0x33; BILLING_WITNESS_LEN];

        db.billing_witness_put(
            CHAIN_ID,
            CONTRACT,
            1,
            100,
            OPRF_KEY_ID,
            &witness,
            10,
            50,
        )
        .expect("put");

        assert_eq!(
            db.billing_witness_get(CHAIN_ID, CONTRACT, 1, 100, OPRF_KEY_ID, 49)
                .expect("get"),
            Some(witness)
        );
        for (rp_id, period_start, oprf_key_id) in [
            (2, 100, OPRF_KEY_ID),
            (1, 200, OPRF_KEY_ID),
            (1, 100, [0x04; 20]),
        ] {
            assert_eq!(
                db.billing_witness_get(
                    CHAIN_ID,
                    CONTRACT,
                    rp_id,
                    period_start,
                    oprf_key_id,
                    20
                )
                .expect("get other context"),
                None
            );
        }
        assert_eq!(
            db.billing_witness_get(CHAIN_ID, CONTRACT, 1, 100, OPRF_KEY_ID, 50)
                .expect("get expired"),
            None
        );
    }

    #[test]
    fn billing_witnesses_past_their_end_are_not_stored() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = cache(&dir);
        db.billing_witness_put(
            CHAIN_ID,
            CONTRACT,
            1,
            100,
            OPRF_KEY_ID,
            &[0x33; BILLING_WITNESS_LEN],
            50,
            50,
        )
        .expect("put");

        assert_eq!(
            db.billing_witness_get(CHAIN_ID, CONTRACT, 1, 100, OPRF_KEY_ID, 50)
                .expect("get"),
            None
        );
    }

    #[test]
    fn removed_billing_witnesses_are_gone() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = cache(&dir);
        let witness = [0x33; BILLING_WITNESS_LEN];
        db.billing_witness_put(
            CHAIN_ID,
            CONTRACT,
            1,
            100,
            OPRF_KEY_ID,
            &witness,
            10,
            50,
        )
        .expect("put");

        db.billing_witness_remove(CHAIN_ID, CONTRACT, 1, 100, OPRF_KEY_ID)
            .expect("remove");

        assert_eq!(
            db.billing_witness_get(CHAIN_ID, CONTRACT, 1, 100, OPRF_KEY_ID, 20)
                .expect("get"),
            None
        );
    }
}
