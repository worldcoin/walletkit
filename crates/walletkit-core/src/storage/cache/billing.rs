//! Billing witness cache helpers (WIP-107 §4.6).

use walletkit_sqlite::{params, Connection};
use world_id_core::primitives::{billing::BillingContext, OprfKeyId};

use crate::storage::{
    cache::util::{
        cache_entry_times, get_cache_entry, map_db_err, parse_fixed_bytes,
        prune_expired_entries, upsert_cache_entry,
    },
    error::StorageResult,
};

/// `billing_action || billing_nullifier || R.x || R.y`, each a 32-byte big-endian field element.
pub const BILLING_WITNESS_LEN: usize = 128;

/// The cache key of one billing witness: one billing context under one RP OPRF key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BillingWitnessKey {
    /// The chain hosting the Billing Contract, 32 bytes big-endian.
    pub chain_id: [u8; 32],
    /// The Billing Contract's address.
    pub billing_contract: [u8; 20],
    /// The RP's id.
    pub rp_id: u64,
    /// The start of the billing period, in Unix seconds.
    pub period_start: u64,
    /// The RP's OPRF key id, 20 bytes big-endian.
    pub oprf_key_id: [u8; 20],
}

impl BillingWitnessKey {
    /// The key of `context`'s billing witness under the RP OPRF key `oprf_key_id`.
    #[must_use]
    pub fn new(context: &BillingContext, oprf_key_id: OprfKeyId) -> Self {
        Self {
            chain_id: context.chain_id.to_be_bytes(),
            billing_contract: context.billing_contract.into_array(),
            rp_id: context.rp_id.into_inner(),
            period_start: context.period_start,
            oprf_key_id: oprf_key_id.into_inner().to_be_bytes(),
        }
    }
}

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

    use super::{BillingWitnessKey, BILLING_WITNESS_LEN};
    use crate::storage::{cache::util::billing_witness_key, CacheDb};

    const KEY: BillingWitnessKey = BillingWitnessKey {
        chain_id: [0x01; 32],
        billing_contract: [0x02; 20],
        rp_id: 1,
        period_start: 100,
        oprf_key_id: [0x03; 20],
    };

    fn cache(dir: &tempfile::TempDir) -> CacheDb {
        let key = SecretBox::init_with(|| [0x11; 32]);
        CacheDb::new(&dir.path().join("cache.sqlite"), &key).expect("cache")
    }

    #[test]
    fn billing_witness_key_layout_is_frozen() {
        let key = billing_witness_key(&BillingWitnessKey {
            rp_id: 0x2a,
            period_start: 0x0102,
            ..KEY
        });

        let mut expected = vec![0x04];
        expected.extend_from_slice(&[0x01; 32]);
        expected.extend_from_slice(&[0x02; 20]);
        expected.extend_from_slice(&0x2a_u64.to_be_bytes());
        expected.extend_from_slice(&0x0102_u64.to_be_bytes());
        expected.extend_from_slice(&[0x03; 20]);
        assert_eq!(key, expected);
        assert_eq!(key.len(), 1 + 32 + 20 + 8 + 8 + 20);
    }

    #[test]
    fn billing_witnesses_are_isolated_by_context_and_expire() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = cache(&dir);
        let witness = [0x33; BILLING_WITNESS_LEN];

        db.billing_witness_put(&KEY, &witness, 10, 50).expect("put");

        assert_eq!(
            db.billing_witness_get(&KEY, 49).expect("get"),
            Some(witness)
        );
        for other in [
            BillingWitnessKey { rp_id: 2, ..KEY },
            BillingWitnessKey {
                period_start: 200,
                ..KEY
            },
            BillingWitnessKey {
                oprf_key_id: [0x04; 20],
                ..KEY
            },
        ] {
            assert_eq!(
                db.billing_witness_get(&other, 20)
                    .expect("get other context"),
                None
            );
        }
        assert_eq!(db.billing_witness_get(&KEY, 50).expect("get expired"), None);
    }

    #[test]
    fn billing_witnesses_past_their_end_are_not_stored() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = cache(&dir);
        db.billing_witness_put(&KEY, &[0x33; BILLING_WITNESS_LEN], 50, 50)
            .expect("put");

        assert_eq!(db.billing_witness_get(&KEY, 50).expect("get"), None);
    }

    #[test]
    fn removed_billing_witnesses_are_gone() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = cache(&dir);
        let witness = [0x33; BILLING_WITNESS_LEN];
        db.billing_witness_put(&KEY, &witness, 10, 50).expect("put");

        db.billing_witness_remove(&KEY).expect("remove");

        assert_eq!(db.billing_witness_get(&KEY, 20).expect("get"), None);
    }
}
