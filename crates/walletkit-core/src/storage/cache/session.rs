//! Session seed cache helpers.

use crate::storage::error::StorageResult;
use walletkit_sqlite::Connection;

use crate::storage::cache::util::{
    cache_entry_times, get_cache_entry, parse_fixed_bytes, prune_expired_entries,
    upsert_cache_entry,
};

/// Fetches a cached `session_id_r_seed` for the given key, if still valid.
///
/// # Errors
///
/// Returns an error if the query fails or the cached bytes are malformed.
pub(super) fn get(
    conn: &Connection,
    key: &[u8],
    now: u64,
) -> StorageResult<Option<[u8; 32]>> {
    let raw = get_cache_entry(conn, key, now, None)?;
    match raw {
        Some(bytes) => Ok(Some(parse_fixed_bytes::<32>(&bytes, "session_id_r_seed")?)),
        None => Ok(None),
    }
}

/// Stores a `session_id_r_seed` under the given key with a TTL.
///
/// # Errors
///
/// Returns an error if pruning or insert fails.
pub(super) fn put(
    conn: &Connection,
    key: &[u8],
    session_id_r_seed: [u8; 32],
    now: u64,
    ttl_seconds: u64,
) -> StorageResult<()> {
    prune_expired_entries(conn, now)?;
    let times = cache_entry_times(now, ttl_seconds)?;
    upsert_cache_entry(conn, key, session_id_r_seed.as_ref(), times)
}

#[cfg(test)]
mod tests {
    use crate::storage::CacheDb;
    use secrecy::SecretBox;
    use walletkit_sqlite::params;

    #[test]
    fn session_seeds_are_isolated_by_rp() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key = SecretBox::init_with(|| [0x11; 32]);
        let db = CacheDb::new(&dir.path().join("cache.sqlite"), &key).expect("cache");
        let oprf_seed = [0x22; 32];
        let seed_a = [0x33; 32];
        let seed_b = [0x44; 32];

        db.session_seed_put(1, oprf_seed, seed_a, 100, 10)
            .expect("put A");
        assert_eq!(db.session_seed_get(2, oprf_seed, 100).expect("get B"), None);
        db.session_seed_put(2, oprf_seed, seed_b, 100, 10)
            .expect("put B");
        assert_eq!(
            db.session_seed_get(1, oprf_seed, 100).expect("get A"),
            Some(seed_a)
        );
        assert_eq!(
            db.session_seed_get(2, oprf_seed, 100).expect("get B"),
            Some(seed_b)
        );
        assert_eq!(
            db.session_seed_get(1, [0x55; 32], 100).expect("other seed"),
            None
        );
    }

    #[test]
    fn unscoped_session_seeds_are_ignored() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key = SecretBox::init_with(|| [0x11; 32]);
        let db = CacheDb::new(&dir.path().join("cache.sqlite"), &key).expect("cache");
        let mut old_key = [0x22; 33];
        old_key[0] = 0x02;
        let seed = [0x33; 32];
        db.vault.connection().execute(
            "INSERT INTO cache_entries (key_bytes, value_bytes, inserted_at, expires_at)
             VALUES (?1, ?2, 100, 110)",
            params![old_key.as_slice(), seed.as_slice()],
        ).expect("insert unscoped seed");

        assert_eq!(
            db.session_seed_get(1, [0x22; 32], 100).expect("get A"),
            None
        );
        assert_eq!(
            db.session_seed_get(2, [0x22; 32], 100).expect("get B"),
            None
        );
    }
}
