//! Encrypted cache database for credential storage.

use std::path::Path;

use crate::storage::error::StorageResult;
use crate::storage::types::{ActivityEntry, ActivityMetadata, ActivityQuery};
use secrecy::SecretBox;
use walletkit_db::Vault;

mod activity;
mod maintenance;
mod merkle;
mod nullifiers;
mod schema;
mod session;
mod util;

/// Encrypted cache database wrapper.
///
/// Stores non-authoritative, regenerable data (proof cache, session keys,
/// replay guard). Wraps [`walletkit_db::Vault`].
///
/// Unlike the credential vault, cache corruption is recoverable: open
/// failures or integrity failures trigger a wipe-and-rebuild rather than
/// a fatal error.
#[derive(Debug)]
pub struct CacheDb {
    vault: Vault,
}

impl CacheDb {
    /// Opens or rebuilds the encrypted cache database at `path`.
    ///
    /// If the database is corrupted or unreadable, the file is deleted
    /// and a fresh empty cache is created.
    ///
    /// # Errors
    ///
    /// Returns an error if the database cannot be opened or rebuilt.
    pub fn new(
        path: &Path,
        k_intermediate: &SecretBox<[u8; 32]>,
    ) -> StorageResult<Self> {
        let vault = maintenance::open_or_rebuild(path, k_intermediate)?;
        Ok(Self { vault })
    }

    /// Fetches a cached Merkle proof if it remains valid beyond `valid_until`.
    ///
    /// Returns `None` when missing or expired so callers can refetch from the
    /// indexer without relying on stale proofs.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub fn merkle_cache_get(&self, valid_until: u64) -> StorageResult<Option<Vec<u8>>> {
        merkle::get(self.vault.connection(), valid_until)
    }

    /// Inserts a cached Merkle proof with a TTL. Existing entries for the
    /// same key are replaced.
    ///
    /// # Errors
    ///
    /// Returns an error if the insert fails.
    pub fn merkle_cache_put(
        &self,
        proof_bytes: &[u8],
        now: u64,
        ttl_seconds: u64,
    ) -> StorageResult<()> {
        merkle::put(self.vault.connection(), proof_bytes, now, ttl_seconds)
    }

    /// Fetches a cached `session_id_r_seed` for the given RP and `oprf_seed`.
    ///
    /// Returns `None` when missing or expired.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub fn session_seed_get(
        &self,
        rp_id: u64,
        oprf_seed: [u8; 32],
        now: u64,
    ) -> StorageResult<Option<[u8; 32]>> {
        let key = util::session_cache_key(rp_id, oprf_seed);
        session::get(self.vault.connection(), &key, now)
    }

    /// Stores a `session_id_r_seed` keyed by RP and `oprf_seed` with a TTL.
    ///
    /// # Errors
    ///
    /// Returns an error if the insert fails.
    pub fn session_seed_put(
        &self,
        rp_id: u64,
        oprf_seed: [u8; 32],
        session_id_r_seed: [u8; 32],
        now: u64,
        ttl_seconds: u64,
    ) -> StorageResult<()> {
        let key = util::session_cache_key(rp_id, oprf_seed);
        session::put(
            self.vault.connection(),
            &key,
            session_id_r_seed,
            now,
            ttl_seconds,
        )
    }

    /// Checks whether a replay guard entry exists for the given nullifier.
    ///
    /// # Returns
    ///
    /// - `true` if a replay guard entry exists (nullifier replay).
    /// - `false` otherwise.
    ///
    /// # Errors
    ///
    /// Returns an error if the query to the cache unexpectedly fails.
    pub fn is_nullifier_replay(
        &self,
        nullifier: [u8; 32],
        now: u64,
    ) -> StorageResult<bool> {
        nullifiers::is_nullifier_replay(self.vault.connection(), nullifier, now)
    }

    /// After a proof has been successfully generated, creates a replay guard
    /// entry locally to avoid future replays of the same nullifier.
    ///
    /// # Errors
    ///
    /// Returns an error if the query to the cache unexpectedly fails.
    pub fn replay_guard_set(&self, nullifier: [u8; 32], now: u64) -> StorageResult<()> {
        nullifiers::replay_guard_set(self.vault.connection(), nullifier, now)
    }

    /// Records an activity entry.
    ///
    /// # Errors
    ///
    /// Returns an error if the entry is misconfigured or the insert fails.
    pub fn record_activity(
        &self,
        entry: &ActivityEntry,
        now: u64,
    ) -> StorageResult<u64> {
        activity::record(self.vault.connection(), entry, now)
    }

    /// Lists activity entries, most recent first.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub fn list_activities(
        &self,
        query: ActivityQuery,
        limit: u32,
        offset: u32,
    ) -> StorageResult<Vec<ActivityEntry>> {
        activity::list(self.vault.connection(), query, limit, offset)
    }

    /// Returns aggregate activity metadata.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub fn activity_metadata(&self) -> StorageResult<ActivityMetadata> {
        activity::metadata(self.vault.connection())
    }

    /// Deletes all activity entries. Returns the number of entries deleted.
    ///
    /// # Errors
    ///
    /// Returns an error if the delete fails.
    pub fn clear_activities(&self) -> StorageResult<u64> {
        activity::clear(self.vault.connection())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::types::{ActivityOutcome, ProtocolVersion};
    use secrecy::SecretBox;
    use std::fs;
    use std::path::PathBuf;
    use uuid::Uuid;

    fn sample_new_activity_entry() -> ActivityEntry {
        ActivityEntry {
            id: None,
            rp_id: 1,
            client_id: "req-1".to_string(),
            protocol: ProtocolVersion::V3,
            timestamp: None,
            issuer_schema_ids: vec![],
            outcome: ActivityOutcome::Completed,
            failure_reason: None,
        }
    }

    fn temp_cache_path() -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!("walletkit-cache-{}.sqlite", Uuid::new_v4()));
        path
    }

    fn cleanup_cache_files(path: &Path) {
        let _ = fs::remove_file(path);
        let _ = fs::remove_file(path.with_extension("sqlite-wal"));
        let _ = fs::remove_file(path.with_extension("sqlite-shm"));
    }

    fn temp_lock_path() -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!("walletkit-cache-lock-{}.lock", Uuid::new_v4()));
        path
    }

    fn cleanup_lock_file(path: &Path) {
        let _ = fs::remove_file(path);
    }

    #[test]
    fn test_cache_create_and_open() {
        let path = temp_cache_path();
        let key = SecretBox::init_with(|| [0x11u8; 32]);
        let lock_path = temp_lock_path();
        let db = CacheDb::new(&path, &key).expect("create cache");
        drop(db);
        CacheDb::new(&path, &key).expect("open cache");
        cleanup_cache_files(&path);
        cleanup_lock_file(&lock_path);
    }

    #[test]
    fn test_cache_rebuild_on_corruption() {
        let path = temp_cache_path();
        let key = SecretBox::init_with(|| [0x22u8; 32]);
        let lock_path = temp_lock_path();
        let db = CacheDb::new(&path, &key).expect("create cache");
        let oprf_seed = [0x01u8; 32];
        let r_seed = [0x02u8; 32];
        let now = 1_000;
        db.session_seed_put(1, oprf_seed, r_seed, now, 1000)
            .expect("put session seed");
        drop(db);

        fs::write(&path, b"corrupt").expect("corrupt cache file");

        let db = CacheDb::new(&path, &key).expect("rebuild cache");
        let value = db
            .session_seed_get(1, oprf_seed, now)
            .expect("get session seed");
        assert!(value.is_none());
        cleanup_cache_files(&path);
        cleanup_lock_file(&lock_path);
    }

    #[test]
    fn test_merkle_cache_ttl() {
        let path = temp_cache_path();
        let key = SecretBox::init_with(|| [0x33u8; 32]);
        let lock_path = temp_lock_path();
        let db = CacheDb::new(&path, &key).expect("create cache");
        db.merkle_cache_put(&[1, 2, 3], 100, 10)
            .expect("put merkle proof");
        let hit = db.merkle_cache_get(105).expect("get merkle proof");
        assert!(hit.is_some());
        let miss = db.merkle_cache_get(111).expect("get merkle proof");
        assert!(miss.is_none());
        cleanup_cache_files(&path);
        cleanup_lock_file(&lock_path);
    }

    #[test]
    fn test_session_seed_cache_ttl() {
        let path = temp_cache_path();
        let key = SecretBox::init_with(|| [0x44u8; 32]);
        let lock_path = temp_lock_path();
        let db = CacheDb::new(&path, &key).expect("create cache");
        let oprf_seed = [0x55u8; 32];
        let r_seed = [0x66u8; 32];
        let now = 100;
        db.session_seed_put(1, oprf_seed, r_seed, now, 10)
            .expect("put session seed");
        let hit = db.session_seed_get(1, oprf_seed, now).expect("get");
        assert_eq!(hit, Some(r_seed));
        let miss = db.session_seed_get(1, oprf_seed, now + 11).expect("get");
        assert!(miss.is_none());
        cleanup_cache_files(&path);
        cleanup_lock_file(&lock_path);
    }

    #[test]
    fn test_activity_survives_disposable_cache_reset() {
        let path = temp_cache_path();
        let key = SecretBox::init_with(|| [0x77u8; 32]);
        let lock_path = temp_lock_path();
        let db = CacheDb::new(&path, &key).expect("create cache");

        db.record_activity(&sample_new_activity_entry(), 1000)
            .expect("record activity");

        db.session_seed_put(1, [0x01u8; 32], [0x02u8; 32], 1000, 1000)
            .expect("put session seed");

        drop(db);

        let conn = walletkit_sqlite::cipher::open_encrypted(&path, &key, false)
            .expect("open raw connection");
        conn.execute(
            "UPDATE cache_meta SET schema_version = schema_version + 1",
            &[],
        )
        .expect("bump schema version");
        drop(conn);

        let db = CacheDb::new(&path, &key).expect("reopen cache after version bump");

        let seed = db
            .session_seed_get(1, [0x01u8; 32], 1000)
            .expect("get session seed");

        assert!(
            seed.is_none(),
            "disposable cache_entries should be wiped on a schema version mismatch"
        );

        let entries = db
            .list_activities(ActivityQuery::default(), 10, 0)
            .expect("list activities after version bump");

        assert_eq!(entries.len(), 1);

        cleanup_cache_files(&path);
        cleanup_lock_file(&lock_path);
    }

    #[test]
    fn test_activity_migration_applies_to_preexisting_cache_file() {
        let path = temp_cache_path();
        let key = SecretBox::init_with(|| [0x88u8; 32]);
        let lock_path = temp_lock_path();

        let conn = walletkit_sqlite::cipher::open_encrypted(&path, &key, false)
            .expect("create raw connection");
        conn.execute_batch(
            "CREATE TABLE cache_meta (
                schema_version INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );
            CREATE TABLE cache_entries (
                key_bytes BLOB NOT NULL,
                value_bytes BLOB NOT NULL,
                inserted_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                PRIMARY KEY (key_bytes)
            );
            INSERT INTO cache_meta (schema_version, created_at, updated_at)
            VALUES (2, 1000, 1000);
            INSERT INTO cache_entries (key_bytes, value_bytes, inserted_at, expires_at)
            VALUES (X'AA', X'BB', 1000, 999999999);",
        )
        .expect("seed legacy cache schema");
        drop(conn);

        let db = CacheDb::new(&path, &key).expect("open legacy cache file");

        db.record_activity(&sample_new_activity_entry(), 1000)
            .expect("record activity after migration");

        let entries = db
            .list_activities(ActivityQuery::default(), 10, 0)
            .expect("list activities");

        assert_eq!(entries.len(), 1, "migration should add activity_entries");

        drop(db);

        let conn = walletkit_sqlite::cipher::open_encrypted(&path, &key, false)
            .expect("reopen raw connection");

        let count = conn
            .query_row("SELECT COUNT(*) FROM cache_entries", &[], |stmt| {
                Ok(stmt.column_i64(0))
            })
            .expect("count cache_entries");

        assert_eq!(
            count, 1,
            "pre-existing cache_entries row must survive the activity migration"
        );

        cleanup_cache_files(&path);
        cleanup_lock_file(&lock_path);
    }
}
