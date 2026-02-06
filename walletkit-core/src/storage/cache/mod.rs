//! Encrypted cache database for credential storage.

use std::path::Path;

use rusqlite::Connection;

use crate::storage::error::StorageResult;
use crate::storage::lock::StorageLockGuard;

mod maintenance;
mod merkle;
mod nullifiers;
mod schema;
mod session;
mod util;

/// Encrypted cache database wrapper.
///
/// Stores non-authoritative, regenerable data (proof cache, session keys, replay guard)
/// to improve performance without affecting correctness if rebuilt.
#[derive(Debug)]
pub struct CacheDb {
    conn: Connection,
}

impl CacheDb {
    /// Opens or creates the encrypted cache database at `path`.
    ///
    /// If integrity checks fail, the cache is rebuilt since its contents can be
    /// regenerated from authoritative sources.
    ///
    /// # Errors
    ///
    /// Returns an error if the database cannot be opened or rebuilt.
    pub fn new(
        path: &Path,
        k_intermediate: [u8; 32],
        _lock: &StorageLockGuard,
    ) -> StorageResult<Self> {
        let conn = maintenance::open_or_rebuild(path, k_intermediate)?;
        Ok(Self { conn })
    }

    /// Fetches a cached Merkle proof if it remains valid beyond `valid_before`.
    ///
    /// Returns `None` when missing or expired so callers can refetch from the
    /// indexer without relying on stale proofs.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub fn merkle_cache_get(&self, valid_until: u64) -> StorageResult<Option<Vec<u8>>> {
        merkle::get(&self.conn, valid_until)
    }

    /// Inserts a cached Merkle proof with a TTL.
    /// Uses the database current time for `inserted_at`.
    ///
    /// Existing entries for the same (registry, root, leaf index) are replaced.
    ///
    /// # Errors
    ///
    /// Returns an error if the insert fails.
    #[allow(clippy::needless_pass_by_value)]
    pub fn merkle_cache_put(
        &mut self,
        _lock: &StorageLockGuard,
        proof_bytes: Vec<u8>,
        now: u64,
        ttl_seconds: u64,
    ) -> StorageResult<()> {
        merkle::put(&self.conn, proof_bytes.as_ref(), now, ttl_seconds)
    }

    /// Fetches a cached session key if present.
    ///
    /// This value is the per-RP session seed (aka `session_id_r_seed` in the
    /// protocol). It is derived from `K_intermediate` and `rp_id` and is used to
    /// derive the per-session `r` that feeds the sessionId commitment. The cache
    /// is an optional performance hint and may be missing or expired.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub fn session_key_get(&self, rp_id: [u8; 32]) -> StorageResult<Option<[u8; 32]>> {
        session::get(&self.conn, rp_id)
    }

    /// Stores a session key with a TTL.
    ///
    /// The key is cached per relying party (`rp_id`) and replaced on insert.
    ///
    /// # Errors
    ///
    /// Returns an error if the insert fails.
    pub fn session_key_put(
        &mut self,
        _lock: &StorageLockGuard,
        rp_id: [u8; 32],
        k_session: [u8; 32],
        ttl_seconds: u64,
    ) -> StorageResult<()> {
        session::put(&self.conn, rp_id, k_session, ttl_seconds)
    }

    /// Checks whether a replay guard entry exists for the given nullifier.
    ///
    /// # Returns
    /// - bool: true if a replay guard entry exists (hence signalling a nullifier replay), false otherwise.
    ///
    /// # Errors
    ///
    /// Returns an error if the query to the cache unexpectedly fails.
    pub fn is_nullifier_replay(
        &self,
        nullifier: [u8; 32],
        now: u64,
    ) -> StorageResult<bool> {
        nullifiers::is_nullifier_replay(&self.conn, nullifier, now)
    }

    /// After a proof has been successfully generated, creates a replay guard entry
    /// locally to avoid future replays of the same nullifier.
    ///
    /// # Errors
    ///
    /// Returns an error if the query to the cache unexpectedly fails.
    pub fn replay_guard_set(
        &mut self,
        _lock: &StorageLockGuard,
        nullifier: [u8; 32],
        now: u64,
    ) -> StorageResult<()> {
        nullifiers::replay_guard_set(&mut self.conn, nullifier, now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::lock::StorageLock;
    use std::fs;
    use std::path::PathBuf;
    use std::time::Duration;
    use uuid::Uuid;

    fn temp_cache_path() -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!("walletkit-cache-{}.sqlite", Uuid::new_v4()));
        path
    }

    fn cleanup_cache_files(path: &Path) {
        let _ = fs::remove_file(path);
        let wal_path = path.with_extension("sqlite-wal");
        let shm_path = path.with_extension("sqlite-shm");
        let _ = fs::remove_file(wal_path);
        let _ = fs::remove_file(shm_path);
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
        let key = [0x11u8; 32];
        let lock_path = temp_lock_path();
        let lock = StorageLock::open(&lock_path).expect("open lock");
        let guard = lock.lock().expect("lock");
        let db = CacheDb::new(&path, key, &guard).expect("create cache");
        drop(db);
        CacheDb::new(&path, key, &guard).expect("open cache");
        cleanup_cache_files(&path);
        cleanup_lock_file(&lock_path);
    }

    #[test]
    fn test_cache_rebuild_on_corruption() {
        let path = temp_cache_path();
        let key = [0x22u8; 32];
        let lock_path = temp_lock_path();
        let lock = StorageLock::open(&lock_path).expect("open lock");
        let guard = lock.lock().expect("lock");
        let mut db = CacheDb::new(&path, key, &guard).expect("create cache");
        let rp_id = [0x01u8; 32];
        let k_session = [0x02u8; 32];
        db.session_key_put(&guard, rp_id, k_session, 1000)
            .expect("put session key");
        drop(db);

        fs::write(&path, b"corrupt").expect("corrupt cache file");

        let db = CacheDb::new(&path, key, &guard).expect("rebuild cache");
        let value = db.session_key_get(rp_id).expect("get session key");
        assert!(value.is_none());
        cleanup_cache_files(&path);
        cleanup_lock_file(&lock_path);
    }

    #[test]
    fn test_merkle_cache_ttl() {
        let path = temp_cache_path();
        let key = [0x33u8; 32];
        let lock_path = temp_lock_path();
        let lock = StorageLock::open(&lock_path).expect("open lock");
        let guard = lock.lock().expect("lock");
        let mut db = CacheDb::new(&path, key, &guard).expect("create cache");
        db.merkle_cache_put(&guard, vec![1, 2, 3], 100, 10)
            .expect("put merkle proof");
        let valid_until = 105;
        let hit = db.merkle_cache_get(valid_until).expect("get merkle proof");
        assert!(hit.is_some());
        let miss = db.merkle_cache_get(111).expect("get merkle proof");
        assert!(miss.is_none());
        cleanup_cache_files(&path);
        cleanup_lock_file(&lock_path);
    }

    #[test]
    fn test_session_cache_ttl() {
        let path = temp_cache_path();
        let key = [0x44u8; 32];
        let lock_path = temp_lock_path();
        let lock = StorageLock::open(&lock_path).expect("open lock");
        let guard = lock.lock().expect("lock");
        let mut db = CacheDb::new(&path, key, &guard).expect("create cache");
        let rp_id = [0x55u8; 32];
        let k_session = [0x66u8; 32];
        db.session_key_put(&guard, rp_id, k_session, 1)
            .expect("put session key");
        let hit = db.session_key_get(rp_id).expect("get session key");
        assert!(hit.is_some());
        std::thread::sleep(Duration::from_secs(2));
        let miss = db.session_key_get(rp_id).expect("get session key");
        assert!(miss.is_none());
        cleanup_cache_files(&path);
        cleanup_lock_file(&lock_path);
    }
}
