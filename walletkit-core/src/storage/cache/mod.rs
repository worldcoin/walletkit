//! Encrypted cache database for credential storage.

use std::path::Path;

use rusqlite::Connection;

use crate::storage::error::StorageResult;
use crate::storage::lock::StorageLockGuard;
use crate::storage::types::ReplayGuardResult;

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
    pub fn merkle_cache_get(
        &self,
        registry_kind: u8,
        root: [u8; 32],
        leaf_index: u64,
        valid_before: u64,
    ) -> StorageResult<Option<Vec<u8>>> {
        merkle::get(&self.conn, registry_kind, root, leaf_index, valid_before)
    }

    /// Inserts a cached Merkle proof with a TTL.
    /// Uses the database current time for `inserted_at`.
    ///
    /// Existing entries for the same (registry, root, leaf index) are replaced.
    ///
    /// # Errors
    ///
    /// Returns an error if the insert fails.
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::needless_pass_by_value)]
    pub fn merkle_cache_put(
        &mut self,
        _lock: &StorageLockGuard,
        registry_kind: u8,
        root: [u8; 32],
        leaf_index: u64,
        proof_bytes: Vec<u8>,
        now: u64,
        ttl_seconds: u64,
    ) -> StorageResult<()> {
        merkle::put(
            &self.conn,
            registry_kind,
            root,
            leaf_index,
            proof_bytes.as_ref(),
            now,
            ttl_seconds,
        )
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

    /// Checks for a prior disclosure by request id.
    ///
    /// Returns the original proof bytes to make disclosure idempotent.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub fn replay_guard_get(
        &self,
        request_id: [u8; 32],
        now: u64,
    ) -> StorageResult<Option<Vec<u8>>> {
        nullifiers::replay_guard_bytes_for_request_id(&self.conn, request_id, now)
    }

    /// Enforces replay safety for replay guard.
    ///
    /// Ensures a nullifier is disclosed at most once and that repeated requests
    /// return the previously stored proof bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the disclosure conflicts with an existing nullifier.
    pub fn begin_replay_guard(
        &mut self,
        _lock: &StorageLockGuard,
        request_id: [u8; 32],
        nullifier: [u8; 32],
        proof_bytes: Vec<u8>,
        now: u64,
        ttl_seconds: u64,
    ) -> StorageResult<ReplayGuardResult> {
        nullifiers::begin_replay_guard(
            &mut self.conn,
            request_id,
            nullifier,
            proof_bytes,
            now,
            ttl_seconds,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::error::StorageError;
    use crate::storage::lock::StorageLock;
    use crate::storage::types::ReplayGuardKind;
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
        let root = [0xABu8; 32];
        db.merkle_cache_put(&guard, 1, root, 42, vec![1, 2, 3], 100, 10)
            .expect("put merkle proof");
        let valid_before = 105;
        let hit = db
            .merkle_cache_get(1, root, 42, valid_before)
            .expect("get merkle proof");
        assert!(hit.is_some());
        let miss = db
            .merkle_cache_get(1, root, 42, 111)
            .expect("get merkle proof");
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

    #[test]
    fn test_replay_guard_replay_returns_original_bytes() {
        let path = temp_cache_path();
        let key = [0x77u8; 32];
        let lock_path = temp_lock_path();
        let lock = StorageLock::open(&lock_path).expect("open lock");
        let guard = lock.lock().expect("lock");
        let mut db = CacheDb::new(&path, key, &guard).expect("create cache");
        let request_id = [0x10u8; 32];
        let nullifier = [0x20u8; 32];
        let first = vec![1, 2, 3];
        let second = vec![9, 9, 9];

        let fresh = db
            .begin_replay_guard(&guard, request_id, nullifier, first.clone(), 100, 1000)
            .expect("first disclosure");
        assert_eq!(
            fresh,
            ReplayGuardResult {
                kind: ReplayGuardKind::Fresh,
                bytes: first.clone(),
            }
        );

        let replay = db
            .begin_replay_guard(&guard, request_id, nullifier, second, 101, 1000)
            .expect("replay disclosure");
        assert_eq!(
            replay,
            ReplayGuardResult {
                kind: ReplayGuardKind::Replay,
                bytes: first,
            }
        );
        cleanup_cache_files(&path);
        cleanup_lock_file(&lock_path);
    }

    #[test]
    fn test_replay_guard_request_id_lookup() {
        let path = temp_cache_path();
        let key = [0x66u8; 32];
        let lock_path = temp_lock_path();
        let lock = StorageLock::open(&lock_path).expect("open lock");
        let guard = lock.lock().expect("lock");
        let mut db = CacheDb::new(&path, key, &guard).expect("create cache");
        let request_id = [0x55u8; 32];
        let nullifier = [0x44u8; 32];
        let payload = vec![4, 5, 6];

        db.begin_replay_guard(&guard, request_id, nullifier, payload.clone(), 100, 10)
            .expect("disclosure");

        let hit = db.replay_guard_get(request_id, 105).expect("lookup");
        assert_eq!(hit, Some(payload));

        let miss = db.replay_guard_get(request_id, 111).expect("lookup");
        assert!(miss.is_none());
        cleanup_cache_files(&path);
        cleanup_lock_file(&lock_path);
    }

    #[test]
    fn test_replay_guard_nullifier_conflict_errors() {
        let path = temp_cache_path();
        let key = [0x88u8; 32];
        let lock_path = temp_lock_path();
        let lock = StorageLock::open(&lock_path).expect("open lock");
        let guard = lock.lock().expect("lock");
        let mut db = CacheDb::new(&path, key, &guard).expect("create cache");
        let request_id_a = [0x01u8; 32];
        let request_id_b = [0x02u8; 32];
        let nullifier = [0x03u8; 32];

        db.begin_replay_guard(&guard, request_id_a, nullifier, vec![4], 100, 1000)
            .expect("first disclosure");

        let err = db
            .begin_replay_guard(&guard, request_id_b, nullifier, vec![5], 101, 1000)
            .expect_err("nullifier conflict");
        match err {
            StorageError::NullifierAlreadyDisclosed => {}
            other => panic!("unexpected error: {other}"),
        }
        cleanup_cache_files(&path);
        cleanup_lock_file(&lock_path);
    }

    #[test]
    fn test_replay_guard_expiry_allows_new_insert() {
        let path = temp_cache_path();
        let key = [0x99u8; 32];
        let lock_path = temp_lock_path();
        let lock = StorageLock::open(&lock_path).expect("open lock");
        let guard = lock.lock().expect("lock");
        let mut db = CacheDb::new(&path, key, &guard).expect("create cache");
        let request_id_a = [0x0Au8; 32];
        let request_id_b = [0x0Bu8; 32];
        let nullifier = [0x0Cu8; 32];

        db.begin_replay_guard(&guard, request_id_a, nullifier, vec![7], 100, 10)
            .expect("first disclosure");

        let fresh = db
            .begin_replay_guard(&guard, request_id_b, nullifier, vec![8], 111, 10)
            .expect("second disclosure after expiry");
        assert_eq!(
            fresh,
            ReplayGuardResult {
                kind: ReplayGuardKind::Fresh,
                bytes: vec![8],
            }
        );
        cleanup_cache_files(&path);
        cleanup_lock_file(&lock_path);
    }
}
