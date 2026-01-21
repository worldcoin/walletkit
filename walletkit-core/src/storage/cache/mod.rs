//! Encrypted cache database for credential storage.

use std::path::Path;

use rusqlite::Connection;

use crate::storage::error::StorageResult;
use crate::storage::lock::StorageLockGuard;
use crate::storage::types::ProofDisclosureResult;

mod maintenance;
mod merkle;
mod nullifiers;
mod schema;
mod session;
mod util;

/// Encrypted cache database wrapper.
#[derive(Debug)]
pub struct CacheDb {
    conn: Connection,
}

impl CacheDb {
    /// Opens or creates the encrypted cache database at `path`.
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

    /// Fetches a cached Merkle proof if available.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub fn merkle_cache_get(
        &self,
        registry_kind: u8,
        root: [u8; 32],
        leaf_index: u64,
        now: u64,
    ) -> StorageResult<Option<Vec<u8>>> {
        merkle::get(&self.conn, registry_kind, root, leaf_index, now)
    }

    /// Inserts a cached Merkle proof with a TTL.
    ///
    /// # Errors
    ///
    /// Returns an error if the insert fails.
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
            proof_bytes,
            now,
            ttl_seconds,
        )
    }

    /// Fetches a cached session key if present.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub fn session_key_get(
        &self,
        rp_id: [u8; 32],
        now: u64,
    ) -> StorageResult<Option<[u8; 32]>> {
        session::get(&self.conn, rp_id, now)
    }

    /// Stores a session key with a TTL.
    ///
    /// # Errors
    ///
    /// Returns an error if the insert fails.
    pub fn session_key_put(
        &mut self,
        _lock: &StorageLockGuard,
        rp_id: [u8; 32],
        k_session: [u8; 32],
        now: u64,
        ttl_seconds: u64,
    ) -> StorageResult<()> {
        session::put(&self.conn, rp_id, k_session, now, ttl_seconds)
    }

    /// Enforces replay safety for proof disclosure.
    ///
    /// # Errors
    ///
    /// Returns an error if the disclosure conflicts with an existing nullifier.
    pub fn begin_proof_disclosure(
        &mut self,
        _lock: &StorageLockGuard,
        request_id: [u8; 32],
        nullifier: [u8; 32],
        proof_bytes: Vec<u8>,
        now: u64,
        ttl_seconds: u64,
    ) -> StorageResult<ProofDisclosureResult> {
        nullifiers::begin_proof_disclosure(
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
    use std::fs;
    use std::path::PathBuf;
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
        db.session_key_put(&guard, rp_id, k_session, 100, 1000)
            .expect("put session key");
        drop(db);

        fs::write(&path, b"corrupt").expect("corrupt cache file");

        let db = CacheDb::new(&path, key, &guard).expect("rebuild cache");
        let value = db.session_key_get(rp_id, 200).expect("get session key");
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
        let hit = db
            .merkle_cache_get(1, root, 42, 105)
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
        db.session_key_put(&guard, rp_id, k_session, 100, 10)
            .expect("put session key");
        let hit = db.session_key_get(rp_id, 105).expect("get session key");
        assert!(hit.is_some());
        let miss = db.session_key_get(rp_id, 111).expect("get session key");
        assert!(miss.is_none());
        cleanup_cache_files(&path);
        cleanup_lock_file(&lock_path);
    }

    #[test]
    fn test_disclosure_replay_returns_original_bytes() {
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
            .begin_proof_disclosure(
                &guard,
                request_id,
                nullifier,
                first.clone(),
                100,
                1000,
            )
            .expect("first disclosure");
        assert_eq!(fresh, ProofDisclosureResult::Fresh(first.clone()));

        let replay = db
            .begin_proof_disclosure(&guard, request_id, nullifier, second, 101, 1000)
            .expect("replay disclosure");
        assert_eq!(replay, ProofDisclosureResult::Replay(first));
        cleanup_cache_files(&path);
        cleanup_lock_file(&lock_path);
    }

    #[test]
    fn test_disclosure_nullifier_conflict_errors() {
        let path = temp_cache_path();
        let key = [0x88u8; 32];
        let lock_path = temp_lock_path();
        let lock = StorageLock::open(&lock_path).expect("open lock");
        let guard = lock.lock().expect("lock");
        let mut db = CacheDb::new(&path, key, &guard).expect("create cache");
        let request_id_a = [0x01u8; 32];
        let request_id_b = [0x02u8; 32];
        let nullifier = [0x03u8; 32];

        db.begin_proof_disclosure(&guard, request_id_a, nullifier, vec![4], 100, 1000)
            .expect("first disclosure");

        let err = db
            .begin_proof_disclosure(&guard, request_id_b, nullifier, vec![5], 101, 1000)
            .expect_err("nullifier conflict");
        match err {
            StorageError::NullifierAlreadyDisclosed => {}
            other => panic!("unexpected error: {other}"),
        }
        cleanup_cache_files(&path);
        cleanup_lock_file(&lock_path);
    }

    #[test]
    fn test_disclosure_expiry_allows_new_insert() {
        let path = temp_cache_path();
        let key = [0x99u8; 32];
        let lock_path = temp_lock_path();
        let lock = StorageLock::open(&lock_path).expect("open lock");
        let guard = lock.lock().expect("lock");
        let mut db = CacheDb::new(&path, key, &guard).expect("create cache");
        let request_id_a = [0x0Au8; 32];
        let request_id_b = [0x0Bu8; 32];
        let nullifier = [0x0Cu8; 32];

        db.begin_proof_disclosure(&guard, request_id_a, nullifier, vec![7], 100, 10)
            .expect("first disclosure");

        let fresh = db
            .begin_proof_disclosure(&guard, request_id_b, nullifier, vec![8], 111, 10)
            .expect("second disclosure after expiry");
        assert_eq!(fresh, ProofDisclosureResult::Fresh(vec![8]));
        cleanup_cache_files(&path);
        cleanup_lock_file(&lock_path);
    }
}
