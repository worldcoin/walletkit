//! Encrypted cache database for credential storage.

use std::path::Path;

use crate::storage::error::StorageResult;
use secrecy::SecretBox;
use walletkit_db::Vault;

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

    /// Fetches a cached `session_id_r_seed` for the given `oprf_seed`.
    ///
    /// Returns `None` when missing or expired.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub fn session_seed_get(
        &self,
        oprf_seed: [u8; 32],
        now: u64,
    ) -> StorageResult<Option<[u8; 32]>> {
        session::get(self.vault.connection(), oprf_seed, now)
    }

    /// Stores a `session_id_r_seed` keyed by `oprf_seed` with a TTL.
    ///
    /// # Errors
    ///
    /// Returns an error if the insert fails.
    pub fn session_seed_put(
        &self,
        oprf_seed: [u8; 32],
        session_id_r_seed: [u8; 32],
        now: u64,
        ttl_seconds: u64,
    ) -> StorageResult<()> {
        session::put(
            self.vault.connection(),
            oprf_seed,
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::SecretBox;
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
        db.session_seed_put(oprf_seed, r_seed, now, 1000)
            .expect("put session seed");
        drop(db);

        fs::write(&path, b"corrupt").expect("corrupt cache file");

        let db = CacheDb::new(&path, &key).expect("rebuild cache");
        let value = db
            .session_seed_get(oprf_seed, now)
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
        db.session_seed_put(oprf_seed, r_seed, now, 10)
            .expect("put session seed");
        let hit = db.session_seed_get(oprf_seed, now).expect("get");
        assert_eq!(hit, Some(r_seed));
        let miss = db.session_seed_get(oprf_seed, now + 11).expect("get");
        assert!(miss.is_none());
        cleanup_cache_files(&path);
        cleanup_lock_file(&lock_path);
    }
}
