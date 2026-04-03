//! Vault database unit tests.

use super::helpers::{compute_content_id, map_db_err};
use super::*;
use crate::storage::lock::StorageLock;
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;
use zeroize::Zeroizing;

fn temp_vault_path() -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!("walletkit-vault-{}.sqlite", Uuid::new_v4()));
    path
}

fn cleanup_vault_files(path: &Path) {
    let _ = fs::remove_file(path);
    let wal_path = path.with_extension("sqlite-wal");
    let shm_path = path.with_extension("sqlite-shm");
    let _ = fs::remove_file(wal_path);
    let _ = fs::remove_file(shm_path);
}

fn temp_lock_path() -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!("walletkit-vault-lock-{}.lock", Uuid::new_v4()));
    path
}

fn cleanup_lock_file(path: &Path) {
    let _ = fs::remove_file(path);
}

fn sample_blinding_factor() -> Vec<u8> {
    [0x11u8; 32].to_vec()
}

#[test]
fn test_vault_create_and_open() {
    let path = temp_vault_path();
    let key = Zeroizing::new([0x42u8; 32]);
    let lock_path = temp_lock_path();
    let lock = StorageLock::open(&lock_path).expect("open lock");
    let guard = lock.lock().expect("lock");
    let db = VaultDb::new(&path, &key, &guard).expect("create vault");
    drop(db);
    VaultDb::new(&path, &key, &guard).expect("open vault");
    cleanup_vault_files(&path);
    cleanup_lock_file(&lock_path);
}

#[test]
fn test_vault_wrong_key_fails() {
    let path = temp_vault_path();
    let key = Zeroizing::new([0x01u8; 32]);
    let lock_path = temp_lock_path();
    let lock = StorageLock::open(&lock_path).expect("open lock");
    let guard = lock.lock().expect("lock");
    VaultDb::new(&path, &key, &guard).expect("create vault");
    let wrong_key = Zeroizing::new([0x02u8; 32]);
    let err = VaultDb::new(&path, &wrong_key, &guard).expect_err("wrong key");
    match err {
        StorageError::VaultDb(_) | StorageError::CorruptedVault(_) => {}
        _ => panic!("unexpected error: {err}"),
    }
    cleanup_vault_files(&path);
    cleanup_lock_file(&lock_path);
}

#[test]
fn test_leaf_index_set_once() {
    let path = temp_vault_path();
    let lock_path = temp_lock_path();
    let lock = StorageLock::open(&lock_path).expect("open lock");
    let guard = lock.lock().expect("lock");
    let key = Zeroizing::new([0x03u8; 32]);
    let mut db = VaultDb::new(&path, &key, &guard).expect("create vault");
    db.init_leaf_index(&guard, 42, 100)
        .expect("init leaf index");
    db.init_leaf_index(&guard, 42, 200)
        .expect("init leaf index again");
    cleanup_vault_files(&path);
    cleanup_lock_file(&lock_path);
}

#[test]
fn test_leaf_index_immutable() {
    let path = temp_vault_path();
    let lock_path = temp_lock_path();
    let lock = StorageLock::open(&lock_path).expect("open lock");
    let guard = lock.lock().expect("lock");
    let key = Zeroizing::new([0x04u8; 32]);
    let mut db = VaultDb::new(&path, &key, &guard).expect("create vault");
    db.init_leaf_index(&guard, 7, 100).expect("init leaf index");
    let err = db.init_leaf_index(&guard, 8, 200).expect_err("mismatch");
    match err {
        StorageError::InvalidLeafIndex { .. } => {}
        _ => panic!("unexpected error: {err}"),
    }
    cleanup_vault_files(&path);
    cleanup_lock_file(&lock_path);
}

#[test]
fn test_store_credential_without_associated_data() {
    let path = temp_vault_path();
    let lock_path = temp_lock_path();
    let lock = StorageLock::open(&lock_path).expect("open lock");
    let guard = lock.lock().expect("lock");
    let key = Zeroizing::new([0x05u8; 32]);
    let mut db = VaultDb::new(&path, &key, &guard).expect("create vault");
    let credential_id = db
        .store_credential(
            &guard,
            10,
            sample_blinding_factor(),
            123,
            2000,
            b"credential".to_vec(),
            None,
            1000,
        )
        .expect("store credential");
    let records = db.list_credentials(None, 1000).expect("list credentials");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].credential_id, credential_id);
    assert_eq!(records[0].issuer_schema_id, 10);
    assert_eq!(records[0].expires_at, 2000);
    assert!(!records[0].is_expired);
    cleanup_vault_files(&path);
    cleanup_lock_file(&lock_path);
}

#[test]
fn test_store_credential_with_associated_data() {
    let path = temp_vault_path();
    let lock_path = temp_lock_path();
    let lock = StorageLock::open(&lock_path).expect("open lock");
    let guard = lock.lock().expect("lock");
    let key = Zeroizing::new([0x06u8; 32]);
    let mut db = VaultDb::new(&path, &key, &guard).expect("create vault");
    db.store_credential(
        &guard,
        11,
        sample_blinding_factor(),
        456,
        2000,
        b"credential-2".to_vec(),
        Some(b"associated".to_vec()),
        1000,
    )
    .expect("store credential");
    let records = db.list_credentials(None, 1000).expect("list credentials");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].issuer_schema_id, 11);
    assert_eq!(records[0].expires_at, 2000);
    assert!(!records[0].is_expired);
    cleanup_vault_files(&path);
    cleanup_lock_file(&lock_path);
}

#[test]
fn test_content_id_determinism() {
    let a = compute_content_id(BlobKind::CredentialBlob, b"data");
    let b = compute_content_id(BlobKind::CredentialBlob, b"data");
    assert_eq!(a, b);
}

#[test]
fn test_content_id_deduplication() {
    let path = temp_vault_path();
    let lock_path = temp_lock_path();
    let lock = StorageLock::open(&lock_path).expect("open lock");
    let guard = lock.lock().expect("lock");
    let key = Zeroizing::new([0x07u8; 32]);
    let mut db = VaultDb::new(&path, &key, &guard).expect("create vault");
    let first_id = db
        .store_credential(
            &guard,
            12,
            sample_blinding_factor(),
            1,
            2000,
            b"same".to_vec(),
            None,
            1000,
        )
        .expect("store credential");
    let second_id = db
        .store_credential(
            &guard,
            12,
            sample_blinding_factor(),
            1,
            2000,
            b"same".to_vec(),
            None,
            1001,
        )
        .expect("store credential");
    let count = db
        .conn
        .query_row("SELECT COUNT(*) FROM blob_objects", &[], |stmt| {
            Ok(stmt.column_i64(0))
        })
        .map_err(|err| map_db_err(&err))
        .expect("count blobs");
    assert_eq!(count, 1);

    db.delete_credential(&guard, first_id)
        .expect("delete first credential");

    let count_after_first_delete = db
        .conn
        .query_row("SELECT COUNT(*) FROM blob_objects", &[], |stmt| {
            Ok(stmt.column_i64(0))
        })
        .map_err(|err| map_db_err(&err))
        .expect("count blobs after first delete");
    assert_eq!(count_after_first_delete, 1);

    db.delete_credential(&guard, second_id)
        .expect("delete second credential");

    let count_after_second_delete = db
        .conn
        .query_row("SELECT COUNT(*) FROM blob_objects", &[], |stmt| {
            Ok(stmt.column_i64(0))
        })
        .map_err(|err| map_db_err(&err))
        .expect("count blobs after second delete");
    assert_eq!(count_after_second_delete, 0);

    cleanup_vault_files(&path);
    cleanup_lock_file(&lock_path);
}

#[test]
fn test_list_credentials_by_issuer() {
    let path = temp_vault_path();
    let lock_path = temp_lock_path();
    let lock = StorageLock::open(&lock_path).expect("open lock");
    let guard = lock.lock().expect("lock");
    let key = Zeroizing::new([0x08u8; 32]);
    let mut db = VaultDb::new(&path, &key, &guard).expect("create vault");
    db.store_credential(
        &guard,
        100,
        sample_blinding_factor(),
        1,
        2000,
        b"issuer-a".to_vec(),
        None,
        1000,
    )
    .expect("store credential");
    db.store_credential(
        &guard,
        200,
        sample_blinding_factor(),
        1,
        2000,
        b"issuer-b".to_vec(),
        None,
        1000,
    )
    .expect("store credential");
    let records = db
        .list_credentials(Some(200), 1000)
        .expect("list credentials");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].issuer_schema_id, 200);
    cleanup_vault_files(&path);
    cleanup_lock_file(&lock_path);
}

#[test]
fn test_list_credentials_marks_expired() {
    let path = temp_vault_path();
    let lock_path = temp_lock_path();
    let lock = StorageLock::open(&lock_path).expect("open lock");
    let guard = lock.lock().expect("lock");
    let key = Zeroizing::new([0x09u8; 32]);
    let mut db = VaultDb::new(&path, &key, &guard).expect("create vault");
    db.store_credential(
        &guard,
        300,
        sample_blinding_factor(),
        1,
        900,
        b"expired".to_vec(),
        None,
        1000,
    )
    .expect("store expired credential");
    db.store_credential(
        &guard,
        301,
        sample_blinding_factor(),
        1,
        2000,
        b"active".to_vec(),
        None,
        1000,
    )
    .expect("store active credential");

    let records = db.list_credentials(None, 1000).expect("list credentials");
    assert_eq!(records.len(), 2);
    assert!(records.iter().any(|record| record.is_expired));
    assert!(records.iter().any(|record| !record.is_expired));

    cleanup_vault_files(&path);
    cleanup_lock_file(&lock_path);
}

#[test]
fn test_list_credentials_by_issuer_includes_expired() {
    let path = temp_vault_path();
    let lock_path = temp_lock_path();
    let lock = StorageLock::open(&lock_path).expect("open lock");
    let guard = lock.lock().expect("lock");
    let key = Zeroizing::new([0x0Au8; 32]);
    let mut db = VaultDb::new(&path, &key, &guard).expect("create vault");
    db.store_credential(
        &guard,
        500,
        sample_blinding_factor(),
        1,
        900,
        b"expired".to_vec(),
        None,
        1000,
    )
    .expect("store credential");

    let records = db
        .list_credentials(Some(500), 1000)
        .expect("list credentials");
    assert_eq!(records.len(), 1);
    assert!(records[0].is_expired);

    cleanup_vault_files(&path);
    cleanup_lock_file(&lock_path);
}

#[test]
fn test_delete_credential_by_id() {
    let path = temp_vault_path();
    let lock_path = temp_lock_path();
    let lock = StorageLock::open(&lock_path).expect("open lock");
    let guard = lock.lock().expect("lock");
    let key = Zeroizing::new([0x0Bu8; 32]);
    let mut db = VaultDb::new(&path, &key, &guard).expect("create vault");
    let credential_id = db
        .store_credential(
            &guard,
            400,
            sample_blinding_factor(),
            1,
            2000,
            b"to-delete".to_vec(),
            None,
            1000,
        )
        .expect("store credential");

    let blob_count_before = db
        .conn
        .query_row("SELECT COUNT(*) FROM blob_objects", &[], |stmt| {
            Ok(stmt.column_i64(0))
        })
        .map_err(|err| map_db_err(&err))
        .expect("count blobs before delete");
    assert_eq!(blob_count_before, 1);

    db.delete_credential(&guard, credential_id)
        .expect("delete credential");

    let records = db.list_credentials(None, 1000).expect("list credentials");
    assert!(records.is_empty());

    let blob_count_after = db
        .conn
        .query_row("SELECT COUNT(*) FROM blob_objects", &[], |stmt| {
            Ok(stmt.column_i64(0))
        })
        .map_err(|err| map_db_err(&err))
        .expect("count blobs after delete");
    assert_eq!(blob_count_after, 0);

    let err = db
        .delete_credential(&guard, credential_id)
        .expect_err("delete credential again should fail");
    match err {
        StorageError::CredentialIdNotFound {
            credential_id: missing_id,
        } => {
            assert_eq!(missing_id, credential_id);
        }
        _ => panic!("unexpected error: {err}"),
    }

    cleanup_vault_files(&path);
    cleanup_lock_file(&lock_path);
}

#[test]
fn test_delete_credential_cleans_up_orphaned_associated_data() {
    let path = temp_vault_path();
    let lock_path = temp_lock_path();
    let lock = StorageLock::open(&lock_path).expect("open lock");
    let guard = lock.lock().expect("lock");
    let key = Zeroizing::new([0x0Cu8; 32]);
    let mut db = VaultDb::new(&path, &key, &guard).expect("create vault");

    let credential_id = db
        .store_credential(
            &guard,
            401,
            sample_blinding_factor(),
            1,
            2000,
            b"credential-with-associated".to_vec(),
            Some(b"associated-delete".to_vec()),
            1000,
        )
        .expect("store credential");

    let associated_before = db
        .conn
        .query_row(
            "SELECT COUNT(*) FROM blob_objects WHERE blob_kind = ?1",
            params![BlobKind::AssociatedData.as_i64()],
            |stmt| Ok(stmt.column_i64(0)),
        )
        .map_err(|err| map_db_err(&err))
        .expect("count associated data before delete");
    assert_eq!(associated_before, 1);

    db.delete_credential(&guard, credential_id)
        .expect("delete credential");

    let associated_after = db
        .conn
        .query_row(
            "SELECT COUNT(*) FROM blob_objects WHERE blob_kind = ?1",
            params![BlobKind::AssociatedData.as_i64()],
            |stmt| Ok(stmt.column_i64(0)),
        )
        .map_err(|err| map_db_err(&err))
        .expect("count associated data after delete");
    assert_eq!(associated_after, 0);

    cleanup_vault_files(&path);
    cleanup_lock_file(&lock_path);
}

#[test]
fn test_danger_delete_all_credentials() {
    let path = temp_vault_path();
    let lock_path = temp_lock_path();
    let lock = StorageLock::open(&lock_path).expect("open lock");
    let guard = lock.lock().expect("lock");
    let key = Zeroizing::new([0x0Cu8; 32]);
    let mut db = VaultDb::new(&path, &key, &guard).expect("create vault");
    db.store_credential(
        &guard,
        100,
        sample_blinding_factor(),
        1,
        2000,
        b"cred-a".to_vec(),
        None,
        1000,
    )
    .expect("store credential 1");
    db.store_credential(
        &guard,
        200,
        sample_blinding_factor(),
        2,
        2000,
        b"cred-b".to_vec(),
        None,
        1000,
    )
    .expect("store credential 2");

    let deleted = db
        .danger_delete_all_credentials(&guard)
        .expect("delete all");
    assert_eq!(deleted, 2);

    let records = db.list_credentials(None, 1000).expect("list credentials");
    assert!(records.is_empty());

    let blob_count = db
        .conn
        .query_row("SELECT COUNT(*) FROM blob_objects", &[], |stmt| {
            Ok(stmt.column_i64(0))
        })
        .map_err(|err| map_db_err(&err))
        .expect("count blobs");
    assert_eq!(blob_count, 0);

    cleanup_vault_files(&path);
    cleanup_lock_file(&lock_path);
}

#[test]
fn test_danger_delete_all_credentials_empty() {
    let path = temp_vault_path();
    let lock_path = temp_lock_path();
    let lock = StorageLock::open(&lock_path).expect("open lock");
    let guard = lock.lock().expect("lock");
    let key = Zeroizing::new([0x0Du8; 32]);
    let mut db = VaultDb::new(&path, &key, &guard).expect("create vault");

    let deleted = db
        .danger_delete_all_credentials(&guard)
        .expect("delete all on empty");
    assert_eq!(deleted, 0);

    cleanup_vault_files(&path);
    cleanup_lock_file(&lock_path);
}

#[test]
fn test_vault_integrity_check() {
    let path = temp_vault_path();
    let lock_path = temp_lock_path();
    let lock = StorageLock::open(&lock_path).expect("open lock");
    let guard = lock.lock().expect("lock");
    let key = Zeroizing::new([0x0Au8; 32]);
    let db = VaultDb::new(&path, &key, &guard).expect("create vault");
    assert!(db.check_integrity().expect("integrity"));
    cleanup_vault_files(&path);
    cleanup_lock_file(&lock_path);
}

#[test]
fn test_vault_corruption_handling() {
    let path = temp_vault_path();
    let key = Zeroizing::new([0x0Bu8; 32]);
    let lock_path = temp_lock_path();
    let lock = StorageLock::open(&lock_path).expect("open lock");
    let guard = lock.lock().expect("lock");
    VaultDb::new(&path, &key, &guard).expect("create vault");
    fs::write(&path, b"corrupt").expect("corrupt file");
    let err = VaultDb::new(&path, &key, &guard).expect_err("corrupt vault");
    match err {
        StorageError::VaultDb(_) | StorageError::CorruptedVault(_) => {}
        _ => panic!("unexpected error: {err}"),
    }
    cleanup_vault_files(&path);
    cleanup_lock_file(&lock_path);
}

#[test]
fn test_store_and_get_session_seed() {
    let path = temp_vault_path();
    let lock_path = temp_lock_path();
    let lock = StorageLock::open(&lock_path).expect("open lock");
    let guard = lock.lock().expect("lock");
    let key = Zeroizing::new([0x0Eu8; 32]);
    let mut db = VaultDb::new(&path, &key, &guard).expect("create vault");

    let oprf = [0xAAu8; 32];
    let session = [0xBBu8; 32];
    let now = 1_700_000_000;

    db.store_session_seed(&guard, &oprf, &session, now)
        .expect("store session seed");

    let got_session = db
        .get_session_seed(&oprf, now)
        .expect("get session seed")
        .expect("should find seed");
    assert_eq!(got_session, session);

    cleanup_vault_files(&path);
    cleanup_lock_file(&lock_path);
}

#[test]
fn test_session_seed_created_at_floored_to_midnight() {
    let path = temp_vault_path();
    let lock_path = temp_lock_path();
    let lock = StorageLock::open(&lock_path).expect("open lock");
    let guard = lock.lock().expect("lock");
    let key = Zeroizing::new([0x0Fu8; 32]);
    let mut db = VaultDb::new(&path, &key, &guard).expect("create vault");

    let oprf = [0x01u8; 32];
    let session = [0x02u8; 32];
    // 2023-11-14 15:06:40 UTC
    let now = 1_700_000_000;
    let midnight = now - (now % 86_400);

    db.store_session_seed(&guard, &oprf, &session, now)
        .expect("store");

    let stored = db
        .conn
        .query_row(
            "SELECT created_at FROM session_seeds WHERE oprf_seed = ?1",
            params![oprf.as_slice()],
            |stmt| Ok(stmt.column_i64(0)),
        )
        .map_err(|err| map_db_err(&err))
        .expect("query created_at");

    assert_eq!(stored, i64::try_from(midnight).expect("midnight fits i64"));

    cleanup_vault_files(&path);
    cleanup_lock_file(&lock_path);
}

#[test]
fn test_session_seed_expires_after_ttl() {
    let path = temp_vault_path();
    let lock_path = temp_lock_path();
    let lock = StorageLock::open(&lock_path).expect("open lock");
    let guard = lock.lock().expect("lock");
    let key = Zeroizing::new([0x10u8; 32]);
    let mut db = VaultDb::new(&path, &key, &guard).expect("create vault");

    let oprf = [0x03u8; 32];
    let session = [0x04u8; 32];
    let now = 1_700_000_000;
    let midnight = now - (now % 86_400);

    db.store_session_seed(&guard, &oprf, &session, now)
        .expect("store");

    // Just before expiry (relative to floored created_at): still valid
    let before_expiry = midnight + 182 * 86_400 - 1;
    assert!(db.get_session_seed(&oprf, before_expiry).expect("get").is_some());

    // At expiry boundary: expired
    let at_expiry = midnight + 182 * 86_400;
    assert!(db.get_session_seed(&oprf, at_expiry).expect("get").is_none());

    cleanup_vault_files(&path);
    cleanup_lock_file(&lock_path);
}

#[test]
fn test_store_session_seed_deletes_expired() {
    let path = temp_vault_path();
    let lock_path = temp_lock_path();
    let lock = StorageLock::open(&lock_path).expect("open lock");
    let guard = lock.lock().expect("lock");
    let key = Zeroizing::new([0x11u8; 32]);
    let mut db = VaultDb::new(&path, &key, &guard).expect("create vault");

    let old_oprf = [0x05u8; 32];
    let old_session = [0x06u8; 32];
    let t0 = 1_700_000_000;
    db.store_session_seed(&guard, &old_oprf, &old_session, t0)
        .expect("store old seed");

    // Store a new seed well after the first one expired
    let new_oprf = [0x07u8; 32];
    let new_session = [0x08u8; 32];
    let t1 = t0 + 183 * 86_400;
    db.store_session_seed(&guard, &new_oprf, &new_session, t1)
        .expect("store new seed");

    // Old row should have been purged
    let count = db
        .conn
        .query_row("SELECT COUNT(*) FROM session_seeds", &[], |stmt| {
            Ok(stmt.column_i64(0))
        })
        .map_err(|err| map_db_err(&err))
        .expect("count rows");
    assert_eq!(count, 1);

    cleanup_vault_files(&path);
    cleanup_lock_file(&lock_path);
}
