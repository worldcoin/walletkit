use super::helpers::{compute_content_id, map_db_err};
use super::*;
use crate::storage::lock::StorageLock;
use std::fs;
use std::path::{Path, PathBuf};

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

fn sample_blinding_factor() -> [u8; 32] {
    [0x11u8; 32]
}

#[test]
fn test_vault_create_and_open() {
    let path = temp_vault_path();
    let key = [0x42u8; 32];
    let lock_path = temp_lock_path();
    let lock = StorageLock::open(&lock_path).expect("open lock");
    let guard = lock.lock().expect("lock");
    let db = VaultDb::new(&path, key, &guard).expect("create vault");
    drop(db);
    VaultDb::new(&path, key, &guard).expect("open vault");
    cleanup_vault_files(&path);
    cleanup_lock_file(&lock_path);
}

#[test]
fn test_vault_wrong_key_fails() {
    let path = temp_vault_path();
    let key = [0x01u8; 32];
    let lock_path = temp_lock_path();
    let lock = StorageLock::open(&lock_path).expect("open lock");
    let guard = lock.lock().expect("lock");
    VaultDb::new(&path, key, &guard).expect("create vault");
    let err = VaultDb::new(&path, [0x02u8; 32], &guard).expect_err("wrong key");
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
    let mut db = VaultDb::new(&path, [0x03u8; 32], &guard).expect("create vault");
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
    let mut db = VaultDb::new(&path, [0x04u8; 32], &guard).expect("create vault");
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
    let mut db = VaultDb::new(&path, [0x05u8; 32], &guard).expect("create vault");
    let credential_id = db
        .store_credential(
            &guard,
            10,
            CredentialStatus::Active,
            sample_blinding_factor(),
            123,
            None,
            b"credential".to_vec(),
            None,
            1000,
        )
        .expect("store credential");
    let records = db.list_credentials(None, 1000).expect("list credentials");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].credential_id, credential_id);
    assert!(records[0].associated_data.is_none());
    cleanup_vault_files(&path);
    cleanup_lock_file(&lock_path);
}

#[test]
fn test_store_credential_with_associated_data() {
    let path = temp_vault_path();
    let lock_path = temp_lock_path();
    let lock = StorageLock::open(&lock_path).expect("open lock");
    let guard = lock.lock().expect("lock");
    let mut db = VaultDb::new(&path, [0x06u8; 32], &guard).expect("create vault");
    db.store_credential(
        &guard,
        11,
        CredentialStatus::Active,
        sample_blinding_factor(),
        456,
        None,
        b"credential-2".to_vec(),
        Some(b"associated".to_vec()),
        1000,
    )
    .expect("store credential");
    let records = db.list_credentials(None, 1000).expect("list credentials");
    assert_eq!(records.len(), 1);
    assert_eq!(
        records[0].associated_data.as_deref(),
        Some(b"associated".as_slice())
    );
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
    let mut db = VaultDb::new(&path, [0x07u8; 32], &guard).expect("create vault");
    db.store_credential(
        &guard,
        12,
        CredentialStatus::Active,
        sample_blinding_factor(),
        1,
        None,
        b"same".to_vec(),
        None,
        1000,
    )
    .expect("store credential");
    db.store_credential(
        &guard,
        12,
        CredentialStatus::Active,
        sample_blinding_factor(),
        1,
        None,
        b"same".to_vec(),
        None,
        1001,
    )
    .expect("store credential");
    let count: i64 = db
        .conn
        .query_row("SELECT COUNT(*) FROM blob_objects", [], |row| row.get(0))
        .map_err(|err| map_db_err(&err))
        .expect("count blobs");
    assert_eq!(count, 1);
    cleanup_vault_files(&path);
    cleanup_lock_file(&lock_path);
}

#[test]
fn test_list_credentials_by_issuer() {
    let path = temp_vault_path();
    let lock_path = temp_lock_path();
    let lock = StorageLock::open(&lock_path).expect("open lock");
    let guard = lock.lock().expect("lock");
    let mut db = VaultDb::new(&path, [0x08u8; 32], &guard).expect("create vault");
    db.store_credential(
        &guard,
        100,
        CredentialStatus::Active,
        sample_blinding_factor(),
        1,
        None,
        b"issuer-a".to_vec(),
        None,
        1000,
    )
    .expect("store credential");
    db.store_credential(
        &guard,
        200,
        CredentialStatus::Active,
        sample_blinding_factor(),
        1,
        None,
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
fn test_list_credentials_excludes_expired() {
    let path = temp_vault_path();
    let lock_path = temp_lock_path();
    let lock = StorageLock::open(&lock_path).expect("open lock");
    let guard = lock.lock().expect("lock");
    let mut db = VaultDb::new(&path, [0x09u8; 32], &guard).expect("create vault");
    db.store_credential(
        &guard,
        300,
        CredentialStatus::Active,
        sample_blinding_factor(),
        1,
        Some(900),
        b"expired".to_vec(),
        None,
        1000,
    )
    .expect("store credential");
    let records = db.list_credentials(None, 1000).expect("list credentials");
    assert!(records.is_empty());
    cleanup_vault_files(&path);
    cleanup_lock_file(&lock_path);
}

#[test]
fn test_vault_integrity_check() {
    let path = temp_vault_path();
    let lock_path = temp_lock_path();
    let lock = StorageLock::open(&lock_path).expect("open lock");
    let guard = lock.lock().expect("lock");
    let db = VaultDb::new(&path, [0x0Au8; 32], &guard).expect("create vault");
    assert!(db.check_integrity().expect("integrity"));
    cleanup_vault_files(&path);
    cleanup_lock_file(&lock_path);
}

#[test]
fn test_vault_corruption_handling() {
    let path = temp_vault_path();
    let key = [0x0Bu8; 32];
    let lock_path = temp_lock_path();
    let lock = StorageLock::open(&lock_path).expect("open lock");
    let guard = lock.lock().expect("lock");
    VaultDb::new(&path, key, &guard).expect("create vault");
    fs::write(&path, b"corrupt").expect("corrupt file");
    let err = VaultDb::new(&path, key, &guard).expect_err("corrupt vault");
    match err {
        StorageError::VaultDb(_) | StorageError::CorruptedVault(_) => {}
        _ => panic!("unexpected error: {err}"),
    }
    cleanup_vault_files(&path);
    cleanup_lock_file(&lock_path);
}
