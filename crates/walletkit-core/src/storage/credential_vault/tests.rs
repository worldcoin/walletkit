//! Vault database unit tests.

use super::*;
use crate::storage::blob_id::compute_blob_id;
use secrecy::SecretBox;
use std::fs;
use std::path::{Path, PathBuf};
use test_case::test_case;
use uuid::Uuid;

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

fn temp_export_path() -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!("walletkit-vault-export-{}.bin", Uuid::new_v4()));
    path
}

fn sample_blinding_factor() -> Vec<u8> {
    [0x11u8; 32].to_vec()
}

#[test]
fn test_vault_create_and_open() {
    let path = temp_vault_path();
    let key = SecretBox::init_with(|| [0x42u8; 32]);
    let lock_path = temp_lock_path();
    let db = CredentialVault::new(&path, &key).expect("create vault");
    drop(db);
    CredentialVault::new(&path, &key).expect("open vault");
    cleanup_vault_files(&path);
    cleanup_lock_file(&lock_path);
}

#[test]
fn test_vault_wrong_key_fails() {
    let path = temp_vault_path();
    let key = SecretBox::init_with(|| [0x01u8; 32]);
    let lock_path = temp_lock_path();
    CredentialVault::new(&path, &key).expect("create vault");
    let wrong_key = SecretBox::init_with(|| [0x02u8; 32]);
    let err = CredentialVault::new(&path, &wrong_key).expect_err("wrong key");
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
    let key = SecretBox::init_with(|| [0x03u8; 32]);
    let db = CredentialVault::new(&path, &key).expect("create vault");
    db.init_leaf_index(42, 100).expect("init leaf index");
    db.init_leaf_index(42, 200).expect("init leaf index again");
    cleanup_vault_files(&path);
    cleanup_lock_file(&lock_path);
}

#[test]
fn test_leaf_index_immutable() {
    let path = temp_vault_path();
    let lock_path = temp_lock_path();
    let key = SecretBox::init_with(|| [0x04u8; 32]);
    let db = CredentialVault::new(&path, &key).expect("create vault");
    db.init_leaf_index(7, 100).expect("init leaf index");
    let err = db.init_leaf_index(8, 200).expect_err("mismatch");
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
    let key = SecretBox::init_with(|| [0x05u8; 32]);
    let db = CredentialVault::new(&path, &key).expect("create vault");
    let credential_id = db
        .store_credential(
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
    let key = SecretBox::init_with(|| [0x06u8; 32]);
    let db = CredentialVault::new(&path, &key).expect("create vault");
    db.store_credential(
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
fn test_content_id_deduplication() {
    let path = temp_vault_path();
    let lock_path = temp_lock_path();
    let key = SecretBox::init_with(|| [0x07u8; 32]);
    let db = CredentialVault::new(&path, &key).expect("create vault");
    let first_id = db
        .store_credential(
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
        .vault
        .connection()
        .query_row("SELECT COUNT(*) FROM blob_objects", &[], |stmt| {
            Ok(stmt.column_i64(0))
        })
        .map_err(|err| map_db_err(&err))
        .expect("count blobs");
    assert_eq!(count, 1);

    db.delete_credential(first_id)
        .expect("delete first credential");

    let count_after_first_delete = db
        .vault
        .connection()
        .query_row("SELECT COUNT(*) FROM blob_objects", &[], |stmt| {
            Ok(stmt.column_i64(0))
        })
        .map_err(|err| map_db_err(&err))
        .expect("count blobs after first delete");
    assert_eq!(count_after_first_delete, 1);

    db.delete_credential(second_id)
        .expect("delete second credential");

    let count_after_second_delete = db
        .vault
        .connection()
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
    let key = SecretBox::init_with(|| [0x08u8; 32]);
    let db = CredentialVault::new(&path, &key).expect("create vault");
    db.store_credential(
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
    let key = SecretBox::init_with(|| [0x09u8; 32]);
    let db = CredentialVault::new(&path, &key).expect("create vault");
    db.store_credential(
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
    let key = SecretBox::init_with(|| [0x0Au8; 32]);
    let db = CredentialVault::new(&path, &key).expect("create vault");
    db.store_credential(
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
    let key = SecretBox::init_with(|| [0x0Bu8; 32]);
    let db = CredentialVault::new(&path, &key).expect("create vault");
    let credential_id = db
        .store_credential(
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
        .vault
        .connection()
        .query_row("SELECT COUNT(*) FROM blob_objects", &[], |stmt| {
            Ok(stmt.column_i64(0))
        })
        .map_err(|err| map_db_err(&err))
        .expect("count blobs before delete");
    assert_eq!(blob_count_before, 1);

    db.delete_credential(credential_id)
        .expect("delete credential");

    let records = db.list_credentials(None, 1000).expect("list credentials");
    assert!(records.is_empty());

    let blob_count_after = db
        .vault
        .connection()
        .query_row("SELECT COUNT(*) FROM blob_objects", &[], |stmt| {
            Ok(stmt.column_i64(0))
        })
        .map_err(|err| map_db_err(&err))
        .expect("count blobs after delete");
    assert_eq!(blob_count_after, 0);

    let err = db
        .delete_credential(credential_id)
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
    let key = SecretBox::init_with(|| [0x0Cu8; 32]);
    let db = CredentialVault::new(&path, &key).expect("create vault");

    let credential_id = db
        .store_credential(
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
        .vault
        .connection()
        .query_row(
            "SELECT COUNT(*) FROM blob_objects WHERE blob_kind = ?1",
            params![BlobKind::AssociatedData.as_i64()],
            |stmt| Ok(stmt.column_i64(0)),
        )
        .map_err(|err| map_db_err(&err))
        .expect("count associated data before delete");
    assert_eq!(associated_before, 1);

    db.delete_credential(credential_id)
        .expect("delete credential");

    let associated_after = db
        .vault
        .connection()
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
    let key = SecretBox::init_with(|| [0x0Cu8; 32]);
    let db = CredentialVault::new(&path, &key).expect("create vault");
    db.store_credential(
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
        200,
        sample_blinding_factor(),
        2,
        2000,
        b"cred-b".to_vec(),
        None,
        1000,
    )
    .expect("store credential 2");

    let deleted = db.danger_delete_all_credentials().expect("delete all");
    assert_eq!(deleted, 2);

    let records = db.list_credentials(None, 1000).expect("list credentials");
    assert!(records.is_empty());

    let blob_count = db
        .vault
        .connection()
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
    let key = SecretBox::init_with(|| [0x0Du8; 32]);
    let db = CredentialVault::new(&path, &key).expect("create vault");

    let deleted = db
        .danger_delete_all_credentials()
        .expect("delete all on empty");
    assert_eq!(deleted, 0);

    cleanup_vault_files(&path);
    cleanup_lock_file(&lock_path);
}

#[test]
fn test_vault_integrity_check() {
    let path = temp_vault_path();
    let lock_path = temp_lock_path();
    let key = SecretBox::init_with(|| [0x0Au8; 32]);
    let db = CredentialVault::new(&path, &key).expect("create vault");
    assert!(db.check_integrity().expect("integrity"));
    cleanup_vault_files(&path);
    cleanup_lock_file(&lock_path);
}

#[test]
fn test_list_credentials_round_trips_genesis_issued_at() {
    let path = temp_vault_path();
    let lock_path = temp_lock_path();
    let key = SecretBox::init_with(|| [0x0Cu8; 32]);
    let db = CredentialVault::new(&path, &key).expect("create vault");

    let genesis_issued_at = 123_456_789u64;
    db.store_credential(
        100,
        sample_blinding_factor(),
        genesis_issued_at,
        999_999,
        b"blob".to_vec(),
        None,
        1000,
    )
    .expect("store credential");

    let records = db.list_credentials(None, 1000).expect("list credentials");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].genesis_issued_at, genesis_issued_at);
    cleanup_vault_files(&path);
    cleanup_lock_file(&lock_path);
}

/// Hosts record a checksum of an export, delete the plaintext copy so it does not sit on disk, and
/// re-derive it later to prove the backup they hold still matches. That only holds if exporting an
/// unchanged vault is byte-identical.
#[test]
fn test_plaintext_export_is_byte_identical_for_an_unchanged_vault() {
    let path = temp_vault_path();
    let lock_path = temp_lock_path();
    let key = SecretBox::init_with(|| [0x0Du8; 32]);
    let db = CredentialVault::new(&path, &key).expect("create vault");
    db.store_credential(
        10,
        sample_blinding_factor(),
        123,
        2000,
        b"credential".to_vec(),
        None,
        1000,
    )
    .expect("store credential");

    let first = temp_export_path();
    let second = temp_export_path();
    db.export_plaintext(&first).expect("first export");
    db.export_plaintext(&second).expect("second export");

    assert_eq!(
        fs::read(&first).expect("read first export"),
        fs::read(&second).expect("read second export"),
        "re-exporting an unchanged vault produced different bytes",
    );

    let _ = fs::remove_file(&first);
    let _ = fs::remove_file(&second);
    cleanup_vault_files(&path);
    cleanup_lock_file(&lock_path);
}

/// The re-derived export runs against a vault that was reopened and had its leaf index initialized
/// again with the current time, unlike the export that produced the recorded checksum. Neither the
/// reopen nor the re-init may change the exported bytes.
#[test]
fn test_plaintext_export_is_unaffected_by_reopening_and_reinitializing_the_leaf_index()
{
    let path = temp_vault_path();
    let lock_path = temp_lock_path();
    let key = SecretBox::init_with(|| [0x0Eu8; 32]);
    let registered = temp_export_path();
    let regenerated = temp_export_path();

    let db = CredentialVault::new(&path, &key).expect("create vault");
    db.init_leaf_index(7, 1000).expect("init leaf index");
    db.store_credential(
        10,
        sample_blinding_factor(),
        123,
        2000,
        b"credential".to_vec(),
        None,
        1000,
    )
    .expect("store credential");
    db.export_plaintext(&registered).expect("registered export");
    drop(db);

    let db = CredentialVault::new(&path, &key).expect("reopen vault");
    db.init_leaf_index(7, 9999).expect("re-init leaf index");
    db.export_plaintext(&regenerated)
        .expect("regenerated export");

    assert_eq!(
        fs::read(&registered).expect("read registered export"),
        fs::read(&regenerated).expect("read regenerated export"),
        "re-exporting after a reopen and a re-init produced different bytes",
    );

    let _ = fs::remove_file(&registered);
    let _ = fs::remove_file(&regenerated);
    cleanup_vault_files(&path);
    cleanup_lock_file(&lock_path);
}

/// Control for the two tests above: the export has to track the vault's contents, otherwise
/// byte-identical exports would prove nothing.
#[test]
fn test_plaintext_export_changes_when_a_credential_is_stored() {
    let path = temp_vault_path();
    let lock_path = temp_lock_path();
    let key = SecretBox::init_with(|| [0x0Fu8; 32]);
    let db = CredentialVault::new(&path, &key).expect("create vault");
    let before = temp_export_path();
    let after = temp_export_path();

    db.export_plaintext(&before).expect("export before");
    db.store_credential(
        10,
        sample_blinding_factor(),
        123,
        2000,
        b"credential".to_vec(),
        None,
        1000,
    )
    .expect("store credential");
    db.export_plaintext(&after).expect("export after");

    assert_ne!(
        fs::read(&before).expect("read export before"),
        fs::read(&after).expect("read export after"),
        "storing a credential did not change the exported bytes",
    );

    let _ = fs::remove_file(&before);
    let _ = fs::remove_file(&after);
    cleanup_vault_files(&path);
    cleanup_lock_file(&lock_path);
}

#[test]
fn test_vault_corruption_handling() {
    let path = temp_vault_path();
    let key = SecretBox::init_with(|| [0x0Bu8; 32]);
    let lock_path = temp_lock_path();
    CredentialVault::new(&path, &key).expect("create vault");
    fs::write(&path, b"corrupt").expect("corrupt file");
    let err = CredentialVault::new(&path, &key).expect_err("corrupt vault");
    match err {
        StorageError::VaultDb(_) | StorageError::CorruptedVault(_) => {}
        _ => panic!("unexpected error: {err}"),
    }
    cleanup_vault_files(&path);
    cleanup_lock_file(&lock_path);
}

fn store_sample_credential(db: &CredentialVault, issuer_schema_id: u64) -> u64 {
    db.store_credential(
        issuer_schema_id,
        sample_blinding_factor(),
        1,
        2000,
        format!("credential-{issuer_schema_id}").into_bytes(),
        None,
        1000,
    )
    .expect("store credential")
}

fn count_blob_refs(db: &CredentialVault) -> i64 {
    db.vault
        .connection()
        .query_row("SELECT COUNT(*) FROM credential_blob_refs", &[], |stmt| {
            Ok(stmt.column_i64(0))
        })
        .expect("count blob refs")
}

#[test]
fn test_credential_blobs_round_trip_in_byte_order() {
    let path = temp_vault_path();
    let key = SecretBox::init_with(|| [0x0Cu8; 32]);
    let db = CredentialVault::new(&path, &key).expect("create vault");
    let orb = store_sample_credential(&db, 100);
    let face = store_sample_credential(&db, 200);
    let orb_pcp = compute_blob_id(b"orb pcp");
    let orb_pcp_v2 = compute_blob_id(b"orb pcp v2");
    let face_pcp = compute_blob_id(b"face pcp");

    assert!(db
        .set_credential_blobs(orb, &[orb_pcp, orb_pcp_v2, orb_pcp], 1000)
        .expect("link orb"));
    assert!(db
        .set_credential_blobs(face, &[face_pcp], 1000)
        .expect("link face"));

    let mut expected = vec![orb_pcp, orb_pcp_v2];
    expected.sort();
    assert_eq!(db.credential_blobs(orb).expect("orb blobs"), expected);
    assert_eq!(db.credential_blobs(face).expect("face blobs"), [face_pcp]);
    assert!(db.credential_blobs(999).expect("unknown").is_empty());
    cleanup_vault_files(&path);
}

#[test]
fn test_set_credential_blobs_replaces_the_set() {
    let path = temp_vault_path();
    let key = SecretBox::init_with(|| [0x0Du8; 32]);
    let db = CredentialVault::new(&path, &key).expect("create vault");
    let credential_id = store_sample_credential(&db, 100);
    let kept = compute_blob_id(b"kept pcp");
    let dropped = compute_blob_id(b"dropped pcp");
    let added = compute_blob_id(b"added pcp");

    db.set_credential_blobs(credential_id, &[kept, dropped], 1000)
        .expect("first link");
    assert!(!db
        .set_credential_blobs(credential_id, &[dropped, kept], 2000)
        .expect("same set"));
    assert!(db
        .set_credential_blobs(credential_id, &[kept, added], 3000)
        .expect("replace"));

    let mut expected = vec![kept, added];
    expected.sort();
    assert_eq!(db.credential_blobs(credential_id).expect("blobs"), expected);
    let kept_created_at = db
        .vault
        .connection()
        .query_row(
            "SELECT created_at FROM credential_blob_refs
             WHERE credential_id = ?1 AND blob_id = ?2",
            params![
                i64::try_from(credential_id).unwrap(),
                kept.as_bytes().as_slice()
            ],
            |stmt| Ok(stmt.column_i64(0)),
        )
        .expect("kept created_at");
    assert_eq!(kept_created_at, 1000);

    assert!(db
        .set_credential_blobs(credential_id, &[], 4000)
        .expect("clear"));
    assert!(db
        .credential_blobs(credential_id)
        .expect("blobs")
        .is_empty());
    cleanup_vault_files(&path);
}

#[test_case(&[] ; "empty set")]
#[test_case(&[b"orb pcp"] ; "one blob")]
fn test_set_credential_blobs_rejects_unknown_credential(plaintexts: &[&[u8]]) {
    let path = temp_vault_path();
    let key = SecretBox::init_with(|| [0x0Eu8; 32]);
    let db = CredentialVault::new(&path, &key).expect("create vault");
    let blob_ids: Vec<BlobId> = plaintexts.iter().map(|p| compute_blob_id(p)).collect();

    let err = db
        .set_credential_blobs(7, &blob_ids, 1000)
        .expect_err("unknown credential");
    assert!(matches!(
        err,
        StorageError::CredentialIdNotFound { credential_id: 7 }
    ));
    assert_eq!(count_blob_refs(&db), 0);
    cleanup_vault_files(&path);
}

#[test]
fn test_deleting_a_credential_removes_its_blob_refs() {
    let path = temp_vault_path();
    let key = SecretBox::init_with(|| [0x0Fu8; 32]);
    let db = CredentialVault::new(&path, &key).expect("create vault");
    let deleted = store_sample_credential(&db, 100);
    let kept = store_sample_credential(&db, 200);
    let shared_pcp = compute_blob_id(b"shared pcp");
    db.set_credential_blobs(deleted, &[shared_pcp, compute_blob_id(b"orb pcp")], 1000)
        .expect("link deleted");
    db.set_credential_blobs(kept, &[shared_pcp], 1000)
        .expect("link kept");

    db.delete_credential(deleted).expect("delete credential");

    assert!(db.credential_blobs(deleted).expect("deleted").is_empty());
    assert_eq!(db.credential_blobs(kept).expect("kept"), [shared_pcp]);
    assert_eq!(count_blob_refs(&db), 1);

    db.danger_delete_all_credentials().expect("delete all");
    assert_eq!(count_blob_refs(&db), 0);
    cleanup_vault_files(&path);
}

#[test]
fn test_vault_without_blob_refs_table_gains_it_on_open() {
    let path = temp_vault_path();
    let key = SecretBox::init_with(|| [0x10u8; 32]);
    let credential_id = {
        let db = CredentialVault::new(&path, &key).expect("create vault");
        db.init_leaf_index(42, 1000).expect("init leaf index");
        let credential_id = store_sample_credential(&db, 100);
        db.vault
            .connection()
            .execute_batch("DROP TABLE credential_blob_refs;")
            .expect("drop table to mimic an older vault");
        credential_id
    };

    let db = CredentialVault::new(&path, &key).expect("reopen vault");
    db.init_leaf_index(42, 2000).expect("leaf index unchanged");
    let index_count = db
        .vault
        .connection()
        .query_row(
            "SELECT COUNT(*) FROM sqlite_schema
             WHERE type = 'index' AND name = 'idx_credential_blob_refs_blob_id'",
            &[],
            |stmt| Ok(stmt.column_i64(0)),
        )
        .expect("index lookup");
    assert_eq!(index_count, 1);
    let orb_pcp = compute_blob_id(b"orb pcp");
    db.set_credential_blobs(credential_id, &[orb_pcp], 2000)
        .expect("link on upgraded vault");
    assert_eq!(
        db.credential_blobs(credential_id).expect("blobs"),
        [orb_pcp]
    );
    cleanup_vault_files(&path);
}

#[test_case(Value::Blob(vec![0; 31]) ; "short blob")]
#[test_case(Value::Text("a".repeat(32)) ; "text of 32 chars")]
fn test_blob_refs_reject_malformed_ids(blob_id: Value) {
    let path = temp_vault_path();
    let key = SecretBox::init_with(|| [0x12u8; 32]);
    let db = CredentialVault::new(&path, &key).expect("create vault");
    let credential_id = store_sample_credential(&db, 100);

    db.vault
        .connection()
        .execute(
            "INSERT INTO credential_blob_refs (credential_id, blob_id, created_at)
             VALUES (?1, ?2, 1000)",
            &[
                Value::Integer(i64::try_from(credential_id).unwrap()),
                blob_id,
            ],
        )
        .expect_err("CHECK constraint");
    cleanup_vault_files(&path);
}

#[test]
fn test_plaintext_restore_keeps_blob_refs() {
    let source_path = temp_vault_path();
    let restore_path = temp_vault_path();
    let export_path = temp_export_path();
    let key = SecretBox::init_with(|| [0x13u8; 32]);
    let source = CredentialVault::new(&source_path, &key).expect("create source");
    let orb = store_sample_credential(&source, 100);
    let face = store_sample_credential(&source, 200);
    let orb_pcp = compute_blob_id(b"orb pcp");
    let face_pcp = compute_blob_id(b"face pcp");
    source
        .set_credential_blobs(orb, &[orb_pcp], 1000)
        .expect("link orb");
    source
        .set_credential_blobs(face, &[face_pcp], 1000)
        .expect("link face");
    source.export_plaintext(&export_path).expect("export");

    let restored = CredentialVault::new(&restore_path, &key).expect("create restore");
    restored.import_plaintext(&export_path).expect("import");

    assert_eq!(restored.credential_blobs(orb).expect("orb"), [orb_pcp]);
    assert_eq!(restored.credential_blobs(face).expect("face"), [face_pcp]);
    let _ = fs::remove_file(&export_path);
    cleanup_vault_files(&source_path);
    cleanup_vault_files(&restore_path);
}

#[test]
fn test_plaintext_restore_of_backup_without_blob_refs_table() {
    let source_path = temp_vault_path();
    let restore_path = temp_vault_path();
    let export_path = temp_export_path();
    let key = SecretBox::init_with(|| [0x14u8; 32]);
    let source = CredentialVault::new(&source_path, &key).expect("create source");
    let credential_id = store_sample_credential(&source, 100);
    source.export_plaintext(&export_path).expect("export");
    walletkit_sqlite::Connection::open(&export_path, false)
        .expect("open backup")
        .execute_batch("DROP TABLE credential_blob_refs;")
        .expect("drop table to mimic an older backup");

    let restored = CredentialVault::new(&restore_path, &key).expect("create restore");
    restored.import_plaintext(&export_path).expect("import");

    assert_eq!(
        restored.list_credentials(None, 1000).expect("list").len(),
        1
    );
    assert!(restored
        .credential_blobs(credential_id)
        .expect("blobs")
        .is_empty());
    let orb_pcp = compute_blob_id(b"orb pcp");
    restored
        .set_credential_blobs(credential_id, &[orb_pcp], 2000)
        .expect("link after restore");
    assert_eq!(
        restored.credential_blobs(credential_id).expect("blobs"),
        [orb_pcp]
    );
    let _ = fs::remove_file(&export_path);
    cleanup_vault_files(&source_path);
    cleanup_vault_files(&restore_path);
}
