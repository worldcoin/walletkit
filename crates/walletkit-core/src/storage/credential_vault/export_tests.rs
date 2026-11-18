use super::*;
use crate::storage::blob_id::compute_blob_id;
use secrecy::SecretBox;
use tempfile::TempDir;
use test_case::test_case;
use walletkit_sqlite::Connection;

struct Fixture {
    dir: TempDir,
    source: CredentialVault,
    receiver: CredentialVault,
}

impl Fixture {
    fn new() -> Self {
        let dir = TempDir::new().unwrap();
        let key = SecretBox::init_with(|| [42; 32]);
        let source = CredentialVault::new(&dir.path().join("source.db"), &key).unwrap();
        let receiver =
            CredentialVault::new(&dir.path().join("receiver.db"), &key).unwrap();
        Self {
            dir,
            source,
            receiver,
        }
    }

    fn export(&self, ids: Option<&[u64]>) -> (Connection, Vec<BlobId>) {
        let path = self.dir.path().join("export.db");
        let missing = self.source.export_selected_plaintext(&path, ids).unwrap();
        (Connection::open(path, false).unwrap(), missing)
    }

    fn bytes(&self) -> Vec<u8> {
        std::fs::read(self.dir.path().join("export.db")).unwrap()
    }
}

fn credential(vault: &CredentialVault, schema: u64, bytes: &[u8]) -> u64 {
    vault
        .store_credential(
            schema,
            vec![7; 32],
            1000,
            9999,
            bytes.to_vec(),
            Some(vec![9]),
            1000,
        )
        .unwrap()
}

fn linked_blob(
    vault: &CredentialVault,
    credential_id: u64,
    bytes: &[u8],
    data: &[u8],
) -> BlobId {
    let (id, _) = vault
        .put_blob("oxide.orb", data, Some("local/pcp.dat"), 1000)
        .unwrap();
    vault
        .add_credential_blobs(credential_id, bytes, &[id], 1000)
        .unwrap();
    id
}

fn count(conn: &Connection, table: &str) -> i64 {
    conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), &[], |row| {
        Ok(row.column_i64(0))
    })
    .unwrap()
}

#[test]
fn full_and_selected_exports_include_only_reachable_content_once() {
    let f = Fixture::new();
    let a = credential(&f.source, 100, b"a");
    let b = credential(&f.source, 200, b"b");
    let shared = linked_blob(&f.source, a, b"a", b"shared pcp");
    linked_blob(&f.source, b, b"b", b"shared pcp");
    let only_b = linked_blob(&f.source, b, b"b", b"b pcp");
    f.source
        .put_blob("oxide.face", b"unlinked pcp", None, 1000)
        .unwrap();
    let revision = f.source.get_blob(&shared).unwrap().unwrap().record.revision;
    f.source
        .update_blob_metadata(&shared, Some(b"private metadata"), revision, 2000)
        .unwrap();
    let (all, missing) = f.export(None);
    assert!(missing.is_empty());
    assert_eq!(count(&all, "credential_records"), 2);
    assert_eq!(count(&all, "blob_objects"), 3);
    assert_eq!(count(&all, "credential_blob_refs"), 3);
    assert_eq!(count(&all, "blobs"), 2);
    assert_eq!(
        count(&all, "sqlite_schema WHERE name = 'legacy_blob_paths'"),
        0
    );
    assert_eq!(
        count(
            &all,
            "pragma_table_info('blobs') WHERE name IN ('metadata', 'revision')"
        ),
        0
    );
    drop(all);
    let (selected, missing) = f.export(Some(&[a, a]));
    assert!(missing.is_empty());
    assert_eq!(count(&selected, "credential_records"), 1);
    assert_eq!(count(&selected, "blob_objects"), 2);
    assert_eq!(count(&selected, "credential_blob_refs"), 1);
    assert_eq!(count(&selected, "blobs"), 1);
    drop(selected);
    f.receiver.restore_plaintext_bytes(&f.bytes()).unwrap();
    assert_eq!(
        f.receiver.get_blob(&shared).unwrap().unwrap().data,
        b"shared pcp"
    );
    assert!(f.receiver.get_blob(&only_b).unwrap().is_none());
    assert!(f
        .receiver
        .list_credentials(Some(200), 1000)
        .unwrap()
        .is_empty());
    let (both, _) = f.export(Some(&[b, a, b]));
    assert_eq!(count(&both, "blobs"), 2);
    assert_eq!(count(&both, "credential_blob_refs"), 3);
}

#[test]
fn empty_and_unknown_selections_error_and_allow_retry() {
    let f = Fixture::new();
    let a = credential(&f.source, 100, b"a");
    let path = f.dir.path().join("export.db");
    let error = f
        .source
        .export_selected_plaintext(&path, Some(&[]))
        .unwrap_err();
    assert!(matches!(error, StorageError::InvalidInput(_)));
    let error = f
        .source
        .export_selected_plaintext(&path, Some(&[a, 999, 888, u64::MAX]))
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        format!(
            "invalid input: unknown credential ids: [888, 999, {}]",
            u64::MAX
        )
    );
    let (backup, _) = f.export(Some(&[a]));
    assert_eq!(count(&backup, "credential_records"), 1);
}

#[test]
fn missing_linked_blobs_are_distinct_and_scoped_to_the_selection() {
    let f = Fixture::new();
    let a = credential(&f.source, 100, b"a");
    let b = credential(&f.source, 200, b"b");
    let missing = compute_blob_id(b"missing pcp");
    let other = compute_blob_id(b"other missing pcp");
    f.source
        .add_credential_blobs(a, b"a", &[missing], 1000)
        .unwrap();
    f.source
        .add_credential_blobs(b, b"b", &[missing, other], 1000)
        .unwrap();
    let (selected, ids) = f.export(Some(&[a]));
    assert_eq!(ids, [missing]);
    assert_eq!(count(&selected, "blobs"), 0);
    drop(selected);
    let (all, ids) = f.export(None);
    let mut expected = vec![missing, other];
    expected.sort();
    assert_eq!(ids, expected);
    assert_eq!(count(&all, "credential_blob_refs"), 3);
}

#[test_case(false ; "merge")]
#[test_case(true ; "restore with local unlinked blob")]
fn roundtrip_restores_blobs_and_remaps_links_without_local_metadata(restore: bool) {
    let f = Fixture::new();
    // Force the source's local id to differ from the restored id.
    let deleted = credential(&f.source, 1, b"deleted");
    let source_id = credential(&f.source, 100, b"credential");
    f.source.delete_credential(deleted).unwrap();
    let id = linked_blob(&f.source, source_id, b"credential", b"pcp");
    let revision = f.source.get_blob(&id).unwrap().unwrap().record.revision;
    f.source
        .update_blob_metadata(&id, Some(b"private metadata"), revision, 2000)
        .unwrap();
    let (local_id, _) = f
        .receiver
        .put_blob("local", b"local unlinked", Some("keep.dat"), 500)
        .unwrap();
    let (backup, _) = f.export(None);
    backup
        .execute_batch(
            "ALTER TABLE blobs ADD COLUMN metadata BLOB;
         ALTER TABLE blobs ADD COLUMN revision INTEGER;
         UPDATE blobs SET metadata = X'FF', revision = -1",
        )
        .unwrap();
    drop(backup);
    if restore {
        f.receiver.restore_plaintext_bytes(&f.bytes()).unwrap();
    } else {
        assert_eq!(
            f.receiver.merge_plaintext_bytes(&f.bytes()).unwrap().blobs,
            1
        );
    }
    let stored = f.receiver.get_blob(&id).unwrap().unwrap();
    assert_eq!(*stored.record.blob_id, compute_blob_id(&stored.data));
    assert_eq!(stored.record.kind, "oxide.orb");
    assert_eq!(stored.record.metadata, None);
    assert!(stored.record.revision > 0);
    assert_eq!(
        (stored.record.created_at, stored.record.updated_at),
        (1000, 2000)
    );
    let restored_id =
        f.receiver.list_credentials(Some(100), 1000).unwrap()[0].credential_id;
    assert_ne!(source_id, restored_id);
    assert_eq!(f.receiver.credential_blobs(restored_id).unwrap(), [id]);
    assert!(f.receiver.get_blob(&local_id).unwrap().is_some());
    assert_eq!(f.receiver.list_legacy_blob_paths("").unwrap(), ["keep.dat"]);
}

#[test]
fn merge_preserves_an_existing_blobs_kind_metadata_revision_and_timestamps() {
    let f = Fixture::new();
    let a = credential(&f.source, 100, b"a");
    let id = linked_blob(&f.source, a, b"a", b"pcp");
    f.receiver
        .put_blob("local", b"pcp", Some("keep.dat"), 500)
        .unwrap();
    let revision = f.receiver.get_blob(&id).unwrap().unwrap().record.revision;
    f.receiver
        .update_blob_metadata(&id, Some(b"local metadata"), revision, 600)
        .unwrap();
    let before = f.receiver.get_blob(&id).unwrap().unwrap();
    drop(f.export(None));
    let outcome = f.receiver.merge_plaintext_bytes(&f.bytes()).unwrap();
    assert_eq!(
        (outcome.records, outcome.blob_refs, outcome.blobs),
        (1, 1, 0)
    );
    assert_eq!(f.receiver.get_blob(&id).unwrap().unwrap(), before);
    assert_eq!(
        f.receiver.merge_plaintext_bytes(&f.bytes()).unwrap().blobs,
        0
    );
}

#[test_case(false ; "merge")]
#[test_case(true ; "restore")]
fn tampered_data_rolls_back_all_tables_even_if_the_blob_already_exists(restore: bool) {
    let f = Fixture::new();
    let a = credential(&f.source, 100, b"a");
    let id = linked_blob(&f.source, a, b"a", b"pcp");
    linked_blob(&f.source, a, b"a", b"another pcp");
    f.receiver.put_blob("local", b"pcp", None, 500).unwrap();
    let before = f.receiver.get_blob(&id).unwrap().unwrap();
    let (backup, _) = f.export(None);
    backup.execute_batch("UPDATE blobs SET data = X'00' WHERE blob_id = (SELECT MAX(blob_id) FROM blobs)").unwrap();
    drop(backup);
    let bytes = f.bytes();
    let error = if restore {
        f.receiver.restore_plaintext_bytes(&bytes).unwrap_err()
    } else {
        f.receiver.merge_plaintext_bytes(&bytes).unwrap_err()
    };
    assert!(error
        .to_string()
        .contains("invalid credential backup contents"));
    let conn = f.receiver.vault.connection();
    for table in BACKUP_TABLES {
        assert_eq!(count(conn, table), 0);
    }
    assert_eq!(count(conn, "blobs"), 1);
    assert_eq!(f.receiver.get_blob(&id).unwrap().unwrap(), before);
    drop(f.export(None));
    f.receiver.restore_plaintext_bytes(&f.bytes()).unwrap();
    assert_eq!(count(conn, "blobs"), 2);
}

#[test_case("blob_id = X'00'" ; "short id")]
#[test_case("blob_id = NULL" ; "null id")]
#[test_case("kind = X'00'" ; "non-text kind")]
#[test_case("data = 'text'" ; "non-blob data")]
#[test_case("created_at = -1" ; "negative created time")]
#[test_case("updated_at = 'text'" ; "non-integer updated time")]
fn malformed_blob_rows_are_rejected(update: &str) {
    let f = Fixture::new();
    let a = credential(&f.source, 100, b"a");
    linked_blob(&f.source, a, b"a", b"pcp");
    let (backup, _) = f.export(None);
    backup
        .execute_batch(&format!("UPDATE blobs SET {update}"))
        .unwrap();
    drop(backup);
    assert!(f.receiver.merge_plaintext_bytes(&f.bytes()).is_err());
    for table in [
        "credential_records",
        "blob_objects",
        "credential_blob_refs",
        "blobs",
    ] {
        assert_eq!(count(f.receiver.vault.connection(), table), 0);
    }
}

#[test]
fn older_sender_without_a_blobs_table_still_restores() {
    let f = Fixture::new();
    let a = credential(&f.source, 100, b"a");
    let id = linked_blob(&f.source, a, b"a", b"pcp");
    let (backup, _) = f.export(None);
    backup.execute_batch("DROP TABLE blobs").unwrap();
    drop(backup);
    let bytes = f.bytes();
    f.receiver.restore_plaintext_bytes(&bytes).unwrap();
    assert_eq!(f.receiver.credential_blobs(1).unwrap(), [id]);
    assert!(f.receiver.get_blob(&id).unwrap().is_none());
    assert_eq!(f.receiver.merge_plaintext_bytes(&bytes).unwrap().records, 0);
}

#[test]
fn released_v0_30_0_importer_ignores_the_extra_blobs_table() {
    let f = Fixture::new();
    let a = credential(&f.source, 100, b"a");
    let id = linked_blob(&f.source, a, b"a", b"pcp");
    drop(f.export(None));
    let bytes = f.bytes();
    assert_eq!(f.receiver.merge_plaintext_bytes_v0_30_0(&bytes).unwrap(), 1);
    assert_eq!(f.receiver.merge_plaintext_bytes_v0_30_0(&bytes).unwrap(), 0);
    assert_eq!(f.receiver.fetch_credential_by_id(1).unwrap().unwrap(), b"a");
    assert!(f.receiver.get_blob(&id).unwrap().is_none());
    assert!(f.receiver.credential_blobs(1).unwrap().is_empty());
    let outcome = f.receiver.merge_plaintext_bytes(&bytes).unwrap();
    assert_eq!(
        (outcome.records, outcome.blob_refs, outcome.blobs),
        (0, 1, 1)
    );
}
