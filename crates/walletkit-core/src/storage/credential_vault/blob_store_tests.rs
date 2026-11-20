use super::*;
use crate::storage::blob_id::compute_blob_id;
use secrecy::SecretBox;
use tempfile::TempDir;
use test_case::test_case;
use walletkit_db::{blobs, Vault};
use walletkit_sqlite::Connection;

const RELEASED_SCHEMA: &str = include_str!("fixtures/vault-v0.30.0.sql");

const PLAINTEXT: &[u8] = b"hello pcp";
const PATH: &str = "face_pcp/face-pcp-v1.tar.gz";

struct Fixture {
    dir: TempDir,
    db: CredentialVault,
    key: SecretBox<[u8; 32]>,
}

impl Fixture {
    fn new() -> Self {
        let dir = TempDir::new().unwrap();
        let key = SecretBox::init_with(|| [0x42; 32]);
        let db = CredentialVault::new(&dir.path().join("account.vault.sqlite"), &key)
            .unwrap();
        db.init_leaf_index(42, 1000).unwrap();
        Self { dir, db, key }
    }

    fn put(&self, path: Option<&str>) -> BlobId {
        self.db
            .put_blob("oxide.face", PLAINTEXT, path, 1000)
            .unwrap()
            .0
    }
}

#[test_case(b"", "dbc45c9a56ec1cfe89c45c6bfbc3bffe9d574fcfbdb28f24442b0f6a698f529f" ; "empty")]
#[test_case(b"hello pcp", "733ae41c33b82d2d18eba3b18f289f649f49a386362441f9bff74c613764b00f" ; "hello pcp")]
fn put_computes_the_shared_blob_id_vectors(data: &[u8], expected: &str) {
    let f = Fixture::new();
    let (id, linked) = f.db.put_blob("oxide.face", data, None, 1000).unwrap();
    assert!(!linked);
    assert_eq!(id.to_hex_string(), expected);
    assert_eq!(id, *crate::storage::blob_id(data.to_vec()));
    let stored = f.db.get_blob(&id).unwrap().unwrap();
    assert_eq!(*stored.record.blob_id, id);
    assert!(stored.record.revision > 0);
    assert_eq!(stored.data, data);
}

#[test]
fn aliases_move_without_deleting_content_or_other_aliases() {
    let f = Fixture::new();
    let first = f.put(Some(PATH));
    let initial = f.db.get_blob(&first).unwrap().unwrap().record.revision;
    assert_eq!(
        f.db.put_blob("oxide.face", PLAINTEXT, Some("scoped/face.tar.gz"), 1001)
            .unwrap()
            .0,
        first
    );
    assert_eq!(f.db.list_blobs(None).unwrap().len(), 1);
    assert_eq!(
        f.db.get_blob(&first).unwrap().unwrap().record.revision,
        initial + 1
    );
    let second =
        f.db.put_blob("oxide.face", b"replacement face pcp", Some(PATH), 1002)
            .unwrap()
            .0;
    assert_ne!(first, second);
    assert_eq!(f.db.list_blobs(None).unwrap().len(), 2);

    assert_eq!(
        *f.db
            .get_blob_by_legacy_path(PATH)
            .unwrap()
            .unwrap()
            .record
            .blob_id,
        second
    );
    assert_eq!(
        *f.db
            .get_blob_by_legacy_path("scoped/face.tar.gz")
            .unwrap()
            .unwrap()
            .record
            .blob_id,
        first
    );
    assert_eq!(f.db.get_blob(&first).unwrap().unwrap().data, PLAINTEXT);
    assert!(f.db.delete_legacy_blob_path("scoped/face.tar.gz").unwrap());
    assert!(!f.db.delete_legacy_blob_path("scoped/face.tar.gz").unwrap());
    assert!(f.db.get_blob(&first).unwrap().is_some());
    assert!(f.db.delete_blob(&second).unwrap());
    assert!(!f.db.delete_blob(&second).unwrap());
    assert!(f.db.get_blob_by_legacy_path(PATH).unwrap().is_none());
    assert!(f.db.list_legacy_blob_paths("").unwrap().is_empty());
}

#[test]
fn metadata_cas_observes_writes_from_another_connection() {
    let f = Fixture::new();
    let id = f.put(None);
    let initial = f.db.get_blob(&id).unwrap().unwrap().record.revision;
    let other =
        CredentialVault::new(&f.dir.path().join("account.vault.sqlite"), &f.key)
            .unwrap();
    assert_eq!(
        f.db.update_blob_metadata(&id, Some(b"enrolled"), initial, 1001)
            .unwrap(),
        initial + 1
    );
    assert!(matches!(
        other.update_blob_metadata(&id, Some(b"stale"), initial, 1002),
        Err(StorageError::BlobRevisionConflict)
    ));
    assert_eq!(
        other
            .put_blob("oxide.face", PLAINTEXT, None, 1003)
            .unwrap()
            .0,
        id
    );
    assert!(matches!(
        f.db.update_blob_metadata(&id, None, initial + 1, 1004),
        Err(StorageError::BlobRevisionConflict)
    ));
    let stored = f.db.get_blob(&id).unwrap().unwrap();
    assert_eq!(stored.data, PLAINTEXT);
    assert_eq!(stored.record.metadata, Some(b"enrolled".to_vec()));
    assert_eq!(
        (
            stored.record.revision,
            stored.record.created_at,
            stored.record.updated_at
        ),
        (initial + 2, 1000, 1003)
    );
    assert_eq!(
        f.db.update_blob_metadata(&id, None, initial + 2, 1004)
            .unwrap(),
        initial + 3
    );
    assert_eq!(f.db.get_blob(&id).unwrap().unwrap().record.metadata, None);
    f.db.delete_blob(&id).unwrap();
    assert!(matches!(
        f.db.update_blob_metadata(&id, None, initial + 3, 1005),
        Err(StorageError::BlobRevisionConflict)
    ));
}

#[test]
fn recreating_identical_data_rejects_stale_metadata_from_the_previous_incarnation() {
    let f = Fixture::new();
    let id = f.put(None);
    let first = f.db.get_blob(&id).unwrap().unwrap().record.revision;
    let stale =
        f.db.update_blob_metadata(&id, Some(b"old enrollment"), first, 1001)
            .unwrap();
    let other =
        CredentialVault::new(&f.dir.path().join("account.vault.sqlite"), &f.key)
            .unwrap();
    other.delete_blob(&id).unwrap();
    assert_eq!(
        other
            .put_blob("oxide.face", PLAINTEXT, None, 2000)
            .unwrap()
            .0,
        id
    );
    let recreated = other.get_blob(&id).unwrap().unwrap().record.revision;
    let current = other
        .update_blob_metadata(&id, Some(b"new enrollment"), recreated, 2001)
        .unwrap();
    assert_ne!(current, stale);
    assert!(matches!(
        f.db.update_blob_metadata(&id, Some(b"stale enrollment"), stale, 2002),
        Err(StorageError::BlobRevisionConflict)
    ));
    let stored = f.db.get_blob(&id).unwrap().unwrap();
    assert_eq!(stored.data, PLAINTEXT);
    assert_eq!(stored.record.metadata, Some(b"new enrollment".to_vec()));
}

#[test]
fn metadata_commit_failure_is_reported_and_rolled_back() {
    let f = Fixture::new();
    let id = f.put(None);
    let initial = f.db.get_blob(&id).unwrap().unwrap().record.revision;
    f.db.vault.connection().execute_batch(
        "CREATE TABLE commit_guard (blob_id BLOB REFERENCES blobs(blob_id) DEFERRABLE INITIALLY DEFERRED);
         CREATE TRIGGER fail_metadata_commit AFTER UPDATE OF metadata ON blobs
         BEGIN INSERT INTO commit_guard VALUES (X'CAFE'); END;"
    ).unwrap();
    assert!(matches!(
        f.db.update_blob_metadata(&id, Some(b"enrolled"), initial, 2000),
        Err(StorageError::VaultDb(_))
    ));
    let stored = f.db.get_blob(&id).unwrap().unwrap();
    assert_eq!(stored.record.metadata, None);
    assert_eq!(stored.record.revision, initial);
    f.db.vault
        .connection()
        .execute_batch("DROP TRIGGER fail_metadata_commit")
        .unwrap();
    assert_eq!(
        f.db.update_blob_metadata(&id, Some(b"enrolled"), initial, 2000)
            .unwrap(),
        initial + 1
    );
}

#[test]
fn failed_alias_write_rolls_back_blob_upsert() {
    let f = Fixture::new();
    let id = f.put(Some(PATH));
    let initial = f.db.get_blob(&id).unwrap().unwrap().record.revision;
    f.db.vault.connection().execute_batch(
        "CREATE TRIGGER reject_alias BEFORE INSERT ON legacy_blob_paths BEGIN SELECT RAISE(ABORT, 'alias write failed'); END;",
    ).unwrap();
    assert!(f
        .db
        .put_blob("oxide.orb", PLAINTEXT, Some(PATH), 2000)
        .is_err());
    let stored = f.db.get_blob(&id).unwrap().unwrap();
    assert_eq!(stored.data, PLAINTEXT);
    assert_eq!(stored.record.revision, initial);
    let new_id = compute_blob_id(b"new PCP");
    assert!(f
        .db
        .put_blob("oxide.orb", b"new PCP", Some("new.dat"), 2000)
        .is_err());
    assert!(f.db.get_blob(&new_id).unwrap().is_none());
}

#[test]
fn concurrent_writer_failure_leaves_alias_and_revision_unchanged() {
    let f = Fixture::new();
    let id = f.put(Some(PATH));
    let initial = f.db.get_blob(&id).unwrap().unwrap().record.revision;
    let other =
        CredentialVault::new(&f.dir.path().join("account.vault.sqlite"), &f.key)
            .unwrap();
    f.db.vault
        .connection()
        .execute_batch("PRAGMA busy_timeout = 0")
        .unwrap();
    let writer = other.vault.connection().transaction_immediate().unwrap();
    assert!(matches!(
        f.db.put_blob("oxide.face", PLAINTEXT, Some("new.dat"), 2000),
        Err(StorageError::VaultDb(_))
    ));
    drop(writer);
    assert_eq!(
        f.db.get_blob(&id).unwrap().unwrap().record.revision,
        initial
    );
    assert_eq!(f.db.list_legacy_blob_paths("").unwrap(), [PATH]);
    assert_eq!(
        f.db.put_blob("oxide.face", PLAINTEXT, Some("new.dat"), 2000)
            .unwrap()
            .0,
        id
    );
    assert_eq!(
        f.db.get_blob(&id).unwrap().unwrap().record.revision,
        initial + 1
    );
}

#[test]
fn lists_metadata_and_literal_case_sensitive_prefixes() {
    let f = Fixture::new();
    let id = f.put(Some("pcp/a.dat"));
    f.db.put_blob("oxide.orb", b"orb PCP", Some("pcp%/b.dat"), 1001)
        .unwrap();
    f.db.put_blob("oxide.face", PLAINTEXT, Some("PCP/c.dat"), 1002)
        .unwrap();
    assert_eq!(
        f.db.list_legacy_blob_paths("./pcp//").unwrap(),
        ["pcp/a.dat"]
    );
    assert_eq!(f.db.list_legacy_blob_paths("pcp%").unwrap(), ["pcp%/b.dat"]);
    assert_eq!(
        f.db.list_legacy_blob_paths("pcp_").unwrap(),
        [] as [&str; 0]
    );
    assert_eq!(f.db.list_legacy_blob_paths("PCP/").unwrap(), ["PCP/c.dat"]);
    assert_eq!(f.db.list_blobs(None).unwrap().len(), 2);
    let face = f.db.list_blobs(Some("oxide.face")).unwrap();
    assert_eq!(face.len(), 1);
    assert_eq!(*face[0].blob_id, id);
    assert!(f.db.list_blobs(Some("oxide.document")).unwrap().is_empty());
}

#[test_case("/absolute.dat" ; "absolute")]
#[test_case("../escape.dat" ; "parent")]
#[test_case("pcp/../escape.dat" ; "embedded parent")]
#[test_case("C:/pcp.dat" ; "drive")]
#[test_case("\\\\host\\pcp.dat" ; "UNC")]
#[test_case("pcp\\file.dat" ; "backslash")]
#[test_case("pcp/\0file.dat" ; "NUL")]
fn invalid_paths_are_rejected_at_every_entry_point(path: &str) {
    let f = Fixture::new();
    let id = compute_blob_id(b"hello pcp");
    assert!(matches!(
        f.db.put_blob("oxide.face", PLAINTEXT, Some(path), 1000),
        Err(StorageError::InvalidInput(_))
    ));
    assert!(matches!(
        f.db.get_blob_by_legacy_path(path),
        Err(StorageError::InvalidInput(_))
    ));
    assert!(matches!(
        f.db.delete_legacy_blob_path(path),
        Err(StorageError::InvalidInput(_))
    ));
    assert!(matches!(
        f.db.list_legacy_blob_paths(path),
        Err(StorageError::InvalidInput(_))
    ));
    assert!(f.db.get_blob(&id).unwrap().is_none());
}

#[test_case("" ; "empty")]
#[test_case("." ; "dot")]
#[test_case("././" ; "root")]
fn root_is_a_listing_prefix_but_not_a_file_alias(path: &str) {
    let f = Fixture::new();
    f.put(Some(PATH));
    assert!(f
        .db
        .put_blob("oxide.face", PLAINTEXT, Some(path), 2000)
        .is_err());
    assert!(f.db.get_blob_by_legacy_path(path).is_err());
    assert!(f.db.delete_legacy_blob_path(path).is_err());
    assert_eq!(f.db.list_legacy_blob_paths(path).unwrap(), [PATH]);
}

#[test]
fn paths_are_normalized_for_put_read_and_delete() {
    let f = Fixture::new();
    let id = f.put(Some("./face_pcp//./face-pcp-v1.tar.gz"));
    assert_eq!(f.db.list_legacy_blob_paths("").unwrap(), [PATH]);
    assert_eq!(
        *f.db
            .get_blob_by_legacy_path("face_pcp/./face-pcp-v1.tar.gz")
            .unwrap()
            .unwrap()
            .record
            .blob_id,
        id
    );
    assert!(f
        .db
        .delete_legacy_blob_path("./face_pcp//face-pcp-v1.tar.gz")
        .unwrap());
    assert!(f.db.get_blob_by_legacy_path(PATH).unwrap().is_none());
}

#[test_case(Value::Blob(vec![0x42; 31]) ; "short")]
#[test_case(Value::Text("a".repeat(32)) ; "text")]
#[test_case(Value::Null ; "null")]
fn database_rejects_non_blob_or_wrong_length_ids(id: Value) {
    let f = Fixture::new();
    assert!(f
        .db
        .vault
        .connection()
        .execute(
            "INSERT INTO blobs (blob_id, kind, data, metadata, revision, created_at, updated_at) VALUES (?1, 'oxide.face', X'1234', NULL, 1, 1000, 1000)",
            &[id],
        )
        .is_err());
}

#[test]
fn credential_deletion_never_collects_local_blobs() {
    let f = Fixture::new();
    let id = f.put(Some(PATH));
    let credential = world_id_core::Credential::new()
        .issuer_schema_id(100)
        .genesis_issued_at(1000);
    let bytes = crate::Credential::from(credential).to_bytes().unwrap();
    let credential_id =
        f.db.store_credential(100, vec![7; 32], 1000, 9999, bytes.clone(), None, 1000)
            .unwrap();
    f.db.add_credential_blobs(credential_id, &bytes, &[id], 1000)
        .unwrap();
    f.db.delete_credential(credential_id).unwrap();
    f.db.danger_delete_all_credentials().unwrap();
    assert_eq!(
        f.db.get_blob_by_legacy_path(PATH).unwrap().unwrap().data,
        PLAINTEXT
    );
    assert_eq!(f.db.list_blobs(None).unwrap().len(), 1);
}

#[test_case(false ; "merge")]
#[test_case(true ; "restore")]
fn export_excludes_unlinked_data_metadata_and_legacy_paths(restore: bool) {
    let f = Fixture::new();
    let local_id = f.put(Some(PATH));
    let revision = f.db.get_blob(&local_id).unwrap().unwrap().record.revision;
    f.db.update_blob_metadata(&local_id, Some(b"local metadata"), revision, 2000)
        .unwrap();
    let export_path = f.dir.path().join("backup.sqlite");
    f.db.export_plaintext(&export_path).unwrap();
    let backup = Connection::open(&export_path, false).unwrap();
    assert_eq!(
        backup
            .query_row("SELECT COUNT(*) FROM blobs", &[], |row| Ok(
                row.column_i64(0)
            ))
            .unwrap(),
        0
    );
    assert_eq!(backup.query_row(
        "SELECT COUNT(*) FROM pragma_table_info('blobs') WHERE name IN ('metadata', 'revision')",
        &[], |row| Ok(row.column_i64(0)),
    ).unwrap(), 0);
    assert_eq!(
        backup
            .query_row(
                "SELECT COUNT(*) FROM sqlite_schema WHERE name = 'legacy_blob_paths'",
                &[],
                |row| Ok(row.column_i64(0)),
            )
            .unwrap(),
        0
    );
    backup.execute_batch("CREATE TABLE legacy_blob_paths (unexpected TEXT); INSERT INTO legacy_blob_paths VALUES ('ignored');").unwrap();
    drop(backup);
    let bytes = std::fs::read(export_path).unwrap();
    if restore {
        f.db.restore_plaintext_bytes(&bytes).unwrap();
    } else {
        f.db.merge_plaintext_bytes(&bytes).unwrap();
    }
    let stored = f.db.get_blob(&local_id).unwrap().unwrap();
    assert_eq!(stored.data, PLAINTEXT);
    assert_eq!(stored.record.metadata, Some(b"local metadata".to_vec()));
    assert_eq!(f.db.list_legacy_blob_paths("").unwrap(), [PATH]);
}

#[test]
fn revision_overflow_fails_without_changing_data() {
    let f = Fixture::new();
    let id = f.put(Some(PATH));
    f.db.vault
        .connection()
        .execute_batch("UPDATE blobs SET revision = 9223372036854775807")
        .unwrap();
    assert!(f
        .db
        .put_blob("oxide.face", PLAINTEXT, Some("new.dat"), 2000)
        .is_err());
    assert!(f
        .db
        .update_blob_metadata(&id, Some(b"new"), i64::MAX as u64, 2000)
        .is_err());
    assert_eq!(f.db.get_blob(&id).unwrap().unwrap().data, PLAINTEXT);
    assert_eq!(f.db.list_legacy_blob_paths("").unwrap(), [PATH]);
}

#[test]
fn released_schema_gains_tables_and_released_initializer_can_reopen_them() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("account.vault.sqlite");
    let key = SecretBox::init_with(|| [0x42; 32]);
    let credential = crate::Credential::from(
        world_id_core::Credential::new()
            .issuer_schema_id(100)
            .genesis_issued_at(1000),
    )
    .to_bytes()
    .unwrap();
    let credential_id = {
        let old = Vault::open(&path, &key, |conn| conn.execute_batch(RELEASED_SCHEMA))
            .unwrap();
        let conn = old.connection();
        conn.execute_batch("INSERT INTO vault_meta VALUES (1, 42, 1000, 1000)")
            .unwrap();
        let cid = blobs::put(conn, 1, &credential, 1000).unwrap();
        conn.execute("INSERT INTO credential_records VALUES (7, 100, ?1, 1000, 9999, 1000, ?2, NULL)",
            params![vec![7; 32], cid.as_slice()]).unwrap();
        let tables = conn.query_row("SELECT COUNT(*) FROM sqlite_schema WHERE name IN ('blobs', 'legacy_blob_paths')", &[], |row| Ok(row.column_i64(0))).unwrap();
        assert_eq!(tables, 0);
        7
    };
    let id = compute_blob_id(b"hello pcp");
    let initial = {
        let db = CredentialVault::new(&path, &key).unwrap();
        db.init_leaf_index(42, 2000).unwrap();
        assert_eq!(
            db.fetch_credential_by_id(credential_id).unwrap(),
            Some(credential.clone())
        );
        assert_eq!(
            db.put_blob("oxide.face", PLAINTEXT, Some(PATH), 2000)
                .unwrap()
                .0,
            id
        );
        db.get_blob(&id).unwrap().unwrap().record.revision
    };
    {
        let old = Vault::open(&path, &key, |conn| conn.execute_batch(RELEASED_SCHEMA))
            .unwrap();
        let leaf = old.connection().query_row(
            "INSERT INTO vault_meta (schema_version, leaf_index, created_at, updated_at) VALUES (1, 42, 3000, 3000)
             ON CONFLICT(schema_version) DO UPDATE SET leaf_index = COALESCE(vault_meta.leaf_index, excluded.leaf_index) RETURNING leaf_index",
            &[], |row| Ok(row.column_i64(0)),
        ).unwrap();
        assert_eq!(leaf, 42);
        let schema = old
            .connection()
            .query_row("SELECT schema_version FROM vault_meta", &[], |row| {
                Ok(row.column_i64(0))
            })
            .unwrap();
        assert_eq!(schema, 1);
    }
    let reopened = CredentialVault::new(&path, &key).unwrap();
    assert_eq!(
        reopened
            .get_blob_by_legacy_path(PATH)
            .unwrap()
            .unwrap()
            .data,
        PLAINTEXT
    );
    assert_eq!(
        reopened.get_blob(&id).unwrap().unwrap().record.revision,
        initial
    );
    assert_eq!(
        reopened.fetch_credential_by_id(credential_id).unwrap(),
        Some(credential)
    );
}
