use super::*;
use crate::storage::blob_id::compute_blob_id;
use secrecy::SecretBox;
use tempfile::TempDir;
use test_case::test_case;
use walletkit_db::{blobs, Vault};
use walletkit_sqlite::Connection;

const RELEASED_SCHEMA: &str = include_str!("fixtures/vault-v0.30.0.sql");

const SEALED: &[u8] = b"device-sealed hello pcp";
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
        let id = compute_blob_id(b"hello pcp");
        assert_eq!(
            self.db
                .put_blob(&id, "oxide.face", SEALED, path, 1000)
                .unwrap(),
            1
        );
        id
    }
}

#[test]
fn aliases_move_without_deleting_content_or_other_aliases() {
    let f = Fixture::new();
    let first = f.put(Some(PATH));
    assert_eq!(
        f.db.put_blob(
            &first,
            "oxide.face",
            SEALED,
            Some("scoped/face.tar.gz"),
            1001
        )
        .unwrap(),
        2
    );
    let second = compute_blob_id(b"replacement face pcp");
    f.db.put_blob(&second, "oxide.face", b"new sealed PCP", Some(PATH), 1002)
        .unwrap();

    assert_eq!(
        *f.db
            .get_blob_by_path(PATH)
            .unwrap()
            .unwrap()
            .record
            .content_id,
        second
    );
    assert_eq!(
        *f.db
            .get_blob_by_path("scoped/face.tar.gz")
            .unwrap()
            .unwrap()
            .record
            .content_id,
        first
    );
    assert_eq!(f.db.get_blob(&first).unwrap().unwrap().data, SEALED);
    assert!(f.db.delete_blob_path("scoped/face.tar.gz").unwrap());
    assert!(!f.db.delete_blob_path("scoped/face.tar.gz").unwrap());
    assert!(f.db.get_blob(&first).unwrap().is_some());
    assert!(f.db.delete_blob(&second).unwrap());
    assert!(!f.db.delete_blob(&second).unwrap());
    assert!(f.db.get_blob_by_path(PATH).unwrap().is_none());
    assert!(f.db.list_blob_paths("").unwrap().is_empty());
}

#[test]
fn metadata_cas_observes_writes_from_another_connection() {
    let f = Fixture::new();
    let id = f.put(None);
    let other =
        CredentialVault::new(&f.dir.path().join("account.vault.sqlite"), &f.key)
            .unwrap();
    assert_eq!(
        f.db.update_blob_metadata(&id, Some(b"enrolled"), 1, 1001)
            .unwrap(),
        2
    );
    assert!(matches!(
        other.update_blob_metadata(&id, Some(b"stale"), 1, 1002),
        Err(StorageError::BlobRevisionConflict)
    ));
    assert_eq!(
        other
            .put_blob(&id, "oxide.face", b"resealed PCP", None, 1003)
            .unwrap(),
        3
    );
    assert!(matches!(
        f.db.update_blob_metadata(&id, None, 2, 1004),
        Err(StorageError::BlobRevisionConflict)
    ));
    let stored = f.db.get_blob(&id).unwrap().unwrap();
    assert_eq!(stored.data, b"resealed PCP");
    assert_eq!(stored.record.metadata, Some(b"enrolled".to_vec()));
    assert_eq!(
        (
            stored.record.revision,
            stored.record.created_at,
            stored.record.updated_at
        ),
        (3, 1000, 1003)
    );
    assert_eq!(f.db.update_blob_metadata(&id, None, 3, 1004).unwrap(), 4);
    assert_eq!(f.db.get_blob(&id).unwrap().unwrap().record.metadata, None);
    f.db.delete_blob(&id).unwrap();
    assert!(matches!(
        f.db.update_blob_metadata(&id, None, 4, 1005),
        Err(StorageError::BlobRevisionConflict)
    ));
}

#[test]
fn failed_alias_write_rolls_back_blob_upsert() {
    let f = Fixture::new();
    let id = f.put(Some(PATH));
    f.db.vault.connection().execute_batch(
        "CREATE TRIGGER reject_alias BEFORE INSERT ON blob_paths BEGIN SELECT RAISE(ABORT, 'alias write failed'); END;",
    ).unwrap();
    assert!(f
        .db
        .put_blob(&id, "oxide.orb", b"replacement", Some(PATH), 2000)
        .is_err());
    let stored = f.db.get_blob(&id).unwrap().unwrap();
    assert_eq!(stored.data, SEALED);
    assert_eq!(stored.record.revision, 1);
    let new_id = compute_blob_id(b"new PCP");
    assert!(f
        .db
        .put_blob(&new_id, "oxide.orb", b"new", Some("new.dat"), 2000)
        .is_err());
    assert!(f.db.get_blob(&new_id).unwrap().is_none());
}

#[test]
fn concurrent_writer_failure_leaves_alias_and_revision_unchanged() {
    let f = Fixture::new();
    let id = f.put(Some(PATH));
    let other =
        CredentialVault::new(&f.dir.path().join("account.vault.sqlite"), &f.key)
            .unwrap();
    f.db.vault
        .connection()
        .execute_batch("PRAGMA busy_timeout = 0")
        .unwrap();
    let writer = other.vault.connection().transaction_immediate().unwrap();
    assert!(matches!(
        f.db.put_blob(&id, "oxide.face", b"new seal", Some("new.dat"), 2000),
        Err(StorageError::VaultDb(_))
    ));
    drop(writer);
    assert_eq!(f.db.get_blob(&id).unwrap().unwrap().record.revision, 1);
    assert_eq!(f.db.list_blob_paths("").unwrap(), [PATH]);
    assert_eq!(
        f.db.put_blob(&id, "oxide.face", b"new seal", Some("new.dat"), 2000)
            .unwrap(),
        2
    );
}

#[test]
fn lists_metadata_and_literal_case_sensitive_prefixes() {
    let f = Fixture::new();
    let id = f.put(Some("pcp/a.dat"));
    let second = compute_blob_id(b"orb PCP");
    f.db.put_blob(
        &second,
        "oxide.orb",
        b"sealed orb",
        Some("pcp%/b.dat"),
        1001,
    )
    .unwrap();
    f.db.put_blob(&id, "oxide.face", SEALED, Some("PCP/c.dat"), 1002)
        .unwrap();
    assert_eq!(f.db.list_blob_paths("./pcp//").unwrap(), ["pcp/a.dat"]);
    assert_eq!(f.db.list_blob_paths("pcp%").unwrap(), ["pcp%/b.dat"]);
    assert_eq!(f.db.list_blob_paths("pcp_").unwrap(), [] as [&str; 0]);
    assert_eq!(f.db.list_blob_paths("PCP/").unwrap(), ["PCP/c.dat"]);
    assert_eq!(f.db.list_blobs(None).unwrap().len(), 2);
    let face = f.db.list_blobs(Some("oxide.face")).unwrap();
    assert_eq!(face.len(), 1);
    assert_eq!(*face[0].content_id, id);
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
        f.db.put_blob(&id, "oxide.face", SEALED, Some(path), 1000),
        Err(StorageError::InvalidInput(_))
    ));
    assert!(matches!(
        f.db.get_blob_by_path(path),
        Err(StorageError::InvalidInput(_))
    ));
    assert!(matches!(
        f.db.delete_blob_path(path),
        Err(StorageError::InvalidInput(_))
    ));
    assert!(matches!(
        f.db.list_blob_paths(path),
        Err(StorageError::InvalidInput(_))
    ));
    assert!(f.db.get_blob(&id).unwrap().is_none());
}

#[test_case("" ; "empty")]
#[test_case("." ; "dot")]
#[test_case("././" ; "root")]
fn root_is_a_listing_prefix_but_not_a_file_alias(path: &str) {
    let f = Fixture::new();
    let id = f.put(Some(PATH));
    assert!(f
        .db
        .put_blob(&id, "oxide.face", SEALED, Some(path), 2000)
        .is_err());
    assert!(f.db.get_blob_by_path(path).is_err());
    assert!(f.db.delete_blob_path(path).is_err());
    assert_eq!(f.db.list_blob_paths(path).unwrap(), [PATH]);
}

#[test]
fn paths_are_normalized_for_put_read_and_delete() {
    let f = Fixture::new();
    let id = f.put(Some("./face_pcp//./face-pcp-v1.tar.gz"));
    assert_eq!(f.db.list_blob_paths("").unwrap(), [PATH]);
    assert_eq!(
        *f.db
            .get_blob_by_path("face_pcp/./face-pcp-v1.tar.gz")
            .unwrap()
            .unwrap()
            .record
            .content_id,
        id
    );
    assert!(f
        .db
        .delete_blob_path("./face_pcp//face-pcp-v1.tar.gz")
        .unwrap());
    assert!(f.db.get_blob_by_path(PATH).unwrap().is_none());
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
            "INSERT INTO blobs VALUES (?1, 'oxide.face', X'1234', NULL, 1, 1000, 1000)",
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
    assert_eq!(f.db.get_blob_by_path(PATH).unwrap().unwrap().data, SEALED);
    assert_eq!(f.db.list_blobs(None).unwrap().len(), 1);
}

#[test_case(false ; "merge")]
#[test_case(true ; "restore")]
fn export_excludes_local_tables_and_recovery_ignores_them(restore: bool) {
    let f = Fixture::new();
    let local_id = f.put(Some(PATH));
    let export_path = f.dir.path().join("backup.sqlite");
    f.db.export_plaintext(&export_path).unwrap();
    let backup = Connection::open(&export_path, false).unwrap();
    let count = backup
        .query_row(
            "SELECT COUNT(*) FROM sqlite_schema WHERE name IN ('blobs', 'blob_paths')",
            &[],
            |row| Ok(row.column_i64(0)),
        )
        .unwrap();
    assert_eq!(count, 0);
    backup.execute_batch("CREATE TABLE blobs (unexpected TEXT); CREATE TABLE blob_paths (unexpected TEXT); INSERT INTO blobs VALUES ('ignored'); INSERT INTO blob_paths VALUES ('ignored');").unwrap();
    drop(backup);
    let bytes = std::fs::read(export_path).unwrap();
    if restore {
        f.db.restore_plaintext_bytes(&bytes).unwrap();
    } else {
        f.db.merge_plaintext_bytes(&bytes).unwrap();
    }
    assert_eq!(f.db.get_blob(&local_id).unwrap().unwrap().data, SEALED);
    assert_eq!(f.db.list_blob_paths("").unwrap(), [PATH]);
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
        .put_blob(&id, "oxide.face", b"new seal", Some("new.dat"), 2000)
        .is_err());
    assert!(f
        .db
        .update_blob_metadata(&id, Some(b"new"), i64::MAX as u64, 2000)
        .is_err());
    assert_eq!(f.db.get_blob(&id).unwrap().unwrap().data, SEALED);
    assert_eq!(f.db.list_blob_paths("").unwrap(), [PATH]);
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
        let tables = conn.query_row("SELECT COUNT(*) FROM sqlite_schema WHERE name IN ('blobs', 'blob_paths')", &[], |row| Ok(row.column_i64(0))).unwrap();
        assert_eq!(tables, 0);
        7
    };
    let id = compute_blob_id(b"hello pcp");
    {
        let db = CredentialVault::new(&path, &key).unwrap();
        db.init_leaf_index(42, 2000).unwrap();
        assert_eq!(
            db.fetch_credential_by_id(credential_id).unwrap(),
            Some(credential.clone())
        );
        assert_eq!(
            db.put_blob(&id, "oxide.face", SEALED, Some(PATH), 2000)
                .unwrap(),
            1
        );
    }
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
        reopened.get_blob_by_path(PATH).unwrap().unwrap().data,
        SEALED
    );
    assert_eq!(reopened.get_blob(&id).unwrap().unwrap().record.revision, 1);
    assert_eq!(
        reopened.fetch_credential_by_id(credential_id).unwrap(),
        Some(credential)
    );
}
