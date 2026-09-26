use super::*;
use secrecy::SecretBox;
use tempfile::TempDir;

struct Fixture {
    _dir: TempDir,
    source: CredentialVault,
    receiver: CredentialVault,
    backup: std::path::PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let dir = TempDir::new().unwrap();
        let key = SecretBox::init_with(|| [42; 32]);
        let source = CredentialVault::new(&dir.path().join("source.db"), &key).unwrap();
        let receiver =
            CredentialVault::new(&dir.path().join("receiver.db"), &key).unwrap();
        source.init_leaf_index(42, 1000).unwrap();
        receiver.init_leaf_index(42, 1000).unwrap();
        let backup = dir.path().join("backup.db");
        Self {
            _dir: dir,
            source,
            receiver,
            backup,
        }
    }

    fn export(&self) {
        self.source.export_plaintext(&self.backup).unwrap();
    }

    fn merge(&self) -> StorageResult<u64> {
        self.receiver.merge_plaintext(&self.backup)
    }
}

fn store(vault: &CredentialVault, schema: u64, bytes: &[u8], now: u64) -> u64 {
    vault
        .store_credential(
            schema,
            vec![7; 32],
            1000,
            9999,
            bytes.to_vec(),
            Some(vec![9; 5]),
            now,
        )
        .unwrap()
}

#[test]
fn repeat_restore_is_noop_and_keeps_local_ids() {
    let f = Fixture::new();
    store(&f.source, 100, b"credential", 1000);
    f.export();
    assert_eq!(f.merge().unwrap(), 1);
    let ids = f.receiver.list_credentials(None, 1000).unwrap();
    assert_eq!(f.merge().unwrap(), 0);
    assert_eq!(
        f.receiver.list_credentials(None, 1000).unwrap()[0].credential_id,
        ids[0].credential_id
    );
    assert_eq!(f.receiver.list_credentials(None, 1000).unwrap().len(), 1);
}

#[test]
fn colliding_row_ids_preserve_local_and_import_remote_credentials() {
    let f = Fixture::new();
    let local_id = store(&f.receiver, 200, b"local-only", 2000);
    assert_eq!(store(&f.source, 100, b"remote-only", 1000), local_id);
    f.export();
    assert_eq!(f.merge().unwrap(), 1);
    assert_eq!(
        f.receiver.list_credentials(Some(200), 1000).unwrap()[0].credential_id,
        local_id
    );
    assert_eq!(f.receiver.list_credentials(None, 1000).unwrap().len(), 2);
    assert_eq!(
        f.receiver
            .fetch_credential_and_blinding_factor(100, 1000)
            .unwrap()
            .unwrap()
            .0,
        b"remote-only"
    );
}

#[test]
fn older_snapshot_does_not_replace_newer_local_credential() {
    let f = Fixture::new();
    store(&f.receiver, 100, b"newer", 2000);
    store(&f.source, 100, b"older", 1000);
    f.export();
    assert_eq!(f.merge().unwrap(), 1);
    assert_eq!(
        f.receiver
            .fetch_credential_and_blinding_factor(100, 2000)
            .unwrap()
            .unwrap()
            .0,
        b"newer"
    );
    assert_eq!(f.merge().unwrap(), 0);
    // The vault stores versions as separate rows; recovery must not compact history.
    assert_eq!(f.receiver.list_credentials(None, 2000).unwrap().len(), 2);
}

#[test]
fn matching_payload_at_a_later_time_preserves_latest_credential_selection() {
    let f = Fixture::new();
    let local_id = store(&f.receiver, 100, b"A", 100);
    store(&f.source, 100, b"B", 200);
    store(&f.source, 100, b"A", 300);
    f.export();
    assert_eq!(f.merge().unwrap(), 2);
    assert_eq!(
        f.receiver
            .fetch_credential_and_blinding_factor(100, 1000)
            .unwrap()
            .unwrap()
            .0,
        b"A"
    );
    let records = f.receiver.list_credentials(None, 1000).unwrap();
    assert_eq!(records.len(), 3);
    assert_eq!(records.last().unwrap().credential_id, local_id);
    assert_eq!(f.merge().unwrap(), 0);
    assert_eq!(f.receiver.list_credentials(None, 1000).unwrap().len(), 3);
}

#[test]
fn newer_snapshot_version_is_available_without_discarding_local_history() {
    let f = Fixture::new();
    let local_id = store(&f.receiver, 100, b"older", 100);
    store(&f.source, 100, b"newer", 200);
    f.export();
    assert_eq!(f.merge().unwrap(), 1);
    assert_eq!(
        f.receiver
            .fetch_credential_and_blinding_factor(100, 1000)
            .unwrap()
            .unwrap()
            .0,
        b"newer"
    );
    let records = f.receiver.list_credentials(None, 1000).unwrap();
    assert_eq!(records.len(), 2);
    assert_eq!(records[1].credential_id, local_id);
    assert_eq!(f.merge().unwrap(), 0);
}

#[test]
fn expired_newer_version_does_not_discard_an_older_usable_version() {
    let f = Fixture::new();
    store(&f.receiver, 100, b"valid", 100);
    f.source
        .store_credential(100, vec![7; 32], 1000, 1500, b"expired".to_vec(), None, 200)
        .unwrap();
    f.export();
    assert_eq!(f.merge().unwrap(), 1);
    assert_eq!(
        f.receiver
            .fetch_credential_and_blinding_factor(100, 2000)
            .unwrap()
            .unwrap()
            .0,
        b"valid"
    );
    let records = f.receiver.list_credentials(None, 2000).unwrap();
    assert_eq!(records.len(), 2);
    assert!(records[0].is_expired);
    assert!(!records[1].is_expired);
    assert_eq!(f.merge().unwrap(), 0);
}

#[test]
fn corrupt_blob_is_rejected_without_changing_existing_credentials() {
    let f = Fixture::new();
    store(&f.receiver, 200, b"local", 1000);
    store(&f.source, 100, b"remote", 1000);
    f.export();
    Connection::open(&f.backup, false)
        .unwrap()
        .execute_batch("UPDATE blob_objects SET bytes = X'CAFE' WHERE blob_kind = 1;")
        .unwrap();
    assert!(f.merge().is_err());
    assert_eq!(f.receiver.list_credentials(None, 1000).unwrap().len(), 1);
    assert_eq!(
        f.receiver
            .fetch_credential_and_blinding_factor(200, 1000)
            .unwrap()
            .unwrap()
            .0,
        b"local"
    );
}

#[test]
fn missing_associated_blob_is_rejected_and_retry_succeeds() {
    let f = Fixture::new();
    store(&f.source, 100, b"remote", 1000);
    f.export();
    Connection::open(&f.backup, false)
        .unwrap()
        .execute_batch("DELETE FROM blob_objects WHERE blob_kind = 2;")
        .unwrap();
    assert!(f.merge().is_err());
    assert!(f.receiver.list_credentials(None, 1000).unwrap().is_empty());
    f.export();
    assert_eq!(f.merge().unwrap(), 1);
}

#[test]
fn database_failure_rolls_back_both_records_and_blobs() {
    let f = Fixture::new();
    store(&f.source, 100, b"remote", 1000);
    f.export();
    f.receiver.vault.connection().execute_batch(
        "CREATE TRIGGER reject_import BEFORE INSERT ON credential_records BEGIN SELECT RAISE(ABORT, 'injected'); END;",
    ).unwrap();
    assert!(f.merge().is_err());
    let count: i64 = f
        .receiver
        .vault
        .connection()
        .query_row("SELECT COUNT(*) FROM blob_objects", &[], |r| {
            Ok(r.column_i64(0))
        })
        .unwrap();
    assert_eq!(count, 0);
    f.receiver
        .vault
        .connection()
        .execute_batch("DROP TRIGGER reject_import")
        .unwrap();
    assert_eq!(f.merge().unwrap(), 1);
}
