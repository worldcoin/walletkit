//! Additive backup recovery. Row IDs are local database keys, not credential identities.
//! Absence from a snapshot is not a deletion instruction: preserve receiver-only credentials.

use super::{map_db_err, CredentialVault, CREDENTIAL_VERSION_ORDER};
use crate::storage::error::{StorageError, StorageResult};
use walletkit_db::blobs::compute_content_id;
use walletkit_sqlite::{params, Connection, StepResult};

impl CredentialVault {
    /// Atomically merges a plaintext backup, returning the number of added records.
    /// Existing IDs and credentials are preserved; replaying the same snapshot is a no-op.
    /// Source IDs are deliberately ignored because independently written vaults reuse them.
    /// Each distinct version, including its `updated_at`, is retained. The issuer, subject,
    /// and genesis fields do not uniquely identify a stored version: normal writes append
    /// records and reads select the most recent non-expired one. Recovery does not compact
    /// that history or replace receiver rows.
    /// The semantic version set is an idempotent union. Equal timestamps use a
    /// content-based total order for both insertion and selection, so merge order
    /// cannot change the selected credential. Row IDs and blob creation metadata
    /// stay local; database bytes are not a portable identity or convergence test.
    /// Only INSERT is used: no existing credential, timestamp, or blob is updated
    /// or deleted. Invalid snapshots roll back the entire transaction.
    ///
    /// The source is copied into a read-only in-memory database on every platform.
    /// A separate source connection isolates malformed schemas from the vault.
    /// No plaintext temporary file is written.
    ///
    /// # Errors
    /// Returns an error for malformed backup contents, unavailable storage, or a failed transaction.
    pub(crate) fn merge_plaintext_bytes(&self, bytes: &[u8]) -> StorageResult<u64> {
        let incoming = Connection::open(std::path::Path::new(":memory:"), false)
            .map_err(|e| map_db_err(&e))?;
        incoming
            .deserialize_readonly("main", bytes)
            .map_err(|e| map_db_err(&e))?;
        merge_from(self.vault.connection(), &incoming)
    }
}

fn invalid_backup() -> StorageError {
    StorageError::VaultDb("invalid credential backup contents".to_owned())
}

fn merge_from(conn: &Connection, incoming: &Connection) -> StorageResult<u64> {
    validate_incoming(incoming)?;
    let tx = conn.transaction_immediate().map_err(|e| map_db_err(&e))?;
    {
        let mut blobs = incoming.prepare(
            "SELECT content_id, blob_kind, MIN(created_at), bytes FROM blob_objects GROUP BY content_id",
        ).map_err(|e| map_db_err(&e))?;
        while let StepResult::Row(row) = blobs.step().map_err(|e| map_db_err(&e))? {
            tx.execute(
                "INSERT INTO blob_objects(content_id, blob_kind, created_at, bytes)
                 VALUES (?1, ?2, ?3, ?4) ON CONFLICT(content_id) DO NOTHING;",
                params![
                    row.column_blob(0),
                    row.column_i64(1),
                    row.column_i64(2),
                    row.column_blob(3)
                ],
            )
            .map_err(|e| map_db_err(&e))?;
        }
    }

    let mut added = 0;
    {
        let mut records = incoming.prepare(&format!(
            "SELECT issuer_schema_id, subject_blinding_factor, genesis_issued_at, expires_at,
                    updated_at, credential_blob_cid, associated_data_cid
             FROM credential_records ORDER BY {CREDENTIAL_VERSION_ORDER}",
        )).map_err(|e| map_db_err(&e))?;
        while let StepResult::Row(row) = records.step().map_err(|e| map_db_err(&e))? {
            let associated = if row.is_column_null(6) {
                walletkit_sqlite::Value::Null
            } else {
                walletkit_sqlite::Value::Blob(row.column_blob(6))
            };
            let count = tx.execute(
                "INSERT INTO credential_records(issuer_schema_id, subject_blinding_factor,
                    genesis_issued_at, expires_at, updated_at, credential_blob_cid, associated_data_cid)
                 SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7 WHERE NOT EXISTS (
                    SELECT 1 FROM credential_records WHERE issuer_schema_id = ?1
                    AND subject_blinding_factor = ?2 AND genesis_issued_at = ?3 AND expires_at = ?4
                    AND updated_at = ?5
                    AND credential_blob_cid = ?6 AND associated_data_cid IS ?7)",
                params![row.column_i64(0), row.column_blob(1), row.column_i64(2), row.column_i64(3),
                        row.column_i64(4), row.column_blob(5), associated],
            ).map_err(|e| map_db_err(&e))?;
            added += count as u64;
        }
    }
    tx.commit().map_err(|e| map_db_err(&e))?;
    Ok(added)
}

fn validate_incoming(incoming: &Connection) -> StorageResult<()> {
    // Exports made with CREATE TABLE AS have no NOT NULL or type constraints.
    // Validate before using SQLite's permissive getters or writing destination data.
    let invalid: i64 = incoming.query_row(
        "SELECT EXISTS(SELECT 1 FROM blob_objects WHERE
            typeof(content_id) != 'blob' OR length(content_id) != 32 OR
            typeof(blob_kind) != 'integer' OR blob_kind NOT IN (1, 2) OR
            typeof(created_at) != 'integer' OR created_at < 0 OR typeof(bytes) != 'blob')
         OR EXISTS(SELECT 1 FROM credential_records r WHERE
            typeof(issuer_schema_id) != 'integer' OR issuer_schema_id < 0 OR
            typeof(subject_blinding_factor) != 'blob' OR length(subject_blinding_factor) != 32 OR
            typeof(genesis_issued_at) != 'integer' OR genesis_issued_at < 0 OR
            typeof(expires_at) != 'integer' OR expires_at < 0 OR
            typeof(updated_at) != 'integer' OR updated_at < 0 OR
            typeof(credential_blob_cid) != 'blob' OR
            NOT EXISTS(SELECT 1 FROM blob_objects b WHERE b.content_id = r.credential_blob_cid AND b.blob_kind = 1) OR
            (associated_data_cid IS NOT NULL AND (typeof(associated_data_cid) != 'blob' OR
             NOT EXISTS(SELECT 1 FROM blob_objects b WHERE b.content_id = r.associated_data_cid AND b.blob_kind = 2))))",
        &[], |row| Ok(row.column_i64(0)),
    ).map_err(|e| map_db_err(&e))?;
    if invalid != 0 {
        return Err(invalid_backup());
    }

    {
        let mut blobs = incoming
            .prepare("SELECT content_id, blob_kind, bytes FROM blob_objects")
            .map_err(|e| map_db_err(&e))?;
        while let StepResult::Row(row) = blobs.step().map_err(|e| map_db_err(&e))? {
            let kind = u8::try_from(row.column_i64(1)).map_err(|_| invalid_backup())?;
            if row.column_blob(0) != compute_content_id(kind, &row.column_blob(2)) {
                return Err(invalid_backup());
            }
        }
    }
    Ok(())
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
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
            let source =
                CredentialVault::new(&dir.path().join("source.db"), &key).unwrap();
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
            self.receiver
                .merge_plaintext_bytes(&std::fs::read(&self.backup).unwrap())
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

    fn versions(vault: &CredentialVault) -> Vec<Vec<walletkit_sqlite::Value>> {
        let mut stmt = vault.vault.connection().prepare(
            "SELECT issuer_schema_id, subject_blinding_factor, genesis_issued_at, expires_at,
                    updated_at, credential_blob_cid, associated_data_cid
             FROM credential_records ORDER BY updated_at DESC, credential_blob_cid DESC,
                  associated_data_cid DESC, issuer_schema_id DESC, subject_blinding_factor DESC,
                  genesis_issued_at DESC, expires_at DESC",
        ).unwrap();
        let mut result = Vec::new();
        while let StepResult::Row(row) = stmt.step().unwrap() {
            result.push(vec![
                row.column_i64(0).into(),
                row.column_blob(1).into(),
                row.column_i64(2).into(),
                row.column_i64(3).into(),
                row.column_i64(4).into(),
                row.column_blob(5).into(),
                if row.is_column_null(6) {
                    walletkit_sqlite::Value::Null
                } else {
                    row.column_blob(6).into()
                },
            ]);
        }
        result
    }

    #[test]
    fn malformed_images_leave_vault_usable_and_valid_retry_succeeds() {
        let f = Fixture::new();
        store(&f.receiver, 100, b"local", 1000);
        store(&f.source, 200, b"incoming", 1000);
        f.export();
        let backup = std::fs::read(&f.backup).unwrap();
        let before = versions(&f.receiver);

        let mut corrupt_schema = backup.clone();
        corrupt_schema[100] = 0xff; // Invalid page type for the sqlite_schema B-tree.
        let mut wal_image = backup.clone();
        wal_image[18..20].fill(2);
        for bytes in [
            Vec::new(),
            b"not a database".to_vec(),
            corrupt_schema,
            wal_image,
        ] {
            assert!(f.receiver.merge_plaintext_bytes(&bytes).is_err());
            assert_eq!(versions(&f.receiver), before);
        }

        assert_eq!(f.receiver.merge_plaintext_bytes(&backup).unwrap(), 1);
        assert_eq!(f.receiver.merge_plaintext_bytes(&backup).unwrap(), 0);
    }

    #[test]
    fn equal_timestamp_versions_converge_in_every_merge_order() {
        let dir = TempDir::new().unwrap();
        let key = SecretBox::init_with(|| [42; 32]);
        let snapshots: Vec<_> = [b"A", b"B", b"C"]
            .iter()
            .enumerate()
            .map(|(i, bytes)| {
                let source = CredentialVault::new(
                    &dir.path().join(format!("source-{i}.db")),
                    &key,
                )
                .unwrap();
                store(&source, 100, *bytes, 1000);
                let path = dir.path().join(format!("snapshot-{i}.db"));
                source.export_plaintext(&path).unwrap();
                path
            })
            .collect();
        let mut expected = None;
        for (i, order) in [
            [0, 1, 2],
            [0, 2, 1],
            [1, 0, 2],
            [1, 2, 0],
            [2, 0, 1],
            [2, 1, 0],
        ]
        .iter()
        .enumerate()
        {
            let receiver = CredentialVault::new(
                &dir.path().join(format!("receiver-{i}.db")),
                &key,
            )
            .unwrap();
            for index in order {
                assert_eq!(
                    receiver
                        .merge_plaintext_bytes(
                            &std::fs::read(&snapshots[*index]).unwrap()
                        )
                        .unwrap(),
                    1
                );
            }
            let state = (
                versions(&receiver),
                receiver
                    .fetch_credential_and_blinding_factor(100, 1000)
                    .unwrap(),
            );
            if let Some(ref expected) = expected {
                assert_eq!(
                    &state, expected,
                    "different merge order selected a different credential"
                );
            } else {
                expected = Some(state);
            }
            for index in order {
                assert_eq!(
                    receiver
                        .merge_plaintext_bytes(
                            &std::fs::read(&snapshots[*index]).unwrap()
                        )
                        .unwrap(),
                    0
                );
            }
            assert_eq!(versions(&receiver).len(), 3);
        }
    }

    #[test]
    fn merge_never_updates_or_deletes_existing_credentials_or_blobs() {
        let f = Fixture::new();
        let local_id = store(&f.receiver, 100, b"local", 1000);
        let original = versions(&f.receiver);
        store(&f.source, 100, b"remote", 1000);
        f.export();
        f.receiver.vault.connection().execute_batch(
            "CREATE TEMP TABLE original_records AS SELECT * FROM credential_records;
             CREATE TEMP TABLE original_blobs AS SELECT * FROM blob_objects;
             CREATE TEMP TRIGGER forbid_record_update BEFORE UPDATE ON credential_records BEGIN SELECT RAISE(ABORT, 'immutable record'); END;
             CREATE TEMP TRIGGER forbid_record_delete BEFORE DELETE ON credential_records BEGIN SELECT RAISE(ABORT, 'immutable record'); END;
             CREATE TEMP TRIGGER forbid_blob_update BEFORE UPDATE ON blob_objects BEGIN SELECT RAISE(ABORT, 'immutable blob'); END;
             CREATE TEMP TRIGGER forbid_blob_delete BEFORE DELETE ON blob_objects BEGIN SELECT RAISE(ABORT, 'immutable blob'); END;",
        ).unwrap();
        assert_eq!(f.merge().unwrap(), 1);
        assert_eq!(f.merge().unwrap(), 0);
        assert!(versions(&f.receiver).contains(&original[0]));
        let changed: i64 = f.receiver.vault.connection().query_row(
            "SELECT EXISTS(SELECT * FROM original_records EXCEPT SELECT * FROM credential_records)
                 OR EXISTS(SELECT * FROM original_blobs EXCEPT SELECT * FROM blob_objects)",
            &[], |row| Ok(row.column_i64(0)),
        ).unwrap();
        assert_eq!(
            changed, 0,
            "every existing field, ID, timestamp, and blob must stay unchanged"
        );
        assert!(f
            .receiver
            .list_credentials(None, 1000)
            .unwrap()
            .iter()
            .any(|record| record.credential_id == local_id));
    }

    #[test]
    fn same_payload_and_timestamp_use_content_fields_to_break_ties() {
        let f = Fixture::new();
        for (vault, factors) in [(&f.source, [7, 8]), (&f.receiver, [8, 7])] {
            for factor in factors {
                vault
                    .store_credential(
                        100,
                        vec![factor; 32],
                        1000,
                        9999,
                        b"same".to_vec(),
                        None,
                        1000,
                    )
                    .unwrap();
            }
            assert_eq!(
                vault
                    .fetch_credential_and_blinding_factor(100, 1000)
                    .unwrap()
                    .unwrap()
                    .1,
                vec![8; 32]
            );
        }
        f.export();
        assert_eq!(f.merge().unwrap(), 0);
        assert_eq!(versions(&f.source), versions(&f.receiver));
        // Public listing uses the same order, although row IDs differ between devices.
        assert_eq!(
            f.source.list_credentials(None, 1000).unwrap()[0].credential_id,
            2
        );
        assert_eq!(
            f.receiver.list_credentials(None, 1000).unwrap()[0].credential_id,
            1
        );
    }

    #[test]
    fn snapshot_row_order_does_not_change_imported_version_order() {
        let f = Fixture::new();
        for bytes in [b"C", b"A", b"B"] {
            store(&f.source, 100, bytes, 1000);
        }
        f.export();
        assert_eq!(f.merge().unwrap(), 3);
        let dir = TempDir::new().unwrap();
        let other = CredentialVault::new(
            &dir.path().join("other.db"),
            &SecretBox::init_with(|| [42; 32]),
        )
        .unwrap();
        let snapshot = Connection::open(&f.backup, false).unwrap();
        snapshot
            .execute_batch(
                "UPDATE credential_records SET credential_id = 100 - credential_id;",
            )
            .unwrap();
        drop(snapshot);
        assert_eq!(
            other
                .merge_plaintext_bytes(&std::fs::read(&f.backup).unwrap())
                .unwrap(),
            3
        );
        assert_eq!(versions(&f.receiver), versions(&other));
        let first_ids: Vec<_> = f
            .receiver
            .list_credentials(None, 1000)
            .unwrap()
            .into_iter()
            .map(|r| r.credential_id)
            .collect();
        let second_ids: Vec<_> = other
            .list_credentials(None, 1000)
            .unwrap()
            .into_iter()
            .map(|r| r.credential_id)
            .collect();
        assert_eq!(first_ids, second_ids);
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
            .store_credential(
                100,
                vec![7; 32],
                1000,
                1500,
                b"expired".to_vec(),
                None,
                200,
            )
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
            .execute_batch(
                "UPDATE blob_objects SET bytes = X'CAFE' WHERE blob_kind = 1;",
            )
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
}
