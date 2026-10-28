//! Local PCP storage, independent of credential backup tables and notifications.
//!
//! `WalletKit` treats PCPs as opaque: the host chooses each entry's id and kind, and
//! neither is interpreted beyond validation.

use super::{map_db_err, to_i64, to_u64, CredentialVault};
use crate::storage::{PcpMetadata, PcpRecord, StorageError, StorageResult};
use walletkit_sqlite::{params, StepResult, Value};

/// Longest accepted kind, in bytes. Kinds are short labels such as `orb_pkg`.
const MAX_KIND_LEN: usize = 32;

impl CredentialVault {
    pub(crate) fn put_pcp(
        &self,
        id: &str,
        kind: &str,
        data: &[u8],
        now: u64,
    ) -> StorageResult<Vec<u8>> {
        // Text columns are read back up to the first NUL, so such an id could not be
        // listed or fetched again.
        if id.contains('\0') {
            return Err(StorageError::InvalidPcpId);
        }
        validate_kind(kind)?;
        let now = to_i64(now, "now")?;
        let checksum = blake3::hash(data);
        // An autocommit `RETURNING` commits when the statement is finalized, and that
        // result is not observable. The explicit commit surfaces write failures.
        let conn = self.vault.connection();
        let tx = conn.transaction().map_err(|err| map_db_err(&err))?;
        let stored = tx
            .query_row_optional(
                "INSERT INTO pcp_records (id, kind, data, checksum, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?5)
                 ON CONFLICT(id) DO UPDATE SET
                     data = excluded.data, checksum = excluded.checksum, updated_at = excluded.updated_at
                 WHERE pcp_records.kind = excluded.kind
                 RETURNING checksum",
                params![id, kind, data, checksum.as_bytes().as_slice(), now],
                |row| Ok(row.column_blob(0)),
            )
            .map_err(|err| map_db_err(&err))?
            .ok_or(StorageError::PcpKindMismatch)?;
        tx.commit().map_err(|err| map_db_err(&err))?;
        Ok(stored)
    }

    pub(crate) fn get_pcp(&self, id: &str) -> StorageResult<Option<PcpRecord>> {
        let row = self
            .vault
            .connection()
            .query_row_optional(
                "SELECT id, kind, data, checksum FROM pcp_records WHERE id = ?1",
                params![id],
                |row| {
                    Ok((
                        row.column_text(0),
                        row.column_text(1),
                        row.column_blob(2),
                        row.column_blob(3),
                    ))
                },
            )
            .map_err(|err| map_db_err(&err))?;
        let Some((id, kind, data, checksum)) = row else {
            return Ok(None);
        };
        if blake3::hash(&data).as_bytes().as_slice() != checksum {
            return Err(StorageError::CorruptedPcp("checksum mismatch".to_owned()));
        }
        Ok(Some(PcpRecord {
            id,
            kind,
            data,
            checksum,
        }))
    }

    pub(crate) fn list_pcps(
        &self,
        kind: Option<&str>,
    ) -> StorageResult<Vec<PcpMetadata>> {
        let mut stmt = self
            .vault
            .connection()
            .prepare(
                "SELECT id, kind, checksum, created_at, updated_at FROM pcp_records
                 WHERE (?1 IS NULL OR kind = ?1) ORDER BY id",
            )
            .map_err(|err| map_db_err(&err))?;
        stmt.bind_values(params![
            kind.map_or(Value::Null, |kind| Value::Text(kind.to_owned()))
        ])
        .map_err(|err| map_db_err(&err))?;
        let mut entries = Vec::new();
        while let StepResult::Row(row) = stmt.step().map_err(|err| map_db_err(&err))? {
            let checksum = row.column_blob(2);
            if checksum.len() != 32 {
                return Err(StorageError::CorruptedPcp(
                    "invalid checksum length".to_owned(),
                ));
            }
            entries.push(PcpMetadata {
                id: row.column_text(0),
                kind: row.column_text(1),
                checksum,
                created_at: to_u64(row.column_i64(3), "PCP created_at")?,
                updated_at: to_u64(row.column_i64(4), "PCP updated_at")?,
            });
        }
        Ok(entries)
    }

    pub(crate) fn delete_pcp(&self, id: &str) -> StorageResult<bool> {
        self.vault
            .connection()
            .execute("DELETE FROM pcp_records WHERE id = ?1", params![id])
            .map(|count| count != 0)
            .map_err(|err| map_db_err(&err))
    }
}

/// Accepts short lowercase labels such as `orb_pkg`, so kinds stay comparable
/// across hosts and safe to log.
fn validate_kind(kind: &str) -> StorageResult<()> {
    let valid = !kind.is_empty()
        && kind.len() <= MAX_KIND_LEN
        && kind
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
    if valid {
        Ok(())
    } else {
        Err(StorageError::InvalidPcpKind)
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use secrecy::SecretBox;
    use walletkit_sqlite::Connection;

    fn new_vault(dir: &std::path::Path, name: &str) -> CredentialVault {
        CredentialVault::new(&dir.join(name), &SecretBox::init_with(|| [42; 32]))
            .unwrap()
    }

    #[test]
    fn opaque_ids_and_bytes_round_trip_across_reopen_with_stable_checksums() {
        let dir = tempfile::tempdir().unwrap();
        let vault = new_vault(dir.path(), "vault.db");
        let data = vec![0xA5; 5 * 1024 * 1024];
        let id = "./opaque/../identifier/🦉";
        let checksum = vault.put_pcp(id, "orb_pkg", &data, 100).unwrap();
        assert_eq!(checksum, blake3::hash(&data).as_bytes());
        let expected = PcpRecord {
            id: id.to_owned(),
            kind: "orb_pkg".to_owned(),
            data,
            checksum,
        };
        assert_eq!(vault.get_pcp(id).unwrap(), Some(expected.clone()));
        assert_eq!(vault.get_pcp("opaque/../identifier/🦉").unwrap(), None);
        drop(vault);
        let vault = new_vault(dir.path(), "vault.db");
        assert_eq!(vault.get_pcp(id).unwrap(), Some(expected));
        assert!(vault.delete_pcp(id).unwrap());
        assert!(!vault.delete_pcp(id).unwrap());
        assert_eq!(vault.get_pcp(id).unwrap(), None);
        assert!(vault.list_pcps(None).unwrap().is_empty());
    }

    #[test]
    fn put_reports_failures_that_only_surface_at_commit() {
        let dir = tempfile::tempdir().unwrap();
        let vault = new_vault(dir.path(), "vault.db");
        // A deferred foreign key is checked at commit, after the `RETURNING` row.
        vault
            .vault
            .connection()
            .execute_batch(
                "CREATE TABLE commit_guard (
                     missing TEXT REFERENCES pcp_records (id) DEFERRABLE INITIALLY DEFERRED
                 );
                 CREATE TRIGGER fail_at_commit AFTER INSERT ON pcp_records BEGIN
                     INSERT INTO commit_guard VALUES ('not-stored');
                 END;",
            )
            .unwrap();
        assert!(vault.put_pcp("package", "orb_pkg", b"data", 100).is_err());
        assert_eq!(vault.get_pcp("package").unwrap(), None);
    }

    #[test]
    fn put_rejects_ids_and_kinds_it_cannot_store_faithfully() {
        let dir = tempfile::tempdir().unwrap();
        let vault = new_vault(dir.path(), "vault.db");
        assert!(matches!(
            vault.put_pcp("a\0b", "orb_pkg", b"data", 100),
            Err(StorageError::InvalidPcpId)
        ));
        for kind in [
            "",
            "Orb_pkg",
            "orb-pkg",
            "orb pkg",
            "orb\0pkg",
            &"k".repeat(33),
        ] {
            assert!(matches!(
                vault.put_pcp("package", kind, b"data", 100),
                Err(StorageError::InvalidPcpKind)
            ));
        }
        vault
            .put_pcp("package", &"k".repeat(32), b"data", 100)
            .unwrap();
        assert_eq!(vault.list_pcps(None).unwrap().len(), 1);
    }

    #[test]
    fn put_updates_bytes_and_timestamp_but_preserves_kind_and_creation_time() {
        let dir = tempfile::tempdir().unwrap();
        let vault = new_vault(dir.path(), "vault.db");
        let first = vault.put_pcp("package", "face_pkg", b"one", 100).unwrap();
        assert_eq!(
            vault.put_pcp("package", "face_pkg", b"one", 200).unwrap(),
            first
        );
        let next = vault.put_pcp("package", "face_pkg", b"two", 300).unwrap();
        assert_ne!(first, next);
        let before = vault.list_pcps(None).unwrap();
        assert_eq!(
            before,
            vec![PcpMetadata {
                id: "package".to_owned(),
                kind: "face_pkg".to_owned(),
                checksum: next,
                created_at: 100,
                updated_at: 300,
            }]
        );
        let error = vault
            .put_pcp("package", "document_pkg", b"wrong kind", 400)
            .unwrap_err();
        assert!(matches!(error, StorageError::PcpKindMismatch));
        assert!(!error.to_string().contains("package"));
        assert_eq!(vault.list_pcps(None).unwrap(), before);
        assert_eq!(vault.get_pcp("package").unwrap().unwrap().data, b"two");
    }

    #[test]
    fn list_filters_by_kind_and_returns_metadata_for_empty_or_corrupt_data() {
        let dir = tempfile::tempdir().unwrap();
        let vault = new_vault(dir.path(), "vault.db");
        for (kind, id) in [("orb_pkg", "a"), ("face_pkg", "b"), ("document_pkg", "c")] {
            vault.put_pcp(id, kind, b"", 100).unwrap();
            assert_eq!(vault.get_pcp(id).unwrap().unwrap().data, b"");
            assert_eq!(vault.list_pcps(Some(kind)).unwrap()[0].id, id);
        }
        assert!(vault.list_pcps(Some("unknown_pkg")).unwrap().is_empty());
        assert_eq!(vault.list_pcps(None).unwrap().len(), 3);
        vault
            .vault
            .connection()
            .execute_batch("UPDATE pcp_records SET data = X'FF'")
            .unwrap();
        assert_eq!(vault.list_pcps(None).unwrap().len(), 3);
        assert!(matches!(
            vault.get_pcp("a"),
            Err(StorageError::CorruptedPcp(_))
        ));
    }

    #[test]
    fn corrupt_checksums_fail_without_exposing_ids() {
        let dir = tempfile::tempdir().unwrap();
        let vault = new_vault(dir.path(), "vault.db");
        let id = "private-face-identifier";
        vault.put_pcp(id, "face_pkg", b"sealed", 100).unwrap();
        let conn = vault.vault.connection();
        for sql in [
            "UPDATE pcp_records SET checksum = zeroblob(32)",
            "PRAGMA ignore_check_constraints = ON; UPDATE pcp_records SET checksum = X'FF'",
        ] {
            conn.execute_batch(sql).unwrap();
            let error = vault.get_pcp(id).unwrap_err();
            assert!(matches!(error, StorageError::CorruptedPcp(_)));
            assert!(!error.to_string().contains(id));
        }
        assert!(matches!(
            vault.list_pcps(None),
            Err(StorageError::CorruptedPcp(_))
        ));
        conn.execute_batch(
            "UPDATE pcp_records SET checksum = zeroblob(32), created_at = -1",
        )
        .unwrap();
        assert!(matches!(
            vault.list_pcps(None),
            Err(StorageError::VaultDb(_))
        ));
        conn.execute_batch("UPDATE pcp_records SET created_at = 100, updated_at = -1")
            .unwrap();
        assert!(matches!(
            vault.list_pcps(None),
            Err(StorageError::VaultDb(_))
        ));
    }

    #[test]
    fn invalid_time_and_failed_writes_leave_existing_data_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let vault = new_vault(dir.path(), "vault.db");
        vault
            .put_pcp("package", "orb_pkg", b"original", 100)
            .unwrap();
        assert!(matches!(
            vault.put_pcp("package", "orb_pkg", b"new", u64::MAX),
            Err(StorageError::VaultDb(_))
        ));
        let conn = vault.vault.connection();
        conn.execute_batch(
            "CREATE TRIGGER reject_pcp_insert BEFORE INSERT ON pcp_records BEGIN SELECT RAISE(ABORT, 'injected'); END;",
        ).unwrap();
        assert!(matches!(
            vault.put_pcp("another", "face_pkg", b"new", 200),
            Err(StorageError::VaultDb(_))
        ));
        conn.execute_batch(
            "DROP TRIGGER reject_pcp_insert;
             CREATE TRIGGER reject_pcp_update BEFORE UPDATE ON pcp_records BEGIN SELECT RAISE(ABORT, 'injected'); END;",
        ).unwrap();
        assert!(matches!(
            vault.put_pcp("package", "orb_pkg", b"new", 200),
            Err(StorageError::VaultDb(_))
        ));
        conn.execute_batch(
            "CREATE TRIGGER reject_pcp_delete BEFORE DELETE ON pcp_records BEGIN SELECT RAISE(ABORT, 'injected'); END;",
        ).unwrap();
        assert!(matches!(
            vault.delete_pcp("package"),
            Err(StorageError::VaultDb(_))
        ));
        assert_eq!(vault.get_pcp("package").unwrap().unwrap().data, b"original");
        assert_eq!(vault.list_pcps(None).unwrap().len(), 1);
        conn.execute_batch(
            "DROP TRIGGER reject_pcp_update; DROP TRIGGER reject_pcp_delete",
        )
        .unwrap();
        vault.put_pcp("package", "orb_pkg", b"retry", 200).unwrap();
        assert!(vault.delete_pcp("package").unwrap());
    }

    #[test]
    fn unavailable_table_errors_are_propagated_by_every_operation() {
        let dir = tempfile::tempdir().unwrap();
        let vault = new_vault(dir.path(), "vault.db");
        vault
            .vault
            .connection()
            .execute_batch("DROP TABLE pcp_records")
            .unwrap();
        assert!(matches!(
            vault.put_pcp("package", "orb_pkg", b"data", 100),
            Err(StorageError::VaultDb(_))
        ));
        assert!(matches!(
            vault.get_pcp("package"),
            Err(StorageError::VaultDb(_))
        ));
        assert!(matches!(
            vault.list_pcps(None),
            Err(StorageError::VaultDb(_))
        ));
        assert!(matches!(
            vault.delete_pcp("package"),
            Err(StorageError::VaultDb(_))
        ));
    }

    #[test]
    fn credential_backups_exclude_pcps_and_ignore_incoming_pcp_tables() {
        let dir = tempfile::tempdir().unwrap();
        let source = new_vault(dir.path(), "source.db");
        source
            .store_credential(
                10,
                vec![7; 32],
                100,
                1000,
                b"credential".to_vec(),
                None,
                100,
            )
            .unwrap();
        let backup = dir.path().join("backup.db");
        source.export_plaintext(&backup).unwrap();
        let before = std::fs::read(&backup).unwrap();
        source
            .put_pcp("package", "orb_pkg", b"remote", 100)
            .unwrap();
        source.export_plaintext(&backup).unwrap();
        assert_eq!(std::fs::read(&backup).unwrap(), before);
        assert!(!super::super::BACKUP_TABLES.contains(&"pcp_records"));
        let incoming = Connection::open(&backup, false).unwrap();
        assert!(incoming.prepare("SELECT * FROM pcp_records").is_err());
        incoming
            .execute_batch(
                "CREATE TABLE pcp_records (id TEXT, kind TEXT, data BLOB);
             INSERT INTO pcp_records VALUES ('package', 'document_pkg', X'FF');
             INSERT INTO pcp_records VALUES ('incoming-only', 'document_pkg', X'FF');",
            )
            .unwrap();
        drop(incoming);
        for merge in [false, true] {
            let local = new_vault(dir.path(), &format!("local-{merge}.db"));
            local.put_pcp("package", "face_pkg", b"local", 50).unwrap();
            let expected = local.get_pcp("package").unwrap();
            let metadata = local.list_pcps(None).unwrap();
            if merge {
                assert_eq!(
                    local
                        .merge_plaintext_bytes(&std::fs::read(&backup).unwrap())
                        .unwrap(),
                    1
                );
                assert_eq!(
                    local
                        .merge_plaintext_bytes(&std::fs::read(&backup).unwrap())
                        .unwrap(),
                    0
                );
            } else {
                local.import_plaintext(&backup).unwrap();
            }
            assert_eq!(local.get_pcp("package").unwrap(), expected);
            assert_eq!(local.list_pcps(None).unwrap(), metadata);
            assert!(local.get_pcp("incoming-only").unwrap().is_none());
            assert_eq!(
                local
                    .fetch_credential_and_blinding_factor(10, 100)
                    .unwrap()
                    .unwrap()
                    .0,
                b"credential"
            );
        }
    }

    #[test]
    fn failed_credential_import_and_merge_preserve_local_pcps() {
        let dir = tempfile::tempdir().unwrap();
        let source = new_vault(dir.path(), "source.db");
        source
            .store_credential(
                10,
                vec![7; 32],
                100,
                1000,
                b"credential".to_vec(),
                None,
                100,
            )
            .unwrap();
        let backup = dir.path().join("backup.db");
        source.export_plaintext(&backup).unwrap();
        let local = new_vault(dir.path(), "local.db");
        local.put_pcp("package", "face_pkg", b"keep", 50).unwrap();
        let before = local.get_pcp("package").unwrap();
        local.vault.connection().execute_batch(
            "CREATE TRIGGER reject_credential BEFORE INSERT ON credential_records BEGIN SELECT RAISE(ABORT, 'injected'); END;",
        ).unwrap();
        assert!(local.import_plaintext(&backup).is_err());
        assert_eq!(local.get_pcp("package").unwrap(), before);
        assert!(local
            .merge_plaintext_bytes(&std::fs::read(&backup).unwrap())
            .is_err());
        assert_eq!(local.get_pcp("package").unwrap(), before);
        assert!(local.list_credentials(None, 100).unwrap().is_empty());
        local
            .vault
            .connection()
            .execute_batch("DROP TRIGGER reject_credential")
            .unwrap();
        local.import_plaintext(&backup).unwrap();
        assert_eq!(local.get_pcp("package").unwrap(), before);
    }

    #[test]
    fn recorded_v1_vault_upgrades_and_old_backup_preserves_local_pcps() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.db");
        let key = SecretBox::init_with(|| [42; 32]);
        let old = walletkit_db::Vault::open(&path, &key, |conn| {
            walletkit_db::blobs::ensure_schema(conn)?;
            conn.execute_batch(include_str!("fixtures/v1.sql"))?;
            conn.execute_batch("INSERT INTO vault_meta VALUES (1, NULL, 100, 100)")
        })
        .unwrap();
        let source = CredentialVault { vault: old };
        source.init_leaf_index(7, 100).unwrap();
        source
            .store_credential(
                10,
                vec![7; 32],
                100,
                1000,
                b"credential".to_vec(),
                None,
                100,
            )
            .unwrap();
        let backup = dir.path().join("old-backup.db");
        source.export_plaintext(&backup).unwrap();
        drop(source);
        let upgraded = new_vault(dir.path(), "vault.db");
        upgraded.init_leaf_index(7, 200).unwrap();
        assert!(matches!(
            upgraded.init_leaf_index(8, 200),
            Err(StorageError::InvalidLeafIndex { .. })
        ));
        assert_eq!(upgraded.list_credentials(None, 100).unwrap().len(), 1);
        upgraded
            .put_pcp("package", "orb_pkg", b"local", 100)
            .unwrap();
        let receiver = new_vault(dir.path(), "receiver.db");
        receiver
            .put_pcp("package", "document_pkg", b"keep", 100)
            .unwrap();
        receiver.import_plaintext(&backup).unwrap();
        assert_eq!(receiver.get_pcp("package").unwrap().unwrap().data, b"keep");
        assert_eq!(
            receiver
                .merge_plaintext_bytes(&std::fs::read(&backup).unwrap())
                .unwrap(),
            0
        );
        assert_eq!(receiver.get_pcp("package").unwrap().unwrap().data, b"keep");
    }
}
