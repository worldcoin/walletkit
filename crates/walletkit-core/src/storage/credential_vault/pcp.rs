//! Local PCP storage, independent of credential backup tables and notifications.

use super::{map_db_err, to_i64, to_u64, CredentialVault};
use crate::storage::{PcpKind, PcpMetadata, PcpRecord, StorageError, StorageResult};
use walletkit_sqlite::{params, StepResult, Value};

impl CredentialVault {
    pub(crate) fn put_pcp(
        &self,
        path: &str,
        kind: PcpKind,
        data: &[u8],
        now: u64,
    ) -> StorageResult<Vec<u8>> {
        let now = to_i64(now, "now")?;
        let checksum = blake3::hash(data);
        self.vault.connection().query_row_optional(
            "INSERT INTO pcp_records (path, kind, data, checksum, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?5)
             ON CONFLICT(path) DO UPDATE SET
                 data = excluded.data, checksum = excluded.checksum, updated_at = excluded.updated_at
             WHERE pcp_records.kind = excluded.kind
             RETURNING checksum",
            params![path, kind as i64, data, checksum.as_bytes().as_slice(), now],
            |row| Ok(row.column_blob(0)),
        ).map_err(|err| map_db_err(&err))?.ok_or(StorageError::PcpKindMismatch)
    }

    pub(crate) fn get_pcp(&self, path: &str) -> StorageResult<Option<PcpRecord>> {
        let row = self
            .vault
            .connection()
            .query_row_optional(
                "SELECT path, kind, data, checksum FROM pcp_records WHERE path = ?1",
                params![path],
                |row| {
                    Ok((
                        row.column_text(0),
                        row.column_i64(1),
                        row.column_blob(2),
                        row.column_blob(3),
                    ))
                },
            )
            .map_err(|err| map_db_err(&err))?;
        let Some((path, kind, data, checksum)) = row else {
            return Ok(None);
        };
        let kind = PcpKind::try_from(kind)?;
        if blake3::hash(&data).as_bytes().as_slice() != checksum {
            return Err(StorageError::CorruptedPcp("checksum mismatch".to_owned()));
        }
        Ok(Some(PcpRecord {
            path,
            kind,
            data,
            checksum,
        }))
    }

    pub(crate) fn list_pcps(
        &self,
        kind: Option<PcpKind>,
    ) -> StorageResult<Vec<PcpMetadata>> {
        let mut stmt = self
            .vault
            .connection()
            .prepare(
                "SELECT path, kind, checksum, created_at, updated_at FROM pcp_records
             WHERE (?1 IS NULL OR kind = ?1) ORDER BY path",
            )
            .map_err(|err| map_db_err(&err))?;
        stmt.bind_values(params![
            kind.map_or(Value::Null, |kind| Value::Integer(kind as i64))
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
                path: row.column_text(0),
                kind: PcpKind::try_from(row.column_i64(1))?,
                checksum,
                created_at: to_u64(row.column_i64(3), "PCP created_at")?,
                updated_at: to_u64(row.column_i64(4), "PCP updated_at")?,
            });
        }
        Ok(entries)
    }

    pub(crate) fn delete_pcp(&self, path: &str) -> StorageResult<bool> {
        self.vault
            .connection()
            .execute("DELETE FROM pcp_records WHERE path = ?1", params![path])
            .map(|count| count != 0)
            .map_err(|err| map_db_err(&err))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::SecretBox;
    use walletkit_sqlite::Connection;

    fn new_vault(dir: &std::path::Path, name: &str) -> CredentialVault {
        CredentialVault::new(&dir.join(name), &SecretBox::init_with(|| [42; 32]))
            .unwrap()
    }

    #[test]
    fn opaque_paths_and_bytes_round_trip_across_reopen_with_stable_checksums() {
        let dir = tempfile::tempdir().unwrap();
        let vault = new_vault(dir.path(), "vault.db");
        let data = vec![0xA5; 5 * 1024 * 1024];
        let path = "./opaque/../identifier/🦉";
        let checksum = vault.put_pcp(path, PcpKind::Orb, &data, 100).unwrap();
        assert_eq!(checksum, blake3::hash(&data).as_bytes());
        let expected = PcpRecord {
            path: path.to_owned(),
            kind: PcpKind::Orb,
            data,
            checksum,
        };
        assert_eq!(vault.get_pcp(path).unwrap(), Some(expected.clone()));
        assert_eq!(vault.get_pcp("opaque/../identifier/🦉").unwrap(), None);
        drop(vault);
        let vault = new_vault(dir.path(), "vault.db");
        assert_eq!(vault.get_pcp(path).unwrap(), Some(expected));
        assert!(vault.delete_pcp(path).unwrap());
        assert!(!vault.delete_pcp(path).unwrap());
        assert_eq!(vault.get_pcp(path).unwrap(), None);
        assert!(vault.list_pcps(None).unwrap().is_empty());
    }

    #[test]
    fn put_updates_bytes_and_timestamp_but_preserves_kind_and_creation_time() {
        let dir = tempfile::tempdir().unwrap();
        let vault = new_vault(dir.path(), "vault.db");
        let first = vault
            .put_pcp("package", PcpKind::Face, b"one", 100)
            .unwrap();
        assert_eq!(
            vault
                .put_pcp("package", PcpKind::Face, b"one", 200)
                .unwrap(),
            first
        );
        let next = vault
            .put_pcp("package", PcpKind::Face, b"two", 300)
            .unwrap();
        assert_ne!(first, next);
        let before = vault.list_pcps(None).unwrap();
        assert_eq!(
            before,
            vec![PcpMetadata {
                path: "package".to_owned(),
                kind: PcpKind::Face,
                checksum: next,
                created_at: 100,
                updated_at: 300,
            }]
        );
        let error = vault
            .put_pcp("package", PcpKind::Document, b"wrong kind", 400)
            .unwrap_err();
        assert!(matches!(error, StorageError::PcpKindMismatch));
        assert!(!error.to_string().contains("package"));
        assert_eq!(vault.list_pcps(None).unwrap(), before);
        assert_eq!(vault.get_pcp("package").unwrap().unwrap().data, b"two");
    }

    #[test]
    fn list_filters_each_kind_and_returns_metadata_for_empty_or_corrupt_data() {
        let dir = tempfile::tempdir().unwrap();
        let vault = new_vault(dir.path(), "vault.db");
        for (kind, path) in [
            (PcpKind::Orb, "a"),
            (PcpKind::Face, "b"),
            (PcpKind::Document, "c"),
        ] {
            vault.put_pcp(path, kind, b"", 100).unwrap();
            assert_eq!(vault.get_pcp(path).unwrap().unwrap().data, b"");
            assert_eq!(vault.list_pcps(Some(kind)).unwrap()[0].path, path);
        }
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
    fn corrupt_checksums_and_kinds_fail_without_exposing_paths() {
        let dir = tempfile::tempdir().unwrap();
        let vault = new_vault(dir.path(), "vault.db");
        let path = "private-face-identifier";
        vault.put_pcp(path, PcpKind::Face, b"sealed", 100).unwrap();
        let conn = vault.vault.connection();
        for sql in [
            "UPDATE pcp_records SET checksum = zeroblob(32)",
            "PRAGMA ignore_check_constraints = ON; UPDATE pcp_records SET checksum = X'FF'",
            "UPDATE pcp_records SET kind = 4",
        ] {
            conn.execute_batch(sql).unwrap();
            let error = vault.get_pcp(path).unwrap_err();
            assert!(matches!(error, StorageError::CorruptedPcp(_)));
            assert!(!error.to_string().contains(path));
        }
        assert!(matches!(
            vault.list_pcps(None),
            Err(StorageError::CorruptedPcp(_))
        ));
        conn.execute_batch("UPDATE pcp_records SET checksum = zeroblob(32)")
            .unwrap();
        assert!(matches!(
            vault.list_pcps(None),
            Err(StorageError::CorruptedPcp(_))
        ));
        conn.execute_batch("UPDATE pcp_records SET kind = 2, created_at = -1")
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
            .put_pcp("package", PcpKind::Orb, b"original", 100)
            .unwrap();
        assert!(matches!(
            vault.put_pcp("package", PcpKind::Orb, b"new", u64::MAX),
            Err(StorageError::VaultDb(_))
        ));
        let conn = vault.vault.connection();
        conn.execute_batch(
            "CREATE TRIGGER reject_pcp_insert BEFORE INSERT ON pcp_records BEGIN SELECT RAISE(ABORT, 'injected'); END;",
        ).unwrap();
        assert!(matches!(
            vault.put_pcp("another", PcpKind::Face, b"new", 200),
            Err(StorageError::VaultDb(_))
        ));
        conn.execute_batch(
            "DROP TRIGGER reject_pcp_insert;
             CREATE TRIGGER reject_pcp_update BEFORE UPDATE ON pcp_records BEGIN SELECT RAISE(ABORT, 'injected'); END;",
        ).unwrap();
        assert!(matches!(
            vault.put_pcp("package", PcpKind::Orb, b"new", 200),
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
        vault
            .put_pcp("package", PcpKind::Orb, b"retry", 200)
            .unwrap();
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
            vault.put_pcp("package", PcpKind::Orb, b"data", 100),
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
            .put_pcp("package", PcpKind::Orb, b"remote", 100)
            .unwrap();
        source.export_plaintext(&backup).unwrap();
        assert_eq!(std::fs::read(&backup).unwrap(), before);
        assert!(!super::super::BACKUP_TABLES.contains(&"pcp_records"));
        let incoming = Connection::open(&backup, false).unwrap();
        assert!(incoming.prepare("SELECT * FROM pcp_records").is_err());
        incoming
            .execute_batch(
                "CREATE TABLE pcp_records (path TEXT, kind INTEGER, data BLOB);
             INSERT INTO pcp_records VALUES ('package', 3, X'FF');
             INSERT INTO pcp_records VALUES ('incoming-only', 3, X'FF');",
            )
            .unwrap();
        drop(incoming);
        for merge in [false, true] {
            let local = new_vault(dir.path(), &format!("local-{merge}.db"));
            local
                .put_pcp("package", PcpKind::Face, b"local", 50)
                .unwrap();
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
        local
            .put_pcp("package", PcpKind::Face, b"keep", 50)
            .unwrap();
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
            conn.execute_batch("PRAGMA user_version = 1")
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
            .put_pcp("package", PcpKind::Orb, b"local", 100)
            .unwrap();
        let receiver = new_vault(dir.path(), "receiver.db");
        receiver
            .put_pcp("package", PcpKind::Document, b"keep", 100)
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
