//! Versioned credential-vault schema. The shared blob schema is owned by `walletkit-db`.

use walletkit_db::blobs;
use walletkit_sqlite::{
    error::ErrorCode, params, Connection, DbResult, Error, StepResult,
};

/// The vault migrations, in order. Append new versions; never change shipped migrations.
/// `vault_meta.schema_version` counts the applied migrations.
/// Migrations must not start transactions or modify the shared blob schema.
const MIGRATIONS: &[fn(&Connection) -> DbResult<()>] =
    &[migration_v1, migration_v2, migration_v3];

#[expect(
    clippy::cast_possible_wrap,
    reason = "the migration list cannot approach i64::MAX"
)]
pub(super) const VAULT_SCHEMA_VERSION: i64 = MIGRATIONS.len() as i64;

/// Initializes the vault schema or applies pending migrations.
///
/// Existing vaults need no writes unless a schema or metadata upgrade is needed.
/// Upgrades run in one transaction and roll back if interrupted or unsuccessful.
/// Newer or incomplete schemas return an error without resetting the vault.
///
/// Plaintext backups contain only [`super::BACKUP_TABLES`], excluding `vault_meta`.
/// Credential schema changes must preserve compatibility with older backups.
pub(super) fn ensure_schema(conn: &Connection) -> DbResult<()> {
    if schema_is_empty(conn)? {
        return migrate(conn, MIGRATIONS);
    }
    let Some(version) = read_version(conn)? else {
        return migrate(conn, MIGRATIONS);
    };
    if version > VAULT_SCHEMA_VERSION {
        return Err(newer_schema_error(version, MIGRATIONS.len()));
    }
    validate_schema(conn, version)?;
    if version < VAULT_SCHEMA_VERSION {
        migrate(conn, MIGRATIONS)?;
    }
    Ok(())
}

/// Applies pending migrations and records the version in the same transaction.
fn migrate(
    conn: &Connection,
    migrations: &[fn(&Connection) -> DbResult<()>],
) -> DbResult<()> {
    let tx = conn.transaction_immediate()?;
    // Recheck under the write lock: another opener may have initialized or migrated first.
    let (version, needs_metadata) = if schema_is_empty(conn)? {
        (0, true)
    } else if let Some(version) = read_version(conn)? {
        (version, false)
    } else {
        validate_legacy_schema(conn)?;
        (1, true)
    };
    let applied = usize::try_from(version)
        .map_err(|_| schema_error("invalid vault schema version"))?;
    if applied > migrations.len() {
        return Err(newer_schema_error(version, migrations.len()));
    }
    if !needs_metadata {
        validate_schema(conn, version)?;
    }
    if applied == migrations.len() && !needs_metadata {
        return tx.commit();
    }

    blobs::ensure_schema(conn)?;
    for migration in migrations.iter().skip(applied) {
        migration(conn)?;
    }
    record_version(conn, migrations.len())?;
    tx.commit()
}

/// Reads the stored version, or `None` if the metadata table has no row.
/// Missing tables, duplicate rows and invalid versions return an error.
fn read_version(conn: &Connection) -> DbResult<Option<i64>> {
    let mut stmt =
        conn.prepare("SELECT schema_version, typeof(schema_version) FROM vault_meta")?;
    let (version, storage_type) = match stmt.step()? {
        StepResult::Done => return Ok(None),
        StepResult::Row(row) => (row.column_i64(0), row.column_text(1)),
    };
    if matches!(stmt.step()?, StepResult::Row(_)) {
        return Err(schema_error("multiple vault metadata rows"));
    }
    if storage_type != "integer" || version <= 0 {
        return Err(schema_error("invalid vault schema version"));
    }
    Ok(Some(version))
}

fn schema_is_empty(conn: &Connection) -> DbResult<bool> {
    conn.query_row(
        "SELECT NOT EXISTS(SELECT 1 FROM sqlite_master)",
        &[],
        |row| Ok(row.column_i64(0) != 0),
    )
}

/// Validates the tables and metadata constraint required by the stored version.
fn validate_schema(conn: &Connection, version: i64) -> DbResult<()> {
    let required_tables: &[&str] = if version >= 3 {
        &[
            "vault_meta",
            "credential_records",
            "blob_objects",
            "pcp_records",
        ]
    } else {
        &["vault_meta", "credential_records", "blob_objects"]
    };
    for table in required_tables {
        let present = conn
            .query_row_optional(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1",
                params![*table],
                |_| Ok(()),
            )?
            .is_some();
        if !present {
            return Err(schema_error("vault schema is incomplete"));
        }
    }
    if version >= 2 && !has_singleton_constraint(conn)? {
        return Err(schema_error("vault metadata constraint is missing"));
    }
    Ok(())
}

/// Recognizes v1 vaults whose account metadata has not been initialized yet.
fn validate_legacy_schema(conn: &Connection) -> DbResult<()> {
    validate_schema(conn, 1)?;
    let has_legacy_index = conn
        .query_row_optional(
            "SELECT 1 FROM sqlite_master WHERE type = 'index'
         AND tbl_name = 'vault_meta' AND name = 'idx_vault_meta_schema_version'",
            &[],
            |_| Ok(()),
        )?
        .is_some();
    if !has_legacy_index || has_singleton_constraint(conn)? {
        return Err(schema_error("vault metadata row is missing"));
    }
    Ok(())
}

fn has_singleton_constraint(conn: &Connection) -> DbResult<bool> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master
         WHERE type = 'index' AND tbl_name = 'vault_meta'
           AND name = 'idx_vault_meta_singleton')",
        &[],
        |row| Ok(row.column_i64(0) != 0),
    )
}

/// Records the schema version without replacing account metadata.
fn record_version(conn: &Connection, version: usize) -> DbResult<()> {
    let version = i64::try_from(version)
        .map_err(|_| schema_error("invalid vault schema version"))?;
    let updated = conn.execute(
        "UPDATE vault_meta SET schema_version = ?1",
        params![version],
    )?;
    if updated == 0 {
        conn.execute(
            "INSERT INTO vault_meta (schema_version, leaf_index, created_at, updated_at)
             VALUES (?1, NULL, strftime('%s','now'), strftime('%s','now'))",
            params![version],
        )?;
    }
    Ok(())
}

fn newer_schema_error(version: i64, supported: usize) -> Error {
    schema_error(format!(
        "vault schema version {version} is newer than supported version {supported}; upgrade WalletKit"
    ))
}

fn schema_error(message: impl Into<String>) -> Error {
    Error {
        code: ErrorCode(1),
        message: message.into(),
    }
}

/// Version 1: the credential tables and account metadata.
fn migration_v1(conn: &Connection) -> DbResult<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS vault_meta (
            schema_version  INTEGER NOT NULL,
            leaf_index      INTEGER,
            created_at      INTEGER NOT NULL,
            updated_at      INTEGER NOT NULL
        );

        CREATE TRIGGER IF NOT EXISTS vault_meta_set_updated_at
        AFTER UPDATE ON vault_meta
        FOR EACH ROW
        BEGIN
            UPDATE vault_meta
            SET updated_at = CAST(strftime('%s','now') AS INTEGER)
            WHERE schema_version = NEW.schema_version;
        END;

        CREATE TABLE IF NOT EXISTS credential_records (
            credential_id           INTEGER NOT NULL PRIMARY KEY,
            issuer_schema_id        INTEGER NOT NULL,
            subject_blinding_factor BLOB    NOT NULL,
            genesis_issued_at        INTEGER NOT NULL,
            expires_at              INTEGER NOT NULL,
            updated_at              INTEGER NOT NULL,
            credential_blob_cid     BLOB    NOT NULL,
            associated_data_cid     BLOB
        );

        CREATE INDEX IF NOT EXISTS idx_cred_by_issuer_schema
        ON credential_records (issuer_schema_id, updated_at DESC);

        CREATE INDEX IF NOT EXISTS idx_cred_by_expiry
        ON credential_records (expires_at);
",
    )
}

/// Version 2: enforce one metadata row independently of its schema version.
fn migration_v2(conn: &Connection) -> DbResult<()> {
    conn.execute_batch(
        "DROP INDEX IF EXISTS idx_vault_meta_schema_version;
         CREATE UNIQUE INDEX IF NOT EXISTS idx_vault_meta_singleton
         ON vault_meta ((1));",
    )
}

/// Version 3: local PCP storage. PCPs are backed up separately under their own
/// designators, such as `orb_pkg`, so credential backups exclude them.
fn migration_v3(conn: &Connection) -> DbResult<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS pcp_records (
            id          TEXT PRIMARY KEY NOT NULL,
            kind        TEXT NOT NULL CHECK (length(kind) BETWEEN 1 AND 32),
            checksum    BLOB NOT NULL CHECK (typeof(checksum) = 'blob' AND length(checksum) = 32),
            created_at  INTEGER NOT NULL CHECK (created_at >= 0),
            updated_at  INTEGER NOT NULL CHECK (updated_at >= 0),
            -- Last, so reading metadata does not walk the package's overflow pages.
            data        BLOB NOT NULL
        );",
    )
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use crate::storage::{CredentialVault, StorageError};
    use secrecy::SecretBox;
    use walletkit_db::Vault;
    use walletkit_sqlite::cipher;

    fn version(conn: &Connection) -> i64 {
        read_version(conn).unwrap().unwrap()
    }

    fn migration_test_local(conn: &Connection) -> DbResult<()> {
        conn.execute_batch("CREATE TABLE local_only (value INTEGER);")
    }

    #[test]
    fn pcp_data_is_stored_after_its_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let key = SecretBox::init_with(|| [42; 32]);
        let vault = CredentialVault::new(&dir.path().join("vault.db"), &key).unwrap();
        let last_column = vault
            .vault
            .connection()
            .query_row(
                "SELECT name FROM pragma_table_info('pcp_records') ORDER BY cid DESC LIMIT 1",
                &[],
                |row| Ok(row.column_text(0)),
            )
            .unwrap();
        assert_eq!(last_column, "data");
    }

    #[test]
    fn v2_metadata_upgrades_without_changing_the_account() {
        let dir = tempfile::tempdir().unwrap();
        let key = SecretBox::init_with(|| [42; 32]);
        let vault = CredentialVault {
            vault: Vault::open(&dir.path().join("vault.db"), &key, |conn| {
                migrate(conn, &[migration_v1, migration_v2])
            })
            .unwrap(),
        };
        let conn = vault.vault.connection();
        vault.init_leaf_index(7, 100).unwrap();
        assert_eq!(version(conn), 2);
        assert!(conn.prepare("SELECT * FROM pcp_records").is_err());
        ensure_schema(conn).unwrap();
        assert_eq!(version(conn), 3);
        assert!(vault.list_pcps(None).unwrap().is_empty());
        vault.init_leaf_index(7, 200).unwrap();
        assert!(matches!(
            vault.init_leaf_index(8, 300),
            Err(StorageError::InvalidLeafIndex { .. })
        ));
    }

    #[test]
    fn version_reader_only_reads_metadata() {
        let conn = Connection::open(":memory:", false).unwrap();
        assert!(read_version(&conn).is_err());
        conn.execute_batch("CREATE TABLE vault_meta (schema_version)")
            .unwrap();
        assert_eq!(read_version(&conn).unwrap(), None);
        conn.execute_batch("INSERT INTO vault_meta VALUES (1)")
            .unwrap();
        assert_eq!(read_version(&conn).unwrap(), Some(1));
        conn.execute_batch("INSERT INTO vault_meta VALUES (1)")
            .unwrap();
        assert!(read_version(&conn).is_err());
    }

    #[test]
    fn version_reader_rejects_invalid_sqlite_values() {
        for value in ["NULL", "0", "-1", "1.5", "'invalid'", "'1'", "x'31'"] {
            let conn = Connection::open(":memory:", false).unwrap();
            conn.execute_batch("CREATE TABLE vault_meta (schema_version)")
                .unwrap();
            conn.execute_batch(&format!("INSERT INTO vault_meta VALUES ({value})"))
                .unwrap();
            assert!(read_version(&conn).is_err(), "{value}");
        }
    }

    #[test]
    fn incomplete_older_schemas_fail_before_migrations() {
        for initialized in [false, true] {
            for table in ["credential_records", "blob_objects"] {
                let conn = Connection::open(":memory:", false).unwrap();
                blobs::ensure_schema(&conn).unwrap();
                conn.execute_batch(include_str!("fixtures/v1.sql")).unwrap();
                if initialized {
                    conn.execute_batch(
                        "INSERT INTO vault_meta VALUES (1, 7, 100, 100)",
                    )
                    .unwrap();
                }
                conn.execute_batch(&format!("DROP TABLE {table}")).unwrap();
                assert!(ensure_schema(&conn).is_err());
                assert_eq!(read_version(&conn).unwrap(), initialized.then_some(1));
                assert!(!has_singleton_constraint(&conn).unwrap());
                assert!(conn.prepare(&format!("SELECT * FROM {table}")).is_err());
            }
        }
    }

    #[test]
    fn initialization_rechecks_after_another_opener_creates_the_vault() {
        let dir = tempfile::tempdir().unwrap();
        let key = SecretBox::init_with(|| [42; 32]);
        let path = dir.path().join("vault.db");
        let first = cipher::open_encrypted(&path, &key).unwrap();
        let second = cipher::open_encrypted(&path, &key).unwrap();
        assert!(schema_is_empty(&second).unwrap());
        ensure_schema(&first).unwrap();
        migrate(&second, MIGRATIONS).unwrap();
        assert_eq!(version(&second), VAULT_SCHEMA_VERSION);
        assert_eq!(
            second
                .query_row("SELECT total_changes()", &[], |row| {
                    Ok(row.column_i64(0))
                })
                .unwrap(),
            0
        );
    }

    #[test]
    fn missing_current_metadata_constraint_fails_without_repair() {
        let conn = Connection::open(":memory:", false).unwrap();
        ensure_schema(&conn).unwrap();
        conn.execute_batch("DROP INDEX idx_vault_meta_singleton")
            .unwrap();
        assert!(ensure_schema(&conn).is_err());
        assert_eq!(version(&conn), VAULT_SCHEMA_VERSION);
        assert!(!has_singleton_constraint(&conn).unwrap());
    }

    #[test]
    fn populated_database_without_metadata_is_not_initialized() {
        let conn = Connection::open(":memory:", false).unwrap();
        conn.execute_batch(
            "CREATE TABLE unrelated (value); INSERT INTO unrelated VALUES (7)",
        )
        .unwrap();
        assert!(ensure_schema(&conn).is_err());
        assert!(conn.prepare("SELECT * FROM vault_meta").is_err());
        assert_eq!(
            conn.query_row("SELECT value FROM unrelated", &[], |row| Ok(
                row.column_i64(0)
            ))
            .unwrap(),
            7
        );
    }

    #[test]
    fn fresh_vault_records_version_and_reopens_idempotently() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.db");
        let key = SecretBox::init_with(|| [42; 32]);
        let vault = CredentialVault::new(&path, &key).unwrap();
        assert_eq!(version(vault.vault.connection()), VAULT_SCHEMA_VERSION);
        vault.init_leaf_index(7, 100).unwrap();
        drop(vault);
        let vault = CredentialVault::new(&path, &key).unwrap();
        vault.init_leaf_index(7, 200).unwrap();
        let count = vault
            .vault
            .connection()
            .query_row("SELECT COUNT(*) FROM vault_meta", &[], |row| {
                Ok(row.column_i64(0))
            })
            .unwrap();
        assert_eq!(count, 1);
        assert!(matches!(
            vault.init_leaf_index(8, 300),
            Err(StorageError::InvalidLeafIndex { .. })
        ));
    }

    #[test]
    fn account_initialization_preserves_migrated_schema_and_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let key = SecretBox::init_with(|| [42; 32]);
        let vault = CredentialVault {
            vault: Vault::open(&dir.path().join("vault.db"), &key, |conn| {
                migrate(conn, &[migration_v1])
            })
            .unwrap(),
        };
        let conn = vault.vault.connection();
        vault.init_leaf_index(7, 100).unwrap();
        let created_at = conn
            .query_row("SELECT created_at FROM vault_meta", &[], |row| {
                Ok(row.column_i64(0))
            })
            .unwrap();
        migrate(conn, MIGRATIONS).unwrap();

        vault.init_leaf_index(7, 200).unwrap();
        assert!(matches!(
            vault.init_leaf_index(8, 300),
            Err(StorageError::InvalidLeafIndex { .. })
        ));
        assert_eq!(conn.query_row(
            "SELECT COUNT(*), schema_version, leaf_index, created_at FROM vault_meta", &[],
            |row| Ok((row.column_i64(0), row.column_i64(1), row.column_i64(2), row.column_i64(3))),
        ).unwrap(), (1, VAULT_SCHEMA_VERSION, 7, created_at));
    }

    #[test]
    fn metadata_constraint_rejects_a_second_row_with_a_different_version() {
        let conn = Connection::open(":memory:", false).unwrap();
        ensure_schema(&conn).unwrap();
        assert!(conn
            .execute(
                "INSERT INTO vault_meta VALUES (?1, 8, 100, 100)",
                params![VAULT_SCHEMA_VERSION + 1]
            )
            .is_err());
        assert_eq!(version(&conn), VAULT_SCHEMA_VERSION);
        assert_eq!(conn.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE name = 'idx_vault_meta_schema_version'",
            &[], |row| Ok(row.column_i64(0)),
        ).unwrap(), 0);
    }

    #[test]
    fn uninitialized_legacy_metadata_is_adopted_before_account_initialization() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.db");
        let key = SecretBox::init_with(|| [42; 32]);
        let old = Vault::open(&path, &key, |conn| {
            blobs::ensure_schema(conn)?;
            conn.execute_batch(include_str!("fixtures/v1.sql"))
        })
        .unwrap();
        drop(old);
        let vault = CredentialVault::new(&path, &key).unwrap();
        assert_eq!(version(vault.vault.connection()), VAULT_SCHEMA_VERSION);
        vault.init_leaf_index(7, 100).unwrap();
        assert!(matches!(
            vault.init_leaf_index(8, 200),
            Err(StorageError::InvalidLeafIndex { .. })
        ));
        assert!(vault
            .vault
            .connection()
            .execute(
                "INSERT INTO vault_meta VALUES (?1, 8, 100, 100)",
                params![VAULT_SCHEMA_VERSION + 1]
            )
            .is_err());
    }

    #[test]
    fn duplicate_legacy_metadata_fails_without_modifying_rows_or_indexes() {
        let conn = Connection::open(":memory:", false).unwrap();
        blobs::ensure_schema(&conn).unwrap();
        conn.execute_batch(include_str!("fixtures/v1.sql")).unwrap();
        conn.execute_batch(
            "INSERT INTO vault_meta VALUES (1, 7, 100, 100), (2, 8, 200, 200)",
        )
        .unwrap();
        assert!(ensure_schema(&conn).is_err());
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM vault_meta", &[], |row| Ok(
                row.column_i64(0)
            ))
            .unwrap(),
            2
        );
        assert!(!has_singleton_constraint(&conn).unwrap());
        assert_eq!(conn.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE name = 'idx_vault_meta_schema_version'",
            &[], |row| Ok(row.column_i64(0)),
        ).unwrap(), 1);
    }

    #[test]
    fn missing_metadata_row_fails_without_reinitializing_an_existing_vault() {
        let conn = Connection::open(":memory:", false).unwrap();
        ensure_schema(&conn).unwrap();
        conn.execute_batch("DELETE FROM vault_meta").unwrap();
        assert!(ensure_schema(&conn).is_err());
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM vault_meta", &[], |row| Ok(
                row.column_i64(0)
            ))
            .unwrap(),
            0
        );
    }

    #[test]
    fn current_schema_needs_no_write_lock() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.db");
        let key = SecretBox::init_with(|| [42; 32]);
        let vault = CredentialVault::new(&path, &key).unwrap();
        let second = cipher::open_encrypted(&path, &key).unwrap();
        let _writer = vault.vault.connection().transaction_immediate().unwrap();

        ensure_schema(&second).unwrap();
        second.execute_batch("PRAGMA query_only = ON").unwrap();
        ensure_schema(&second).unwrap();
        assert_eq!(version(&second), VAULT_SCHEMA_VERSION);
    }

    #[test]
    fn current_schema_with_missing_tables_fails_without_rebuilding() {
        for table in [
            "vault_meta",
            "credential_records",
            "blob_objects",
            "pcp_records",
        ] {
            let dir = tempfile::tempdir().unwrap();
            let key = SecretBox::init_with(|| [42; 32]);
            let vault =
                CredentialVault::new(&dir.path().join("vault.db"), &key).unwrap();
            let conn = vault.vault.connection();
            conn.execute_batch(&format!("DROP TABLE {table}")).unwrap();

            assert!(ensure_schema(conn).is_err(), "missing {table}");
            if table != "vault_meta" {
                assert_eq!(version(conn), VAULT_SCHEMA_VERSION);
            }
            assert!(conn.prepare(&format!("SELECT * FROM {table}")).is_err());
        }
    }

    #[test]
    fn legacy_v1_is_adopted_without_changing_data_or_blob_schema() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.db");
        let key = SecretBox::init_with(|| [42; 32]);
        let old = Vault::open(&path, &key, |conn| {
            blobs::ensure_schema(conn)?;
            conn.execute_batch(include_str!("fixtures/v1.sql"))?;
            conn.execute_batch("INSERT INTO vault_meta VALUES (1, 7, 100, 100)")
        })
        .unwrap();
        let cid = blobs::put(old.connection(), 1, b"credential", 100).unwrap();
        old.connection().execute(
            "INSERT INTO credential_records VALUES (1, 10, ?1, 100, 1000, 100, ?2, NULL)",
            walletkit_sqlite::params![vec![7_u8; 32], cid.as_slice()],
        ).unwrap();
        let blob_schema = old
            .connection()
            .query_row(
                "SELECT sql FROM sqlite_master WHERE name = 'blob_objects'",
                &[],
                |row| Ok(row.column_text(0)),
            )
            .unwrap();
        assert_eq!(version(old.connection()), 1);
        drop(old);
        let vault = CredentialVault::new(&path, &key).unwrap();
        let conn = vault.vault.connection();
        assert_eq!(version(conn), VAULT_SCHEMA_VERSION);
        assert_eq!(blobs::get(conn, &cid).unwrap().unwrap(), b"credential");
        assert_eq!(
            vault
                .fetch_credential_and_blinding_factor(10, 100)
                .unwrap()
                .unwrap(),
            (b"credential".to_vec(), vec![7; 32])
        );
        assert_eq!(
            conn.query_row(
                "SELECT leaf_index = 7 AND created_at = 100 FROM vault_meta",
                &[],
                |row| Ok(row.column_i64(0)),
            )
            .unwrap(),
            1
        );
        assert_eq!(
            conn.query_row(
                "SELECT sql FROM sqlite_master WHERE name = 'blob_objects'",
                &[],
                |row| Ok(row.column_text(0)),
            )
            .unwrap(),
            blob_schema
        );
    }

    #[test]
    fn unsupported_versions_fail_without_modifying_the_vault() {
        for marker in [
            "UPDATE vault_meta SET schema_version = 2147483647",
            "UPDATE vault_meta SET schema_version = -1",
            "UPDATE vault_meta SET schema_version = 'invalid'",
        ] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("vault.db");
            let key = SecretBox::init_with(|| [42; 32]);
            let vault = CredentialVault::new(&path, &key).unwrap();
            vault.init_leaf_index(7, 100).unwrap();
            let conn = vault.vault.connection();
            conn.execute_batch(marker).unwrap();
            let before = conn
                .query_row("SELECT schema_version FROM vault_meta", &[], |row| {
                    Ok(row.column_text(0))
                })
                .unwrap();
            conn.execute_batch("DROP TABLE blob_objects").unwrap();
            drop(vault);
            let err = CredentialVault::new(&path, &key).unwrap_err();
            assert!(matches!(err, StorageError::VaultDb(_)));
            assert!(err.to_string().contains("vault schema version"));
            let conn = cipher::open_encrypted(&path, &key).unwrap();
            assert_eq!(
                conn.query_row("SELECT schema_version FROM vault_meta", &[], |row| Ok(
                    row.column_text(0)
                ),)
                    .unwrap(),
                before
            );
            assert_eq!(
                conn.query_row(
                    "SELECT COUNT(*) FROM vault_meta WHERE leaf_index = 7",
                    &[],
                    |row| Ok(row.column_i64(0)),
                )
                .unwrap(),
                1
            );
            assert!(conn.prepare("SELECT * FROM blob_objects").is_err());
        }
    }

    #[test]
    fn failed_migration_rolls_back_ddl_and_version_then_retries() {
        fn fail(conn: &Connection) -> DbResult<()> {
            migration_test_local(conn)?;
            conn.execute_batch("INSERT INTO missing_table VALUES (1)")
        }
        let conn = Connection::open(":memory:", false).unwrap();
        ensure_schema(&conn).unwrap();
        let mut migrations = MIGRATIONS.to_vec();
        migrations.push(fail);
        assert!(migrate(&conn, &migrations).is_err());
        assert_eq!(version(&conn), VAULT_SCHEMA_VERSION);
        assert!(conn.prepare("SELECT * FROM local_only").is_err());
        *migrations.last_mut().unwrap() = migration_test_local;
        migrate(&conn, &migrations).unwrap();
        assert_eq!(version(&conn), VAULT_SCHEMA_VERSION + 1);
        migrate(&conn, &migrations).unwrap();
    }

    #[test]
    fn failed_version_update_rolls_back_migration_and_preserves_account() {
        let dir = tempfile::tempdir().unwrap();
        let key = SecretBox::init_with(|| [42; 32]);
        let vault = CredentialVault {
            vault: Vault::open(&dir.path().join("vault.db"), &key, |conn| {
                blobs::ensure_schema(conn)?;
                conn.execute_batch(include_str!("fixtures/v1.sql"))?;
                conn.execute_batch("INSERT INTO vault_meta VALUES (1, 7, 100, 100)")
            })
            .unwrap(),
        };
        let conn = vault.vault.connection();
        conn.execute_batch(
            "CREATE TRIGGER reject_version BEFORE UPDATE OF schema_version ON vault_meta
             BEGIN SELECT RAISE(ABORT, 'injected'); END;",
        ).unwrap();
        assert!(ensure_schema(conn).is_err());
        assert_eq!(version(conn), 1);
        assert!(!has_singleton_constraint(conn).unwrap());
        assert!(conn.query_row_optional(
            "SELECT 1 FROM sqlite_master WHERE name = 'idx_vault_meta_schema_version'", &[], |_| Ok(()),
        ).unwrap().is_some());
        vault.init_leaf_index(7, 200).unwrap();
        conn.execute_batch("DROP TRIGGER reject_version").unwrap();
        ensure_schema(conn).unwrap();
        assert_eq!(version(conn), VAULT_SCHEMA_VERSION);
        assert!(matches!(
            vault.init_leaf_index(8, 300),
            Err(StorageError::InvalidLeafIndex { .. })
        ));
    }

    #[test]
    fn concurrent_migrator_fails_busy_then_rechecks_committed_version() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.db");
        let key = SecretBox::init_with(|| [42; 32]);
        let first = cipher::open_encrypted(&path, &key).unwrap();
        ensure_schema(&first).unwrap();
        let second = cipher::open_encrypted(&path, &key).unwrap();
        let tx = first.transaction_immediate().unwrap();
        migration_test_local(&first).unwrap();
        let mut migrations = MIGRATIONS.to_vec();
        migrations.push(migration_test_local);
        record_version(&first, migrations.len()).unwrap();
        let error = migrate(&second, &migrations).unwrap_err();
        assert_eq!(error.code.0 & 0xff, 5); // SQLITE_BUSY
        tx.commit().unwrap();
        migrate(&second, &migrations).unwrap();
        assert_eq!(version(&second), VAULT_SCHEMA_VERSION + 1);
    }

    #[test]
    fn crash_during_migration_is_retried_on_next_open() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.db");
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "storage::credential_vault::schema::tests::crash_child",
            ])
            .env("WALLETKIT_MIGRATION_CRASH_DB", &path)
            .status()
            .unwrap();
        assert!(status.success());
        assert!(path.exists());
        let key = SecretBox::init_with(|| [42; 32]);
        let conn = cipher::open_encrypted(&path, &key).unwrap();
        assert!(schema_is_empty(&conn).unwrap());
        assert!(conn.prepare("SELECT * FROM vault_meta").is_err());
        drop(conn);
        let vault = CredentialVault::new(&path, &key).unwrap();
        assert_eq!(version(vault.vault.connection()), VAULT_SCHEMA_VERSION);
        vault.init_leaf_index(8, 200).unwrap();
    }

    #[test]
    fn crash_child() {
        let Some(path) = std::env::var_os("WALLETKIT_MIGRATION_CRASH_DB") else {
            return;
        };
        let key = SecretBox::init_with(|| [42; 32]);
        let conn = cipher::open_encrypted(std::path::Path::new(&path), &key).unwrap();
        let _tx = conn.transaction_immediate().unwrap();
        blobs::ensure_schema(&conn).unwrap();
        migration_v1(&conn).unwrap();
        conn.execute_batch("INSERT INTO vault_meta VALUES (1, 7, 100, 100)")
            .unwrap();
        std::process::exit(0);
    }

    #[test]
    fn old_backup_import_and_merge_preserve_newer_destination_version() {
        let dir = tempfile::tempdir().unwrap();
        let key = SecretBox::init_with(|| [42; 32]);
        let source = CredentialVault {
            vault: Vault::open(&dir.path().join("old.db"), &key, |conn| {
                blobs::ensure_schema(conn)?;
                conn.execute_batch(include_str!("fixtures/v1.sql"))
            })
            .unwrap(),
        };
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
        let bytes = std::fs::read(&backup).unwrap();
        for merge in [false, true] {
            let destination =
                CredentialVault::new(&dir.path().join(format!("new-{merge}.db")), &key)
                    .unwrap();
            destination.init_leaf_index(7, 100).unwrap();
            if merge {
                assert_eq!(destination.merge_plaintext_bytes(&bytes).unwrap(), 1);
            } else {
                destination.import_plaintext(&backup).unwrap();
            }
            assert_eq!(
                version(destination.vault.connection()),
                VAULT_SCHEMA_VERSION
            );
            assert_eq!(
                destination
                    .fetch_credential_and_blinding_factor(10, 100)
                    .unwrap()
                    .unwrap()
                    .0,
                b"credential"
            );
            destination.init_leaf_index(7, 200).unwrap();
            assert!(matches!(
                destination.init_leaf_index(8, 200),
                Err(StorageError::InvalidLeafIndex { .. })
            ));
        }
    }
}
