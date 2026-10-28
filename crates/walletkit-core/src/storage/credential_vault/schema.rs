//! Versioned credential-vault schema. The shared blob schema is owned by `walletkit-db`.

use walletkit_db::blobs;
use walletkit_sqlite::{error::ErrorCode, Connection, DbResult, Error};

// This column is a fixed metadata key, independent of the database schema version.
pub(super) const VAULT_META_KEY: i64 = 1;

/// The vault migrations, in order. Append new versions; never change shipped migrations.
/// `PRAGMA user_version` counts the applied migrations.
/// Migrations must not start transactions or modify the shared blob schema.
const MIGRATIONS: &[fn(&Connection) -> DbResult<()>] = &[migration_v1, migration_v2];

#[allow(
    clippy::cast_possible_wrap,
    reason = "the migration list cannot approach i64::MAX"
)]
const SCHEMA_VERSION: i64 = MIGRATIONS.len() as i64;

/// Ensures the vault schema is present and at the expected version.
///
/// Current vaults are checked without a write transaction. Pending migrations
/// and their version marker commit together; interrupted migrations roll back.
/// A newer or incomplete vault returns an error without resetting its data.
///
/// Plaintext backups contain only [`super::BACKUP_TABLES`], not `user_version`.
/// New credential columns require backward-compatible import and merge queries.
pub(super) fn ensure_schema(conn: &Connection) -> DbResult<()> {
    match read_version(conn)? {
        version if version == SCHEMA_VERSION => {
            if !schema_is_intact(conn)? {
                return Err(schema_error("vault schema is incomplete"));
            }
        }
        version if version < SCHEMA_VERSION => {
            migrate(conn, MIGRATIONS)?;
        }
        version => {
            return Err(newer_schema_error(version, MIGRATIONS.len()));
        }
    }
    Ok(())
}

/// Applies pending migrations and records the version in the same transaction.
fn migrate(
    conn: &Connection,
    migrations: &[fn(&Connection) -> DbResult<()>],
) -> DbResult<()> {
    let tx = conn.transaction_immediate()?;
    // Recheck after taking the write lock: another opener may have migrated first.
    let version = read_version(conn)?;
    let applied = usize::try_from(version)
        .map_err(|_| schema_error("invalid vault schema version"))?;
    if applied > migrations.len() {
        return Err(newer_schema_error(version, migrations.len()));
    }
    if applied == migrations.len() {
        return tx.commit();
    }

    if version == 0 {
        validate_legacy_schema(conn)?;
    }

    blobs::ensure_schema(conn)?;
    for migration in migrations.iter().skip(applied) {
        migration(conn)?;
    }
    record_version(conn, migrations.len())?;
    tx.commit()
}

fn read_version(conn: &Connection) -> DbResult<i64> {
    let version =
        conn.query_row("PRAGMA user_version", &[], |row| Ok(row.column_i64(0)))?;
    if version < 0 {
        return Err(schema_error("invalid vault schema version"));
    }
    Ok(version)
}

/// Checks that the tables a current vault must have are present.
fn schema_is_intact(conn: &Connection) -> DbResult<bool> {
    let present = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master
         WHERE type = 'table'
           AND name IN ('vault_meta', 'credential_records', 'blob_objects');",
        &[],
        |row| Ok(row.column_i64(0)),
    )?;
    Ok(present == 3)
}

fn validate_legacy_schema(conn: &Connection) -> DbResult<()> {
    let has_meta = conn
        .query_row_optional(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'vault_meta'",
            &[],
            |_| Ok(()),
        )?
        .is_some();
    if !has_meta {
        return Ok(());
    }
    let invalid = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM vault_meta
         WHERE schema_version != 1 OR typeof(schema_version) != 'integer')",
        &[],
        |row| Ok(row.column_i64(0) != 0),
    )?;
    if invalid {
        return Err(schema_error(
            "unsupported legacy vault schema version; upgrade WalletKit",
        ));
    }
    Ok(())
}

fn record_version(conn: &Connection, version: usize) -> DbResult<()> {
    conn.execute_batch(&format!("PRAGMA user_version = {version}"))
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

/// Version 1: the credential tables and fixed-key account metadata.
fn migration_v1(conn: &Connection) -> DbResult<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS vault_meta (
            schema_version  INTEGER NOT NULL,
            leaf_index      INTEGER,
            created_at      INTEGER NOT NULL,
            updated_at      INTEGER NOT NULL
        );

        CREATE UNIQUE INDEX IF NOT EXISTS idx_vault_meta_schema_version
        ON vault_meta (schema_version);

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

/// Version 2: local PCP storage, deliberately excluded from credential backups.
fn migration_v2(conn: &Connection) -> DbResult<()> {
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
        conn.query_row("PRAGMA user_version", &[], |row| Ok(row.column_i64(0)))
            .unwrap()
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
    fn fresh_vault_records_version_and_reopens_idempotently() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.db");
        let key = SecretBox::init_with(|| [42; 32]);
        let vault = CredentialVault::new(&path, &key).unwrap();
        assert_eq!(version(vault.vault.connection()), 2);
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
        assert_eq!(version(&second), SCHEMA_VERSION);
    }

    #[test]
    fn current_schema_with_missing_tables_fails_without_rebuilding() {
        for table in ["vault_meta", "credential_records", "blob_objects"] {
            let dir = tempfile::tempdir().unwrap();
            let key = SecretBox::init_with(|| [42; 32]);
            let vault =
                CredentialVault::new(&dir.path().join("vault.db"), &key).unwrap();
            let conn = vault.vault.connection();
            conn.execute_batch(&format!("DROP TABLE {table}")).unwrap();

            assert!(ensure_schema(conn).is_err(), "missing {table}");
            assert_eq!(version(conn), SCHEMA_VERSION);
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
        assert_eq!(version(old.connection()), 0);
        drop(old);
        let vault = CredentialVault::new(&path, &key).unwrap();
        let conn = vault.vault.connection();
        assert_eq!(version(conn), 2);
        assert_eq!(blobs::get(conn, &cid).unwrap().unwrap(), b"credential");
        assert_eq!(
            vault
                .fetch_credential_and_blinding_factor(10, 100)
                .unwrap()
                .unwrap(),
            (b"credential".to_vec(), vec![7; 32])
        );
        assert_eq!(conn.query_row(
            "SELECT leaf_index = 7 AND created_at = 100 AND updated_at = 100 FROM vault_meta",
            &[], |row| Ok(row.column_i64(0)),
        ).unwrap(), 1);
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
            "PRAGMA user_version = 2147483647",
            "PRAGMA user_version = -1",
            "UPDATE vault_meta SET schema_version = 2; PRAGMA user_version = 0",
        ] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("vault.db");
            let key = SecretBox::init_with(|| [42; 32]);
            let vault = CredentialVault::new(&path, &key).unwrap();
            vault.init_leaf_index(7, 100).unwrap();
            let conn = vault.vault.connection();
            conn.execute_batch(marker).unwrap();
            let before = version(conn);
            conn.execute_batch("DROP TABLE blob_objects").unwrap();
            drop(vault);
            let err = CredentialVault::new(&path, &key).unwrap_err();
            assert!(matches!(err, StorageError::VaultDb(_)));
            assert!(err.to_string().contains("vault schema version"));
            let conn = cipher::open_encrypted(&path, &key).unwrap();
            assert_eq!(version(&conn), before);
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
        migrate(&conn, &[migration_v1]).unwrap();
        assert!(migrate(&conn, &[migration_v1, fail]).is_err());
        assert_eq!(version(&conn), 1);
        assert!(conn.prepare("SELECT * FROM local_only").is_err());
        migrate(&conn, &[migration_v1, migration_test_local]).unwrap();
        assert_eq!(version(&conn), 2);
        migrate(&conn, &[migration_v1, migration_test_local]).unwrap();
    }

    #[test]
    fn concurrent_migrator_fails_busy_then_rechecks_committed_version() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.db");
        let key = SecretBox::init_with(|| [42; 32]);
        let first = cipher::open_encrypted(&path, &key).unwrap();
        migrate(&first, &[migration_v1]).unwrap();
        let second = cipher::open_encrypted(&path, &key).unwrap();
        let tx = first.transaction_immediate().unwrap();
        migration_test_local(&first).unwrap();
        tx.execute_batch("PRAGMA user_version = 2").unwrap();
        let error =
            migrate(&second, &[migration_v1, migration_test_local]).unwrap_err();
        assert_eq!(error.code.0 & 0xff, 5); // SQLITE_BUSY
        tx.commit().unwrap();
        migrate(&second, &[migration_v1, migration_test_local]).unwrap();
        assert_eq!(version(&second), 2);
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
        assert_eq!(version(&conn), 0);
        assert!(conn.prepare("SELECT * FROM vault_meta").is_err());
        drop(conn);
        let vault = CredentialVault::new(&path, &key).unwrap();
        assert_eq!(version(vault.vault.connection()), 2);
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
        conn.execute_batch(
            "INSERT INTO vault_meta VALUES (1, 7, 100, 100); PRAGMA user_version = 1",
        )
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
            assert_eq!(version(destination.vault.connection()), 2);
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
