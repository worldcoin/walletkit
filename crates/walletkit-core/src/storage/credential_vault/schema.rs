//! Versioned credential-vault schema. The shared blob schema is owned by `walletkit-db`.

use walletkit_db::blobs;
use walletkit_sqlite::{
    error::ErrorCode, params, Connection, DbResult, Error, StepResult,
};

/// The vault migrations, in order. Append new versions; never change shipped migrations.
/// `vault_meta.vault_version` counts the applied migrations.
/// Migrations must not start transactions or modify the shared blob schema.
const MIGRATIONS: &[fn(&Connection) -> DbResult<()>] =
    &[migration_v1, migration_v2, migration_v3];

#[expect(
    clippy::cast_possible_wrap,
    reason = "the migration list cannot approach i64::MAX"
)]
const VAULT_VERSION: i64 = MIGRATIONS.len() as i64;

/// The oldest vault version whose code can use vaults written by this build.
/// Raise it only with a migration that older code cannot safely ignore.
/// Builds that predate `vault_version` never read it.
const MIN_VAULT_VERSION: i64 = 1;

/// Every vault keeps `vault_meta.schema_version` at 1. Builds that predate
/// `vault_version` find their metadata row by this value.
const LEGACY_SCHEMA_VERSION: i64 = 1;

/// The versions recorded in `vault_meta`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct StoredVersion {
    version: i64,
    min_version: i64,
}

/// Initializes the vault schema or applies pending migrations.
///
/// Existing vaults need no writes unless a schema or metadata upgrade is needed.
/// Upgrades run in one transaction and roll back if interrupted or unsuccessful.
/// A newer vault opens without migrating unless it requires a newer build.
/// Incomplete schemas return an error without resetting the vault.
///
/// Plaintext backups contain only [`super::BACKUP_TABLES`], excluding `vault_meta`.
/// Credential schema changes must preserve compatibility with older backups.
pub(super) fn ensure_schema(conn: &Connection) -> DbResult<()> {
    if schema_is_empty(conn)? {
        return migrate(conn, MIGRATIONS);
    }
    let Some(stored) = read_version(conn)? else {
        return migrate(conn, MIGRATIONS);
    };
    check_supported(stored, VAULT_VERSION)?;
    validate_schema(conn, stored.version)?;
    if stored.version > VAULT_VERSION {
        tracing::warn!(
            vault_version = stored.version,
            supported_version = VAULT_VERSION,
            "opening a newer vault without migrating it"
        );
    } else if stored.version < VAULT_VERSION {
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
    let version = if schema_is_empty(conn)? {
        0
    } else if let Some(stored) = read_version(conn)? {
        check_supported(stored, version_count(migrations)?)?;
        validate_schema(conn, stored.version)?;
        stored.version
    } else {
        validate_legacy_schema(conn)?;
        1
    };
    let applied =
        usize::try_from(version).map_err(|_| schema_error("invalid vault version"))?;
    if applied >= migrations.len() {
        return tx.commit();
    }

    blobs::ensure_schema(conn)?;
    for migration in migrations.iter().skip(applied) {
        migration(conn)?;
    }
    record_version(conn, version_count(migrations)?)?;
    tx.commit()
}

fn schema_is_empty(conn: &Connection) -> DbResult<bool> {
    conn.query_row(
        "SELECT NOT EXISTS(SELECT 1 FROM sqlite_master)",
        &[],
        |row| Ok(row.column_i64(0) != 0),
    )
}

fn version_count(migrations: &[fn(&Connection) -> DbResult<()>]) -> DbResult<i64> {
    i64::try_from(migrations.len()).map_err(|_| schema_error("invalid vault version"))
}

/// Rejects vaults that require a newer build than one supporting `supported`.
fn check_supported(stored: StoredVersion, supported: i64) -> DbResult<()> {
    if stored.min_version > supported {
        return Err(schema_error(format!(
            "vault requires vault version {}, newer than supported version {supported}; upgrade WalletKit",
            stored.min_version
        )));
    }
    Ok(())
}

/// Reads the stored versions, or `None` if the metadata table has no row.
/// Missing tables, duplicate rows and invalid versions return an error.
fn read_version(conn: &Connection) -> DbResult<Option<StoredVersion>> {
    if !has_column(conn, "vault_version")? {
        return read_legacy_version(conn);
    }
    let mut stmt = conn.prepare(
        "SELECT vault_version, typeof(vault_version), min_vault_version,
                typeof(min_vault_version), schema_version IS 1
         FROM vault_meta",
    )?;
    let (stored, valid) = match stmt.step()? {
        StepResult::Done => return Ok(None),
        StepResult::Row(row) => {
            let stored = StoredVersion {
                version: row.column_i64(0),
                min_version: row.column_i64(2),
            };
            let valid = row.column_text(1) == "integer"
                && row.column_text(3) == "integer"
                && row.column_i64(4) != 0
                && stored.min_version > 0
                && stored.min_version <= stored.version;
            (stored, valid)
        }
    };
    if matches!(stmt.step()?, StepResult::Row(_)) {
        return Err(schema_error("multiple vault metadata rows"));
    }
    if !valid {
        return Err(schema_error("invalid vault version"));
    }
    Ok(Some(stored))
}

/// Reads a vault without `vault_version`, which needs migration v2.
///
/// A `schema_version` of 2 with the single-row index was recorded by builds that kept
/// the version in `schema_version`; v2 restores the legacy metadata layout.
fn read_legacy_version(conn: &Connection) -> DbResult<Option<StoredVersion>> {
    // One statement, so a concurrent conversion cannot change the index between reads.
    let mut stmt = conn.prepare(
        "SELECT typeof(schema_version) = 'integer'
                AND (schema_version = 1
                     OR (schema_version = 2 AND EXISTS(
                         SELECT 1 FROM sqlite_master WHERE type = 'index'
                         AND tbl_name = 'vault_meta' AND name = 'idx_vault_meta_singleton')))
         FROM vault_meta",
    )?;
    let valid = match stmt.step()? {
        StepResult::Done => return Ok(None),
        StepResult::Row(row) => row.column_i64(0) != 0,
    };
    if matches!(stmt.step()?, StepResult::Row(_)) {
        return Err(schema_error("multiple vault metadata rows"));
    }
    if !valid {
        return Err(schema_error("invalid vault version"));
    }
    Ok(Some(StoredVersion {
        version: 1,
        min_version: 1,
    }))
}

/// Validates the tables and metadata layout required by the stored version.
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
    if version >= 2 && (!has_legacy_index(conn)? || has_singleton_constraint(conn)?) {
        return Err(schema_error("vault metadata constraint is missing"));
    }
    Ok(())
}

/// Recognizes v1 vaults whose account metadata has not been initialized yet.
fn validate_legacy_schema(conn: &Connection) -> DbResult<()> {
    validate_schema(conn, 1)?;
    if !has_legacy_index(conn)?
        || has_singleton_constraint(conn)?
        || has_column(conn, "vault_version")?
    {
        return Err(schema_error("vault metadata row is missing"));
    }
    Ok(())
}

fn has_column(conn: &Connection, column: &str) -> DbResult<bool> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_table_info('vault_meta') WHERE name = ?1)",
        params![column],
        |row| Ok(row.column_i64(0) != 0),
    )
}

fn has_legacy_index(conn: &Connection) -> DbResult<bool> {
    has_index(conn, "idx_vault_meta_schema_version")
}

fn has_singleton_constraint(conn: &Connection) -> DbResult<bool> {
    has_index(conn, "idx_vault_meta_singleton")
}

fn has_index(conn: &Connection, name: &str) -> DbResult<bool> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master
         WHERE type = 'index' AND tbl_name = 'vault_meta' AND name = ?1)",
        params![name],
        |row| Ok(row.column_i64(0) != 0),
    )
}

/// Records the vault versions without replacing account metadata or lowering them.
fn record_version(conn: &Connection, version: i64) -> DbResult<()> {
    let updated = conn.execute(
        "UPDATE vault_meta SET vault_version = MAX(vault_version, ?1),
             min_vault_version = MAX(min_vault_version, ?2)",
        params![version, MIN_VAULT_VERSION],
    )?;
    if updated == 0 {
        conn.execute(
            "INSERT INTO vault_meta (schema_version, leaf_index, created_at, updated_at,
                                     vault_version, min_vault_version)
             VALUES (?1, NULL, strftime('%s','now'), strftime('%s','now'), ?2, ?3)",
            params![LEGACY_SCHEMA_VERSION, version, MIN_VAULT_VERSION],
        )?;
    }
    Ok(())
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

/// Version 2: record the vault version in its own columns.
///
/// The unique `schema_version` index stays: builds that predate `vault_version`
/// upsert their metadata row on it, and it keeps the table to one row.
fn migration_v2(conn: &Connection) -> DbResult<()> {
    if has_singleton_constraint(conn)? {
        conn.execute_batch(
            "DROP INDEX idx_vault_meta_singleton;
             UPDATE vault_meta SET schema_version = 1;",
        )?;
    }
    conn.execute_batch(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_vault_meta_schema_version
         ON vault_meta (schema_version);",
    )?;
    for column in ["vault_version", "min_vault_version"] {
        if !has_column(conn, column)? {
            conn.execute_batch(&format!(
                "ALTER TABLE vault_meta ADD COLUMN {column} INTEGER NOT NULL DEFAULT 1;"
            ))?;
        }
    }
    Ok(())
}

/// Version 3: local PCP storage. PCPs are backed up separately under their own
/// designators, such as `orb_pkg`, so credential backups exclude them.
fn migration_v3(conn: &Connection) -> DbResult<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS pcp_records (
            id          TEXT PRIMARY KEY NOT NULL,
            kind        TEXT NOT NULL CHECK (length(kind) BETWEEN 1 AND 32),
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

    /// `CredentialVault::init_leaf_index` as shipped before `vault_version`.
    const PRE_VAULT_VERSION_INIT: &str =
        "INSERT INTO vault_meta (schema_version, leaf_index, created_at, updated_at)
         VALUES (1, ?1, 100, 100)
         ON CONFLICT(schema_version) DO UPDATE SET
             leaf_index = CASE
                 WHEN vault_meta.leaf_index IS NULL
                 THEN excluded.leaf_index
                 ELSE vault_meta.leaf_index
             END
         RETURNING leaf_index";

    fn version(conn: &Connection) -> i64 {
        read_version(conn).unwrap().unwrap().version
    }

    fn metadata(conn: &Connection) -> (i64, i64, i64, i64) {
        conn.query_row(
            "SELECT COUNT(*), MAX(schema_version), MAX(vault_version), MAX(min_vault_version)
             FROM vault_meta",
            &[],
            |row| {
                Ok((
                    row.column_i64(0),
                    row.column_i64(1),
                    row.column_i64(2),
                    row.column_i64(3),
                ))
            },
        )
        .unwrap()
    }

    fn v1_vault(path: &std::path::Path, key: &SecretBox<[u8; 32]>, row: &str) {
        let old = Vault::open(path, key, |conn| {
            blobs::ensure_schema(conn)?;
            conn.execute_batch(include_str!("fixtures/v1.sql"))?;
            conn.execute_batch(row)
        })
        .unwrap();
        drop(old);
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
    fn v2_vault_upgrades_to_v3_without_changing_the_account() {
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
        assert!(vault.pcps().list(None).unwrap().is_empty());
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
        assert_eq!(version(&conn), 1);
        conn.execute_batch("INSERT INTO vault_meta VALUES (1)")
            .unwrap();
        assert!(read_version(&conn).is_err());
    }

    #[test]
    fn version_reader_rejects_invalid_sqlite_values() {
        for value in [
            "NULL",
            "0",
            "-1",
            "1.5",
            "2",
            "3",
            "'invalid'",
            "'1'",
            "x'31'",
        ] {
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
                assert_eq!(
                    read_version(&conn).unwrap().map(|stored| stored.version),
                    initialized.then_some(1)
                );
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
        assert_eq!(version(&second), VAULT_VERSION);
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
        conn.execute_batch("DROP INDEX idx_vault_meta_schema_version")
            .unwrap();
        assert!(ensure_schema(&conn).is_err());
        assert_eq!(version(&conn), VAULT_VERSION);
        assert!(!has_legacy_index(&conn).unwrap());
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
        assert_eq!(version(vault.vault.connection()), VAULT_VERSION);
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
                blobs::ensure_schema(conn)?;
                conn.execute_batch(include_str!("fixtures/v1.sql"))?;
                conn.execute_batch("INSERT INTO vault_meta VALUES (1, NULL, 100, 100)")
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
        assert_eq!(metadata(conn), (1, 1, VAULT_VERSION, MIN_VAULT_VERSION));
        assert_eq!(
            conn.query_row(
                "SELECT leaf_index, created_at FROM vault_meta",
                &[],
                |row| { Ok((row.column_i64(0), row.column_i64(1))) }
            )
            .unwrap(),
            (7, created_at)
        );
    }

    #[test]
    fn metadata_constraint_rejects_a_second_row() {
        let conn = Connection::open(":memory:", false).unwrap();
        ensure_schema(&conn).unwrap();
        assert!(conn
            .execute_batch("INSERT INTO vault_meta VALUES (1, 8, 100, 100, 1, 1)")
            .is_err());
        assert_eq!(metadata(&conn), (1, 1, VAULT_VERSION, MIN_VAULT_VERSION));
        assert!(!has_singleton_constraint(&conn).unwrap());
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
        assert_eq!(version(vault.vault.connection()), VAULT_VERSION);
        vault.init_leaf_index(7, 100).unwrap();
        assert!(matches!(
            vault.init_leaf_index(8, 200),
            Err(StorageError::InvalidLeafIndex { .. })
        ));
        assert!(vault
            .vault
            .connection()
            .execute_batch("INSERT INTO vault_meta VALUES (1, 8, 100, 100, 1, 1)")
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
        assert_eq!(version(&second), VAULT_VERSION);
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
                assert_eq!(version(conn), VAULT_VERSION);
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
        assert_eq!(version(conn), VAULT_VERSION);
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
            "UPDATE vault_meta SET min_vault_version = 2147483647, vault_version = 2147483647",
            "UPDATE vault_meta SET vault_version = -1",
            "UPDATE vault_meta SET vault_version = 'invalid'",
            "UPDATE vault_meta SET min_vault_version = 0",
            "UPDATE vault_meta SET min_vault_version = vault_version + 1",
            "UPDATE vault_meta SET schema_version = 2",
        ] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("vault.db");
            let key = SecretBox::init_with(|| [42; 32]);
            let vault = CredentialVault::new(&path, &key).unwrap();
            vault.init_leaf_index(7, 100).unwrap();
            let conn = vault.vault.connection();
            conn.execute_batch(marker).unwrap();
            let before = conn
                .query_row(
                    "SELECT quote(schema_version) || quote(vault_version) || quote(min_vault_version)
                     FROM vault_meta",
                    &[],
                    |row| Ok(row.column_text(0)),
                )
                .unwrap();
            conn.execute_batch("DROP TABLE blob_objects").unwrap();
            drop(vault);
            let err = CredentialVault::new(&path, &key).unwrap_err();
            assert!(matches!(err, StorageError::VaultDb(_)));
            assert!(err.to_string().contains("vault version"), "{marker}: {err}");
            let conn = cipher::open_encrypted(&path, &key).unwrap();
            assert_eq!(
                conn.query_row(
                    "SELECT quote(schema_version) || quote(vault_version) || quote(min_vault_version)
                     FROM vault_meta",
                    &[],
                    |row| Ok(row.column_text(0)),
                )
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
        assert_eq!(version(&conn), VAULT_VERSION);
        assert!(conn.prepare("SELECT * FROM local_only").is_err());
        *migrations.last_mut().unwrap() = migration_test_local;
        migrate(&conn, &migrations).unwrap();
        assert_eq!(version(&conn), VAULT_VERSION + 1);
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
            "CREATE TRIGGER reject_version BEFORE UPDATE ON vault_meta
             BEGIN SELECT RAISE(ABORT, 'injected'); END;",
        )
        .unwrap();
        assert!(ensure_schema(conn).is_err());
        assert_eq!(version(conn), 1);
        assert!(!has_column(conn, "vault_version").unwrap());
        assert!(has_legacy_index(conn).unwrap());
        vault.init_leaf_index(7, 200).unwrap();
        conn.execute_batch("DROP TRIGGER reject_version").unwrap();
        ensure_schema(conn).unwrap();
        assert_eq!(version(conn), VAULT_VERSION);
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
        record_version(&first, version_count(&migrations).unwrap()).unwrap();
        let error = migrate(&second, &migrations).unwrap_err();
        assert_eq!(error.code.0 & 0xff, 5); // SQLITE_BUSY
        tx.commit().unwrap();
        migrate(&second, &migrations).unwrap();
        assert_eq!(version(&second), VAULT_VERSION + 1);
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
        assert_eq!(version(vault.vault.connection()), VAULT_VERSION);
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
            assert_eq!(version(destination.vault.connection()), VAULT_VERSION);
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

    #[test]
    fn builds_before_vault_version_reopen_migrated_vaults() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.db");
        let key = SecretBox::init_with(|| [42; 32]);
        v1_vault(
            &path,
            &key,
            "INSERT INTO vault_meta VALUES (1, 7, 100, 100)",
        );
        let vault = CredentialVault::new(&path, &key).unwrap();
        vault.init_leaf_index(7, 200).unwrap();
        drop(vault);

        let old = cipher::open_encrypted(&path, &key).unwrap();
        blobs::ensure_schema(&old).unwrap();
        old.execute_batch(include_str!("fixtures/v1.sql")).unwrap();
        for provided in [7, 8] {
            let stored = old
                .query_row(PRE_VAULT_VERSION_INIT, params![provided], |row| {
                    Ok(row.column_i64(0))
                })
                .unwrap();
            assert_eq!(stored, 7);
        }
        assert_eq!(metadata(&old), (1, 1, VAULT_VERSION, MIN_VAULT_VERSION));
        drop(old);

        let vault = CredentialVault::new(&path, &key).unwrap();
        vault.init_leaf_index(7, 300).unwrap();
        assert!(matches!(
            vault.init_leaf_index(8, 300),
            Err(StorageError::InvalidLeafIndex { .. })
        ));
    }

    #[test]
    fn newer_compatible_vault_opens_without_migrating() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.db");
        let key = SecretBox::init_with(|| [42; 32]);
        let vault = CredentialVault::new(&path, &key).unwrap();
        vault.init_leaf_index(7, 100).unwrap();
        vault
            .vault
            .connection()
            .execute_batch(
                "UPDATE vault_meta SET vault_version = vault_version + 5;
                 CREATE TABLE newer_only (value INTEGER);",
            )
            .unwrap();
        drop(vault);

        let vault = CredentialVault::new(&path, &key).unwrap();
        vault.init_leaf_index(7, 200).unwrap();
        let conn = vault.vault.connection();
        assert_eq!(metadata(conn), (1, 1, VAULT_VERSION + 5, MIN_VAULT_VERSION));
        assert!(conn.prepare("SELECT * FROM newer_only").is_ok());
    }

    #[test]
    fn version_kept_in_schema_version_is_converted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.db");
        let key = SecretBox::init_with(|| [42; 32]);
        v1_vault(
            &path,
            &key,
            "INSERT INTO vault_meta VALUES (2, 7, 100, 100);
             DROP INDEX idx_vault_meta_schema_version;
             CREATE UNIQUE INDEX idx_vault_meta_singleton ON vault_meta ((1));",
        );
        let vault = CredentialVault::new(&path, &key).unwrap();
        let conn = vault.vault.connection();
        assert_eq!(metadata(conn), (1, 1, VAULT_VERSION, MIN_VAULT_VERSION));
        assert!(has_legacy_index(conn).unwrap());
        assert!(!has_singleton_constraint(conn).unwrap());
        vault.init_leaf_index(7, 200).unwrap();
        assert!(matches!(
            vault.init_leaf_index(8, 200),
            Err(StorageError::InvalidLeafIndex { .. })
        ));
        for provided in [7, 8] {
            let stored = conn
                .query_row(PRE_VAULT_VERSION_INIT, params![provided], |row| {
                    Ok(row.column_i64(0))
                })
                .unwrap();
            assert_eq!(stored, 7);
        }
        assert_eq!(metadata(conn), (1, 1, VAULT_VERSION, MIN_VAULT_VERSION));
    }

    #[test]
    fn stale_version_with_existing_columns_reapplies_migrations() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.db");
        let key = SecretBox::init_with(|| [42; 32]);
        let vault = CredentialVault::new(&path, &key).unwrap();
        vault.init_leaf_index(7, 100).unwrap();
        vault
            .vault
            .connection()
            .execute_batch("UPDATE vault_meta SET vault_version = 1")
            .unwrap();
        drop(vault);

        let vault = CredentialVault::new(&path, &key).unwrap();
        assert_eq!(
            metadata(vault.vault.connection()),
            (1, 1, VAULT_VERSION, MIN_VAULT_VERSION)
        );
        vault.init_leaf_index(7, 200).unwrap();
    }
}
