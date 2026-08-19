//! Credential-activity schema management and migrations.
//!
//! Activity history uses a numbered migration runner: a bootstrap `schema_migrations`
//! table plus sequential migration functions, each applied and recorded in
//! order.

use walletkit_db::{params, Connection, DbResult};

type Migration = fn(&Connection) -> DbResult<()>;

/// Migrations in order. Add new entries at the end; never reorder or remove
/// existing ones — `version` numbers are persisted in `schema_migrations` and
/// must remain stable across releases.
const MIGRATIONS: &[(i64, Migration)] = &[(1, migration_1)];

/// Ensures the credential-activity schema is present and applies any pending
/// migrations.
///
/// Returns `(version_before, version_after)` so callers can detect whether
/// any migration actually ran and report it to the schema-migrated listener.
///
/// # Errors
///
/// Returns an error if the bootstrap table, a migration, or the version
/// bookkeeping fails.
pub(super) fn perform_migrations(conn: &Connection) -> DbResult<(i64, i64)> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_migrations (
            version     INTEGER PRIMARY KEY,
            applied_at  INTEGER NOT NULL
        );",
    )?;

    // Reading `current` and applying pending migrations happens in one
    // transaction so two callers racing `open_or_rebuild` on the same file
    // can't both read the same `current` and both attempt to apply (and
    // insert a schema_migrations row for) the same migration.
    let tx = conn.transaction()?;

    let current = tx.query_row(
        "SELECT COALESCE(MAX(version), 0) FROM schema_migrations;",
        &[],
        |stmt| Ok(stmt.column_i64(0)),
    )?;

    let mut version = current;
    for (target_version, migration) in MIGRATIONS {
        if *target_version <= current {
            continue;
        }

        migration(conn)?;

        tx.execute(
            "INSERT INTO schema_migrations (version, applied_at)
             VALUES (?1, strftime('%s','now'))",
            params![*target_version],
        )?;

        version = *target_version;
    }

    tx.commit()?;
    Ok((current, version))
}

fn migration_1(conn: &Connection) -> DbResult<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS activity_entries (
            entry_id        INTEGER PRIMARY KEY,
            client_id       TEXT NOT NULL,
            request_id      TEXT NULL,
            protocol        TEXT NOT NULL,
            created_at      INTEGER NOT NULL,
            updated_at      INTEGER NOT NULL,
            outcome         TEXT NULL,
            app_identifier  TEXT NOT NULL,
            failure_reason  INTEGER NULL
        );

        CREATE INDEX IF NOT EXISTS idx_activity_entries_created_at
        ON activity_entries (created_at DESC);

        CREATE INDEX IF NOT EXISTS idx_activity_entries_client_id
        ON activity_entries (client_id);

        CREATE TABLE IF NOT EXISTS activity_credentials (
            id                 INTEGER PRIMARY KEY,
            entry_id           INTEGER NOT NULL REFERENCES activity_entries(entry_id) ON DELETE CASCADE,
            credential_type    INTEGER NOT NULL,
            credential_source  INTEGER NOT NULL,
            proof_kind         INTEGER NOT NULL,
            issuer_schema_id   INTEGER NULL,
            credential_id      INTEGER NULL
        );

        CREATE INDEX IF NOT EXISTS idx_activity_credentials_entry_id
        ON activity_credentials (entry_id);

        CREATE INDEX IF NOT EXISTS idx_activity_credentials_credential_type
        ON activity_credentials (credential_type, entry_id);

        CREATE INDEX IF NOT EXISTS idx_activity_entries_outcome
        ON activity_entries (outcome);",
    )
}
