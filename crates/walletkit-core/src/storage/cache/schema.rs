//! Cache database schema management.
//!
//! A table for storing cachable data. Each row has a key (`key_bytes`),
//! value (`value_bytes`) and TTL columns (see `ensure_entries_schema` for details).
//!
//! The keys adhere to the following schema:
//!
//! - `0x01` — Merkle inclusion proof; at most one entry; value is the proof bytes.
//! - `0x02 || oprf_seed` — session seed; value is the `session_id_r_seed`.
//! - `0x03 || nullifier` — replay guard; value is a presence marker.

pub(super) const CACHE_KEY_PREFIX_MERKLE: u8 = 0x01;
pub(super) const CACHE_KEY_PREFIX_SESSION: u8 = 0x02;
pub(super) const CACHE_KEY_PREFIX_REPLAY_NULLIFIER: u8 = 0x03;

use walletkit_db::{params, Connection, DbResult};

const CACHE_SCHEMA_VERSION: i64 = 2;
#[allow(
    clippy::cast_possible_wrap,
    reason = "the migration list cannot approach i64::MAX"
)]
const ACTIVITY_SCHEMA_VERSION: i64 = ACTIVITY_MIGRATIONS.len() as i64;

/// Ensures the cache schema is present and at the expected version.
///
/// # Errors
///
/// Returns an error if schema creation or migration fails.
pub(super) fn ensure_schema(conn: &Connection) -> DbResult<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS cache_meta (
            schema_version  INTEGER NOT NULL,
            created_at      INTEGER NOT NULL,
            updated_at      INTEGER NOT NULL
        );",
    )?;

    let existing = conn.query_row_optional(
        "SELECT schema_version FROM cache_meta LIMIT 1;",
        &[],
        |stmt| Ok(stmt.column_i64(0)),
    )?;

    match existing {
        Some(version) if version == CACHE_SCHEMA_VERSION => {
            ensure_entries_schema(conn)?;
        }
        Some(_) => {
            reset_cache_schema(conn)?;
        }
        None => {
            ensure_entries_schema(conn)?;
            insert_meta(conn)?;
        }
    }

    ensure_activity_schema(conn)?;

    Ok(())
}

fn ensure_entries_schema(conn: &Connection) -> DbResult<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS cache_entries (
            key_bytes       BLOB    NOT NULL,
            value_bytes     BLOB    NOT NULL,
            inserted_at     INTEGER NOT NULL,
            expires_at      INTEGER NOT NULL,
            PRIMARY KEY (key_bytes)
        );

        CREATE INDEX IF NOT EXISTS idx_cache_entries_expiry
        ON cache_entries (expires_at);",
    )
}

fn reset_cache_schema(conn: &Connection) -> DbResult<()> {
    conn.execute_batch(
        "DROP TABLE IF EXISTS used_nullifiers;
         DROP TABLE IF EXISTS merkle_proof_cache;
         DROP TABLE IF EXISTS session_keys;
         DROP TABLE IF EXISTS cache_entries;",
    )?;
    // Activity history is intentionally preserved here; it is versioned separately.
    ensure_entries_schema(conn)?;
    conn.execute("DELETE FROM cache_meta;", &[])?;
    insert_meta(conn)?;
    Ok(())
}

fn insert_meta(conn: &Connection) -> DbResult<()> {
    conn.execute(
        "INSERT INTO cache_meta (schema_version, created_at, updated_at)
         VALUES (?1, strftime('%s','now'), strftime('%s','now'))",
        params![CACHE_SCHEMA_VERSION],
    )?;
    Ok(())
}

/// The activity-history migrations, in order.
///
/// A database's version is the number of these it has had applied, so adding a new
/// schema version means writing an `activity_migration_vN` function and appending it
/// here — nothing else needs to change.
const ACTIVITY_MIGRATIONS: &[fn(&Connection) -> DbResult<()>] =
    &[activity_migration_v1];

/// Creates the activity-history table.
///
/// The table is dropped first so that a database written before activity history was
/// versioned is rebuilt rather than left with the wrong columns. That drop is a no-op
/// on a fresh install.
fn activity_migration_v1(conn: &Connection) -> DbResult<()> {
    conn.execute_batch(
        "DROP TABLE IF EXISTS activity_entries;

        CREATE TABLE activity_entries (
            entry_id           INTEGER PRIMARY KEY,
            client_id          TEXT NOT NULL,
            protocol           INTEGER NOT NULL,
            created_at         INTEGER NOT NULL,
            outcome            TEXT NOT NULL,
            rp_id              INTEGER NOT NULL,
            app_identifier     TEXT NOT NULL,
            issuer_schema_ids  BLOB NOT NULL,
            failure_reason     TEXT NOT NULL
        );

        CREATE INDEX idx_activity_entries_created_at
        ON activity_entries (created_at DESC);",
    )
}

/// Applies any activity-history migrations this database has not seen yet.
///
/// Activity history is versioned independently of the cache tables so that
/// [`reset_cache_schema`] never discards it.
///
/// # Errors
///
/// Returns an error if a migration step fails.
pub(super) fn ensure_activity_schema(conn: &Connection) -> DbResult<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS activity_meta (
            schema_version  INTEGER NOT NULL,
            created_at      INTEGER NOT NULL,
            updated_at      INTEGER NOT NULL
        );",
    )?;

    let recorded = conn.query_row_optional(
        "SELECT schema_version FROM activity_meta LIMIT 1;",
        &[],
        |stmt| Ok(stmt.column_i64(0)),
    )?;

    let applied = usize::try_from(recorded.unwrap_or(0)).unwrap_or(0);
    for migration in ACTIVITY_MIGRATIONS.iter().skip(applied) {
        migration(conn)?;
    }

    if recorded.is_none() {
        insert_activity_meta(conn)
    } else if recorded == Some(ACTIVITY_SCHEMA_VERSION) {
        Ok(())
    } else {
        update_activity_version(conn)
    }
}

fn insert_activity_meta(conn: &Connection) -> DbResult<()> {
    conn.execute(
        "INSERT INTO activity_meta (schema_version, created_at, updated_at)
         VALUES (?1, strftime('%s','now'), strftime('%s','now'))",
        params![ACTIVITY_SCHEMA_VERSION],
    )?;
    Ok(())
}

fn update_activity_version(conn: &Connection) -> DbResult<()> {
    conn.execute(
        "UPDATE activity_meta
         SET schema_version = ?1, updated_at = strftime('%s','now')",
        params![ACTIVITY_SCHEMA_VERSION],
    )?;
    Ok(())
}
