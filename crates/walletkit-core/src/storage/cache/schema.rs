//! Cache database schema management.
//!
//! The schema is versioned as a whole: a database's version is the number of
//! [`MIGRATIONS`] that have been applied. Activity history lives in this same
//! schema rather than carrying its own metadata table, so the disposable cache
//! tables and the activity history always migrate (and reset) together.
//!
//! The cache table stores cachable data. Each row has a key (`key_bytes`),
//! value (`value_bytes`) and TTL columns (see [`migration_v1`] for details).
//!
//! The keys adhere to the following schema:
//!
//! - Merkle Inclusion Proof: `0x01`; at most one entry; value is the proof bytes.
//! - Session Seeds: `0x02 || rp_id (8-byte big-endian) || oprf_seed`; value is the `session_id_r_seed`.
//! - Nullifier Replay Guards: `0x03 || nullifier`; value is a presence marker.

pub(super) const CACHE_KEY_PREFIX_MERKLE: u8 = 0x01;
pub(super) const CACHE_KEY_PREFIX_SESSION: u8 = 0x02;
pub(super) const CACHE_KEY_PREFIX_REPLAY_NULLIFIER: u8 = 0x03;

use walletkit_sqlite::{params, Connection, DbResult};

/// The cache-database migrations, in order.
///
/// A database's schema version is the number of these that have been applied, so
/// adding a new version means writing a `migration_vN` function and appending it
/// here — nothing else needs to change.
const MIGRATIONS: &[fn(&Connection) -> DbResult<()>] =
    &[migration_v1, migration_v2, migration_v3];

#[allow(
    clippy::cast_possible_wrap,
    reason = "the migration list cannot approach i64::MAX"
)]
const SCHEMA_VERSION: i64 = MIGRATIONS.len() as i64;

/// Ensures the cache schema is present and at the expected version.
///
/// Migrations are applied when the recorded version is behind [`SCHEMA_VERSION`].
/// A database recorded as anything newer than this build cannot be downgraded, so
/// it is reset instead of migrated.
///
/// # Errors
///
/// Returns an error if schema creation, migration, or reset fails.
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
        Some(version) if version == SCHEMA_VERSION => {
            // Already current: only verify the metadata is telling the truth.
            if !schema_is_intact(conn)? {
                reset_schema(conn)?;
            }
        }
        Some(version) if version < SCHEMA_VERSION => {
            migrate(conn, version)?;
        }
        // A version we do not recognise — including one written by a newer
        // build — cannot be trusted, so start from a clean slate.
        Some(_) => {
            reset_schema(conn)?;
        }
        None => {
            migrate(conn, 0)?;
        }
    }

    Ok(())
}

/// Applies every migration after `from` and records the new version.
fn migrate(conn: &Connection, from: i64) -> DbResult<()> {
    let applied = usize::try_from(from).unwrap_or(0);
    for migration in MIGRATIONS.iter().skip(applied) {
        migration(conn)?;
    }
    record_version(conn)
}

/// Drops every managed table and rebuilds the schema from scratch.
fn reset_schema(conn: &Connection) -> DbResult<()> {
    conn.execute_batch(
        "DROP TABLE IF EXISTS used_nullifiers;
         DROP TABLE IF EXISTS merkle_proof_cache;
         DROP TABLE IF EXISTS session_keys;
         DROP TABLE IF EXISTS activity_entries;
         DROP TABLE IF EXISTS cache_entries;",
    )?;
    migrate(conn, 0)
}

/// Checks that the tables a current database must have are present.
///
/// This catches a database whose metadata claims to be current but whose tables
/// went missing.
fn schema_is_intact(conn: &Connection) -> DbResult<bool> {
    let present = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master
         WHERE type = 'table' AND name IN ('cache_entries', 'activity_entries');",
        &[],
        |stmt| Ok(stmt.column_i64(0)),
    )?;
    Ok(present == 2)
}

/// Records the current schema version, preserving the original `created_at`.
fn record_version(conn: &Connection) -> DbResult<()> {
    let updated = conn.execute(
        "UPDATE cache_meta
         SET schema_version = ?1, updated_at = strftime('%s','now')",
        params![SCHEMA_VERSION],
    )?;
    if updated == 0 {
        conn.execute(
            "INSERT INTO cache_meta (schema_version, created_at, updated_at)
             VALUES (?1, strftime('%s','now'), strftime('%s','now'))",
            params![SCHEMA_VERSION],
        )?;
    }
    Ok(())
}

/// Migration 1: creates the disposable key/value cache table.
fn migration_v1(conn: &Connection) -> DbResult<()> {
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

/// Migration 2: creates the activity-history table.
///
/// The original shape stored the RP identifier in `app_identifier`; migration 3
/// splits the two apart.
fn migration_v2(conn: &Connection) -> DbResult<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS activity_entries (
            entry_id           INTEGER PRIMARY KEY,
            client_id          TEXT NOT NULL,
            protocol           INTEGER NOT NULL,
            created_at         INTEGER NOT NULL,
            outcome            TEXT NOT NULL,
            app_identifier     TEXT NOT NULL,
            issuer_schema_ids  BLOB NOT NULL,
            failure_reason     TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_activity_entries_created_at
        ON activity_entries (created_at DESC);",
    )
}

/// Migration 3: rebuilds activity history with separate `rp_id` and
/// `app_identifier` columns.
///
/// The table is dropped rather than altered so that a database written before
/// activity history was versioned is rebuilt instead of left half-migrated. The
/// old, now-unused `activity_meta` table is dropped as well.
fn migration_v3(conn: &Connection) -> DbResult<()> {
    conn.execute_batch(
        "DROP TABLE IF EXISTS activity_entries;
         DROP TABLE IF EXISTS activity_meta;

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
