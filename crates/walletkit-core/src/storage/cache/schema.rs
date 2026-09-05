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

use walletkit_sqlite::{params, Connection, DbResult};

const CACHE_SCHEMA_VERSION: i64 = 2;

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
    // NOTE it currently skips the activity history (not part of the same migration schema)
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

pub(super) fn ensure_activity_schema(conn: &Connection) -> DbResult<()> {
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
