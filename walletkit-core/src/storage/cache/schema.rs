//! Cache database schema management.

use crate::storage::error::StorageResult;
use walletkit_db::{params, Connection, Value};

use super::util::map_db_err;

const CACHE_SCHEMA_VERSION: i64 = 2;

/// Ensures the cache schema is present and at the expected version.
///
/// # Errors
///
/// Returns an error if schema creation or migration fails.
pub(super) fn ensure_schema(conn: &Connection) -> StorageResult<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS cache_meta (
            schema_version  INTEGER NOT NULL,
            created_at      INTEGER NOT NULL,
            updated_at      INTEGER NOT NULL
        );",
    )
    .map_err(|err| map_db_err(&err))?;

    let existing = conn
        .query_row_optional(
            "SELECT schema_version FROM cache_meta LIMIT 1;",
            &[],
            |stmt| Ok(stmt.column_i64(0)),
        )
        .map_err(|err| map_db_err(&err))?;

    match existing {
        Some(version) if version == CACHE_SCHEMA_VERSION => {
            ensure_entries_schema(conn)?;
        }
        Some(_) => {
            reset_schema(conn)?;
        }
        None => {
            ensure_entries_schema(conn)?;
            insert_meta(conn)?;
        }
    }
    Ok(())
}

/// Ensures the `cache_entries` table and indexes exist.
///
/// # Errors
///
/// Returns an error if schema creation fails.
fn ensure_entries_schema(conn: &Connection) -> StorageResult<()> {
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
    .map_err(|err| map_db_err(&err))?;
    Ok(())
}

/// Drops legacy cache tables and recreates the current schema.
///
/// # Errors
///
/// Returns an error if the reset or re-init fails.
fn reset_schema(conn: &Connection) -> StorageResult<()> {
    conn.execute_batch(
        "DROP TABLE IF EXISTS used_nullifiers;
         DROP TABLE IF EXISTS merkle_proof_cache;
         DROP TABLE IF EXISTS session_keys;
         DROP TABLE IF EXISTS cache_entries;",
    )
    .map_err(|err| map_db_err(&err))?;
    ensure_entries_schema(conn)?;
    conn.execute("DELETE FROM cache_meta;", &[])
        .map_err(|err| map_db_err(&err))?;
    insert_meta(conn)?;
    Ok(())
}

/// Inserts the current schema version into `cache_meta`.
///
/// # Errors
///
/// Returns an error if the insert fails.
fn insert_meta(conn: &Connection) -> StorageResult<()> {
    conn.execute(
        "INSERT INTO cache_meta (schema_version, created_at, updated_at)
         VALUES (?1, strftime('%s','now'), strftime('%s','now'))",
        params![Value::Integer(CACHE_SCHEMA_VERSION)],
    )
    .map_err(|err| map_db_err(&err))?;
    Ok(())
}
