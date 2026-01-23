//! Cache database schema management.

use rusqlite::{Connection, OptionalExtension};

use crate::storage::error::StorageResult;

use super::util::map_db_err;

const CACHE_SCHEMA_VERSION: i64 = 2;

pub(super) fn ensure_schema(conn: &Connection) -> StorageResult<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS cache_meta (
            schema_version  INTEGER NOT NULL,
            created_at      INTEGER NOT NULL,
            updated_at      INTEGER NOT NULL
        );",
    )
    .map_err(|err| map_db_err(&err))?;

    let existing: Option<i64> = conn
        .query_row(
            "SELECT schema_version FROM cache_meta LIMIT 1;",
            [],
            |row| row.get(0),
        )
        .optional()
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

fn reset_schema(conn: &Connection) -> StorageResult<()> {
    conn.execute_batch(
        "DROP TABLE IF EXISTS used_nullifiers;
         DROP TABLE IF EXISTS merkle_proof_cache;
         DROP TABLE IF EXISTS session_keys;
         DROP TABLE IF EXISTS cache_entries;",
    )
    .map_err(|err| map_db_err(&err))?;
    ensure_entries_schema(conn)?;
    conn.execute("DELETE FROM cache_meta;", [])
        .map_err(|err| map_db_err(&err))?;
    insert_meta(conn)?;
    Ok(())
}

fn insert_meta(conn: &Connection) -> StorageResult<()> {
    conn.execute(
        "INSERT INTO cache_meta (schema_version, created_at, updated_at)
         VALUES (?1, strftime('%s','now'), strftime('%s','now'))",
        [CACHE_SCHEMA_VERSION],
    )
    .map_err(|err| map_db_err(&err))?;
    Ok(())
}
