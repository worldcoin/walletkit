//! Cache database schema management.

use rusqlite::Connection;

use crate::storage::error::StorageResult;

use super::util::map_db_err;

const CACHE_SCHEMA_VERSION: i64 = 1;

pub(super) fn ensure_schema(conn: &Connection) -> StorageResult<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS cache_meta (
            schema_version  INTEGER NOT NULL,
            created_at      INTEGER NOT NULL,
            updated_at      INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS used_nullifiers (
            request_id      BLOB    NOT NULL,
            nullifier       BLOB    NOT NULL,
            expires_at      INTEGER NOT NULL,
            proof_bytes     BLOB    NOT NULL,
            PRIMARY KEY (request_id),
            UNIQUE (nullifier)
        );

        CREATE INDEX IF NOT EXISTS idx_used_nullifiers_expiry
        ON used_nullifiers (expires_at);

        CREATE TABLE IF NOT EXISTS merkle_proof_cache (
            registry_kind   INTEGER NOT NULL,
            root            BLOB    NOT NULL,
            leaf_index      INTEGER NOT NULL,
            proof_bytes     BLOB    NOT NULL,
            inserted_at     INTEGER NOT NULL,
            expires_at      INTEGER NOT NULL,
            PRIMARY KEY (registry_kind, root, leaf_index)
        );

        CREATE INDEX IF NOT EXISTS idx_merkle_proof_expiry
        ON merkle_proof_cache (expires_at);

        CREATE TABLE IF NOT EXISTS session_keys (
            rp_id       BLOB    NOT NULL,
            k_session   BLOB    NOT NULL,
            expires_at  INTEGER NOT NULL,
            PRIMARY KEY (rp_id)
        );

        CREATE INDEX IF NOT EXISTS idx_session_keys_expiry
        ON session_keys (expires_at);",
    )
    .map_err(map_db_err)?;

    let existing: i64 = conn
        .query_row("SELECT COUNT(*) FROM cache_meta;", [], |row| row.get(0))
        .map_err(map_db_err)?;
    if existing == 0 {
        conn.execute(
            "INSERT INTO cache_meta (schema_version, created_at, updated_at)
             VALUES (?1, strftime('%s','now'), strftime('%s','now'))",
            [CACHE_SCHEMA_VERSION],
        )
        .map_err(map_db_err)?;
    }

    Ok(())
}
