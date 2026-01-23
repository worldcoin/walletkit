use rusqlite::Connection;

use crate::storage::error::StorageResult;

use super::helpers::map_db_err;

pub(super) const VAULT_SCHEMA_VERSION: i64 = 1;

pub(super) fn ensure_schema(conn: &Connection) -> StorageResult<()> {
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
            expires_at              INTEGER,
            updated_at              INTEGER NOT NULL,
            credential_blob_cid     BLOB    NOT NULL,
            associated_data_cid     BLOB
        );

        CREATE INDEX IF NOT EXISTS idx_cred_by_issuer_schema
        ON credential_records (issuer_schema_id, updated_at DESC);

        CREATE INDEX IF NOT EXISTS idx_cred_by_expiry
        ON credential_records (expires_at);

        CREATE TABLE IF NOT EXISTS blob_objects (
            content_id  BLOB    NOT NULL,
            blob_kind   INTEGER NOT NULL,
            created_at  INTEGER NOT NULL,
            bytes       BLOB    NOT NULL,
            PRIMARY KEY (content_id)
        );",
    )
    .map_err(|err| map_db_err(&err))?;
    Ok(())
}
