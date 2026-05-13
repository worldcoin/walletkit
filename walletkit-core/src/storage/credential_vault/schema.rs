//! Credential-vault schema (vault metadata + credential records).
//!
//! The shared `blob_objects` table comes from
//! [`walletkit_db::Blobs::ensure_schema`]; this module owns only the
//! credential-specific tables.

use walletkit_db::{Connection, DbResult};

pub(super) const VAULT_SCHEMA_VERSION: i64 = 1;

/// Tables included in plaintext vault backups.
///
/// `vault_meta` is intentionally excluded: on restore, the destination vault
/// already has its own `vault_meta` (created by `ensure_schema` +
/// `init_leaf_index`) with the authoritative `leaf_index` from the
/// authenticator.
///
/// **Note:** New tables added to the vault schema must be added here too.
pub const BACKUP_TABLES: &[&str] = &["credential_records", "blob_objects"];

/// Creates the credential-vault tables, indexes, and triggers.
///
/// **Backup sensitivity:** Schema changes here affect plaintext vault
/// backups.
/// - New tables must be added to [`BACKUP_TABLES`].
/// - Column changes (especially new `NOT NULL` columns without defaults) can
///   break restoring older backups into a newer schema.
pub(super) fn ensure_schema(conn: &Connection) -> DbResult<()> {
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
