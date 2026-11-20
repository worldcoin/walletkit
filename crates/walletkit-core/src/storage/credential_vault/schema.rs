//! Credential-vault schema (vault metadata, credential records, and their
//! PCP blob links).
//!
//! The shared `blob_objects` table comes from
//! [`walletkit_db::Blobs::ensure_schema`]; this module owns only the
//! credential tables and the local-only content-addressed blob store.

use walletkit_sqlite::{Connection, DbResult};

pub(super) const VAULT_SCHEMA_VERSION: i64 = 1;

/// Creates the credential-vault tables, indexes, and triggers.
///
/// **Backup sensitivity:** Schema changes here affect plaintext vault
/// backups.
/// - Portable credential tables belong in [`super::BACKUP_TABLES`].
///   Local-only `blobs` and `legacy_blob_paths` must stay out of backup and recovery.
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

        CREATE TABLE IF NOT EXISTS credential_blob_refs (
            credential_id INTEGER NOT NULL REFERENCES credential_records (credential_id) ON DELETE CASCADE,
            blob_id       BLOB    NOT NULL CHECK (typeof(blob_id) = 'blob' AND length(blob_id) = 32),
            created_at    INTEGER NOT NULL,
            PRIMARY KEY (credential_id, blob_id)
        ) WITHOUT ROWID;

        CREATE INDEX IF NOT EXISTS idx_credential_blob_refs_blob_id
        ON credential_blob_refs (blob_id);

        CREATE TABLE IF NOT EXISTS blobs (
            blob_id BLOB PRIMARY KEY NOT NULL CHECK (typeof(blob_id) = 'blob' AND length(blob_id) = 32),
            kind TEXT NOT NULL,
            metadata BLOB,
            revision INTEGER NOT NULL CHECK (typeof(revision) = 'integer' AND revision > 0),
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            data BLOB NOT NULL
        );

        -- Maps legacy on-disk PCP paths only; removed once those files are deleted.
        CREATE TABLE IF NOT EXISTS legacy_blob_paths (
            legacy_path TEXT PRIMARY KEY NOT NULL,
            blob_id BLOB NOT NULL REFERENCES blobs (blob_id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_legacy_blob_paths_blob_id ON legacy_blob_paths (blob_id);
",
    )
}
