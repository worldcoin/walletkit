//! Vault database schema management.
//!
//! Owns only the credential-specific tables. The shared `blob_objects` table
//! is created via [`walletkit_secure_store::Blobs::ensure_schema`] from
//! [`super::VaultDb::new`].

use walletkit_db::Connection;
use walletkit_secure_store::{StoreError, StoreResult};

pub(super) const VAULT_SCHEMA_VERSION: i64 = 1;

/// **Backup sensitivity:** Schema changes here affect vault backups made into the backup system.
/// - New tables must be added to `BACKUP_TABLES` in `walletkit-db/src/cipher.rs`.
/// - Column changes (especially new `NOT NULL` columns without defaults) will
///   break restoring older backups into a newer schema. See the schema migration
///   note on `import_plaintext_copy` in `walletkit-db/src/cipher.rs`.
pub(super) fn ensure_schema(conn: &Connection) -> StoreResult<()> {
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
    .map_err(StoreError::from)?;
    Ok(())
}
