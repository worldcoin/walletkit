//! Encrypted vault database for credential storage.

use std::path::Path;

use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::error::{StorageError, StorageResult};
use super::types::{
    BlobKind, ContentId, CredentialId, CredentialRecord, CredentialStatus,
};

const VAULT_SCHEMA_VERSION: i64 = 1;
const CONTENT_ID_PREFIX: &[u8] = b"worldid:blob";

/// Encrypted vault database wrapper.
pub struct VaultDb {
    conn: Connection,
}

impl VaultDb {
    /// Opens or creates the encrypted vault database at `path`.
    ///
    /// # Errors
    ///
    /// Returns an error if the database cannot be opened, keyed, or initialized.
    pub fn new(path: &Path, vault_key: [u8; 32]) -> StorageResult<Self> {
        let conn = open_connection(path)?;
        apply_key(&conn, vault_key)?;
        configure_connection(&conn)?;
        ensure_schema(&conn)?;
        let db = Self { conn };
        if !db.check_integrity()? {
            return Err(StorageError::CorruptedVault(
                "integrity_check failed".to_string(),
            ));
        }
        Ok(db)
    }

    /// Initializes or validates the leaf index for this vault.
    ///
    /// # Errors
    ///
    /// Returns an error if the stored leaf index does not match.
    pub fn init_leaf_index(
        &mut self,
        leaf_index: u64,
        now: u64,
    ) -> StorageResult<()> {
        let tx = self.conn.transaction().map_err(map_db_err)?;
        let existing = tx
            .query_row(
                "SELECT leaf_index FROM vault_meta LIMIT 1",
                [],
                |row| row.get::<_, Option<i64>>(0),
            )
            .optional()
            .map_err(map_db_err)?;
        match existing {
            None => {
                tx.execute(
                    "INSERT INTO vault_meta (schema_version, leaf_index, created_at, updated_at)
                     VALUES (?1, ?2, ?3, ?4)",
                    params![
                        VAULT_SCHEMA_VERSION,
                        leaf_index as i64,
                        now as i64,
                        now as i64
                    ],
                )
                .map_err(map_db_err)?;
            }
            Some(None) => {
                tx.execute(
                    "UPDATE vault_meta SET leaf_index = ?1, updated_at = ?2",
                    params![leaf_index as i64, now as i64],
                )
                .map_err(map_db_err)?;
            }
            Some(Some(stored)) => {
                if stored != leaf_index as i64 {
                    return Err(StorageError::InvalidLeafIndex {
                        expected: stored as u64,
                        provided: leaf_index,
                    });
                }
                tx.execute(
                    "UPDATE vault_meta SET updated_at = ?1",
                    params![now as i64],
                )
                .map_err(map_db_err)?;
            }
        }
        tx.commit().map_err(map_db_err)?;
        Ok(())
    }

    /// Stores a credential and optional associated data.
    ///
    /// # Errors
    ///
    /// Returns an error if any insert fails.
    #[allow(clippy::too_many_arguments)]
    pub fn store_credential(
        &mut self,
        issuer_schema_id: u64,
        status: CredentialStatus,
        subject_blinding_factor: [u8; 32],
        genesis_issued_at: u64,
        expires_at: Option<u64>,
        credential_blob: Vec<u8>,
        associated_data: Option<Vec<u8>>,
        now: u64,
    ) -> StorageResult<CredentialId> {
        let credential_id = *Uuid::new_v4().as_bytes();
        let credential_cid = compute_content_id(BlobKind::CredentialBlob, &credential_blob);
        let associated_cid = associated_data
            .as_ref()
            .map(|bytes| compute_content_id(BlobKind::AssociatedData, bytes));

        let tx = self.conn.transaction().map_err(map_db_err)?;
        tx.execute(
            "INSERT OR IGNORE INTO blob_objects (content_id, blob_kind, created_at, bytes)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                credential_cid.as_ref(),
                BlobKind::CredentialBlob.as_i64(),
                now as i64,
                credential_blob
            ],
        )
        .map_err(map_db_err)?;

        if let Some(data) = associated_data {
            let cid = associated_cid
                .as_ref()
                .expect("associated data CID must be present");
            tx.execute(
                "INSERT OR IGNORE INTO blob_objects (content_id, blob_kind, created_at, bytes)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    cid.as_ref(),
                    BlobKind::AssociatedData.as_i64(),
                    now as i64,
                    data
                ],
            )
            .map_err(map_db_err)?;
        }

        tx.execute(
            "INSERT INTO credential_records (
                credential_id,
                issuer_schema_id,
                subject_blinding_factor,
                genesis_issued_at,
                expires_at,
                status,
                updated_at,
                credential_blob_cid,
                associated_data_cid
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                credential_id.as_ref(),
                issuer_schema_id as i64,
                subject_blinding_factor.as_ref(),
                genesis_issued_at as i64,
                expires_at.map(|value| value as i64),
                status.as_i64(),
                now as i64,
                credential_cid.as_ref(),
                associated_cid
                    .as_ref()
                    .map(|cid| cid.as_ref())
            ],
        )
        .map_err(map_db_err)?;

        tx.commit().map_err(map_db_err)?;
        Ok(credential_id)
    }

    /// Lists active credentials, optionally filtered by issuer schema.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub fn list_credentials(
        &self,
        issuer_schema_id: Option<u64>,
        now: u64,
    ) -> StorageResult<Vec<CredentialRecord>> {
        let mut records = Vec::new();
        let status = CredentialStatus::Active.as_i64();
        let expires = now as i64;
        if let Some(issuer_schema_id) = issuer_schema_id {
            let mut stmt = self
                .conn
                .prepare(
                    "SELECT
                        cr.credential_id,
                        cr.issuer_schema_id,
                        cr.status,
                        cr.subject_blinding_factor,
                        cr.genesis_issued_at,
                        cr.expires_at,
                        cr.updated_at,
                        cb.bytes,
                        ad.bytes
                     FROM credential_records cr
                     JOIN blob_objects cb ON cb.content_id = cr.credential_blob_cid
                     LEFT JOIN blob_objects ad ON ad.content_id = cr.associated_data_cid
                     WHERE cr.status = ?1
                       AND (cr.expires_at IS NULL OR cr.expires_at > ?2)
                       AND cr.issuer_schema_id = ?3
                     ORDER BY cr.updated_at DESC",
                )
                .map_err(map_db_err)?;
            let rows = stmt
                .query_map(params![status, expires, issuer_schema_id as i64], map_record)
                .map_err(map_db_err)?;
            for record in rows {
                records.push(record?);
            }
        } else {
            let mut stmt = self
                .conn
                .prepare(
                    "SELECT
                        cr.credential_id,
                        cr.issuer_schema_id,
                        cr.status,
                        cr.subject_blinding_factor,
                        cr.genesis_issued_at,
                        cr.expires_at,
                        cr.updated_at,
                        cb.bytes,
                        ad.bytes
                     FROM credential_records cr
                     JOIN blob_objects cb ON cb.content_id = cr.credential_blob_cid
                     LEFT JOIN blob_objects ad ON ad.content_id = cr.associated_data_cid
                     WHERE cr.status = ?1
                       AND (cr.expires_at IS NULL OR cr.expires_at > ?2)
                     ORDER BY cr.updated_at DESC",
                )
                .map_err(map_db_err)?;
            let rows = stmt
                .query_map(params![status, expires], map_record)
                .map_err(map_db_err)?;
            for record in rows {
                records.push(record?);
            }
        }
        Ok(records)
    }

    /// Runs an integrity check on the vault database.
    ///
    /// # Errors
    ///
    /// Returns an error if the check cannot be executed.
    pub fn check_integrity(&self) -> StorageResult<bool> {
        let result: String = self
            .conn
            .query_row("PRAGMA integrity_check;", [], |row| row.get(0))
            .map_err(map_db_err)?;
        Ok(result.trim() == "ok")
    }
}

fn open_connection(path: &Path) -> StorageResult<Connection> {
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
        | OpenFlags::SQLITE_OPEN_CREATE
        | OpenFlags::SQLITE_OPEN_FULL_MUTEX;
    Connection::open_with_flags(path, flags).map_err(map_db_err)
}

fn apply_key(conn: &Connection, vault_key: [u8; 32]) -> StorageResult<()> {
    let key_hex = hex::encode(vault_key);
    let pragma = format!("PRAGMA key = \"x'{key_hex}'\";");
    conn.execute_batch(&pragma).map_err(map_db_err)?;
    let cipher_version: String = conn
        .query_row("PRAGMA cipher_version;", [], |row| row.get(0))
        .map_err(map_db_err)?;
    if cipher_version.trim().is_empty() {
        return Err(StorageError::VaultDb(
            "sqlcipher not available".to_string(),
        ));
    }
    Ok(())
}

fn configure_connection(conn: &Connection) -> StorageResult<()> {
    conn.execute_batch(
        "PRAGMA foreign_keys = ON;
         PRAGMA journal_mode = WAL;
         PRAGMA synchronous = FULL;",
    )
    .map_err(map_db_err)?;
    Ok(())
}

fn ensure_schema(conn: &Connection) -> StorageResult<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS vault_meta (
            schema_version  INTEGER NOT NULL,
            leaf_index      INTEGER,
            created_at      INTEGER NOT NULL,
            updated_at      INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS credential_records (
            credential_id           BLOB    NOT NULL,
            issuer_schema_id        INTEGER NOT NULL,
            subject_blinding_factor BLOB    NOT NULL,
            genesis_issued_at        INTEGER NOT NULL,
            expires_at              INTEGER,
            status                  INTEGER NOT NULL,
            updated_at              INTEGER NOT NULL,
            credential_blob_cid     BLOB    NOT NULL,
            associated_data_cid     BLOB,
            PRIMARY KEY (credential_id)
        );

        CREATE INDEX IF NOT EXISTS idx_cred_by_issuer_schema
        ON credential_records (issuer_schema_id, status, updated_at DESC);

        CREATE INDEX IF NOT EXISTS idx_cred_by_expiry
        ON credential_records (status, expires_at);

        CREATE TABLE IF NOT EXISTS blob_objects (
            content_id  BLOB    NOT NULL,
            blob_kind   INTEGER NOT NULL,
            created_at  INTEGER NOT NULL,
            bytes       BLOB    NOT NULL,
            PRIMARY KEY (content_id)
        );",
    )
    .map_err(map_db_err)?;
    Ok(())
}

fn compute_content_id(blob_kind: BlobKind, plaintext: &[u8]) -> ContentId {
    let mut hasher = Sha256::new();
    hasher.update(CONTENT_ID_PREFIX);
    hasher.update([blob_kind as u8]);
    hasher.update(plaintext);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn map_record(row: &rusqlite::Row<'_>) -> rusqlite::Result<CredentialRecord> {
    let credential_id_bytes: Vec<u8> = row.get(0)?;
    let issuer_schema_id: i64 = row.get(1)?;
    let status_raw: i64 = row.get(2)?;
    let subject_blinding_factor_bytes: Vec<u8> = row.get(3)?;
    let genesis_issued_at: i64 = row.get(4)?;
    let expires_at: Option<i64> = row.get(5)?;
    let updated_at: i64 = row.get(6)?;
    let credential_blob: Vec<u8> = row.get(7)?;
    let associated_data: Option<Vec<u8>> = row.get(8)?;

    let credential_id = parse_fixed_bytes::<16>(&credential_id_bytes, "credential_id")
        .map_err(|err| rusqlite::Error::UserFunctionError(Box::new(err)))?;
    let subject_blinding_factor =
        parse_fixed_bytes::<32>(&subject_blinding_factor_bytes, "subject_blinding_factor")
            .map_err(|err| rusqlite::Error::UserFunctionError(Box::new(err)))?;
    let status = CredentialStatus::try_from(status_raw)
        .map_err(|err| rusqlite::Error::UserFunctionError(Box::new(err)))?;

    Ok(CredentialRecord {
        credential_id,
        issuer_schema_id: issuer_schema_id as u64,
        status,
        subject_blinding_factor,
        genesis_issued_at: genesis_issued_at as u64,
        expires_at: expires_at.map(|value| value as u64),
        updated_at: updated_at as u64,
        credential_blob,
        associated_data,
    })
}

fn parse_fixed_bytes<const N: usize>(
    bytes: &[u8],
    label: &str,
) -> StorageResult<[u8; N]> {
    if bytes.len() != N {
        return Err(StorageError::VaultDb(format!(
            "{label} length mismatch: expected {N}, got {}",
            bytes.len()
        )));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(bytes);
    Ok(out)
}

fn map_db_err(err: rusqlite::Error) -> StorageError {
    StorageError::VaultDb(err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    fn temp_vault_path() -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!("walletkit-vault-{}.sqlite", Uuid::new_v4()));
        path
    }

    fn cleanup_vault_files(path: &Path) {
        let _ = fs::remove_file(path);
        let wal_path = path.with_extension("sqlite-wal");
        let shm_path = path.with_extension("sqlite-shm");
        let _ = fs::remove_file(wal_path);
        let _ = fs::remove_file(shm_path);
    }

    fn sample_blinding_factor() -> [u8; 32] {
        [0x11u8; 32]
    }

    #[test]
    fn test_vault_create_and_open() {
        let path = temp_vault_path();
        let key = [0x42u8; 32];
        let db = VaultDb::new(&path, key).expect("create vault");
        drop(db);
        VaultDb::new(&path, key).expect("open vault");
        cleanup_vault_files(&path);
    }

    #[test]
    fn test_vault_wrong_key_fails() {
        let path = temp_vault_path();
        let key = [0x01u8; 32];
        VaultDb::new(&path, key).expect("create vault");
        let err = VaultDb::new(&path, [0x02u8; 32]).expect_err("wrong key");
        match err {
            StorageError::VaultDb(_) | StorageError::CorruptedVault(_) => {}
            _ => panic!("unexpected error: {err}"),
        }
        cleanup_vault_files(&path);
    }

    #[test]
    fn test_leaf_index_set_once() {
        let path = temp_vault_path();
        let mut db = VaultDb::new(&path, [0x03u8; 32]).expect("create vault");
        db.init_leaf_index(42, 100).expect("init leaf index");
        db.init_leaf_index(42, 200).expect("init leaf index again");
        cleanup_vault_files(&path);
    }

    #[test]
    fn test_leaf_index_immutable() {
        let path = temp_vault_path();
        let mut db = VaultDb::new(&path, [0x04u8; 32]).expect("create vault");
        db.init_leaf_index(7, 100).expect("init leaf index");
        let err = db.init_leaf_index(8, 200).expect_err("mismatch");
        match err {
            StorageError::InvalidLeafIndex { .. } => {}
            _ => panic!("unexpected error: {err}"),
        }
        cleanup_vault_files(&path);
    }

    #[test]
    fn test_store_credential_without_associated_data() {
        let path = temp_vault_path();
        let mut db = VaultDb::new(&path, [0x05u8; 32]).expect("create vault");
        let credential_id = db
            .store_credential(
                10,
                CredentialStatus::Active,
                sample_blinding_factor(),
                123,
                None,
                b"credential".to_vec(),
                None,
                1000,
            )
            .expect("store credential");
        let records = db.list_credentials(None, 1000).expect("list credentials");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].credential_id, credential_id);
        assert!(records[0].associated_data.is_none());
        cleanup_vault_files(&path);
    }

    #[test]
    fn test_store_credential_with_associated_data() {
        let path = temp_vault_path();
        let mut db = VaultDb::new(&path, [0x06u8; 32]).expect("create vault");
        db.store_credential(
            11,
            CredentialStatus::Active,
            sample_blinding_factor(),
            456,
            None,
            b"credential-2".to_vec(),
            Some(b"associated".to_vec()),
            1000,
        )
        .expect("store credential");
        let records = db.list_credentials(None, 1000).expect("list credentials");
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].associated_data.as_deref(),
            Some(b"associated".as_slice())
        );
        cleanup_vault_files(&path);
    }

    #[test]
    fn test_content_id_determinism() {
        let a = compute_content_id(BlobKind::CredentialBlob, b"data");
        let b = compute_content_id(BlobKind::CredentialBlob, b"data");
        assert_eq!(a, b);
    }

    #[test]
    fn test_content_id_deduplication() {
        let path = temp_vault_path();
        let mut db = VaultDb::new(&path, [0x07u8; 32]).expect("create vault");
        db.store_credential(
            12,
            CredentialStatus::Active,
            sample_blinding_factor(),
            1,
            None,
            b"same".to_vec(),
            None,
            1000,
        )
        .expect("store credential");
        db.store_credential(
            12,
            CredentialStatus::Active,
            sample_blinding_factor(),
            1,
            None,
            b"same".to_vec(),
            None,
            1001,
        )
        .expect("store credential");
        let count: i64 = db
            .conn
            .query_row("SELECT COUNT(*) FROM blob_objects", [], |row| row.get(0))
            .map_err(map_db_err)
            .expect("count blobs");
        assert_eq!(count, 1);
        cleanup_vault_files(&path);
    }

    #[test]
    fn test_list_credentials_by_issuer() {
        let path = temp_vault_path();
        let mut db = VaultDb::new(&path, [0x08u8; 32]).expect("create vault");
        db.store_credential(
            100,
            CredentialStatus::Active,
            sample_blinding_factor(),
            1,
            None,
            b"issuer-a".to_vec(),
            None,
            1000,
        )
        .expect("store credential");
        db.store_credential(
            200,
            CredentialStatus::Active,
            sample_blinding_factor(),
            1,
            None,
            b"issuer-b".to_vec(),
            None,
            1000,
        )
        .expect("store credential");
        let records = db
            .list_credentials(Some(200), 1000)
            .expect("list credentials");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].issuer_schema_id, 200);
        cleanup_vault_files(&path);
    }

    #[test]
    fn test_list_credentials_excludes_expired() {
        let path = temp_vault_path();
        let mut db = VaultDb::new(&path, [0x09u8; 32]).expect("create vault");
        db.store_credential(
            300,
            CredentialStatus::Active,
            sample_blinding_factor(),
            1,
            Some(900),
            b"expired".to_vec(),
            None,
            1000,
        )
        .expect("store credential");
        let records = db.list_credentials(None, 1000).expect("list credentials");
        assert!(records.is_empty());
        cleanup_vault_files(&path);
    }

    #[test]
    fn test_vault_integrity_check() {
        let path = temp_vault_path();
        let db = VaultDb::new(&path, [0x0Au8; 32]).expect("create vault");
        assert!(db.check_integrity().expect("integrity"));
        cleanup_vault_files(&path);
    }

    #[test]
    fn test_vault_corruption_handling() {
        let path = temp_vault_path();
        let key = [0x0Bu8; 32];
        VaultDb::new(&path, key).expect("create vault");
        fs::write(&path, b"corrupt").expect("corrupt file");
        let err = VaultDb::new(&path, key).expect_err("corrupt vault");
        match err {
            StorageError::VaultDb(_) | StorageError::CorruptedVault(_) => {}
            _ => panic!("unexpected error: {err}"),
        }
        cleanup_vault_files(&path);
    }
}
