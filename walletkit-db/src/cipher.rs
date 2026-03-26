//! `sqlite3mc` encryption configuration.
//!
//! # Encryption flow
//!
//! The credential storage uses `sqlite3mc` (`SQLite3` Multiple Ciphers) to
//! encrypt both the vault and cache databases at rest. The encryption is
//! transparent to SQL -- once a database is opened and keyed, all reads and
//! writes are automatically encrypted/decrypted by the `SQLite` pager layer.
//!
//! The flow when opening a database is:
//!
//! 1. **Open** -- `sqlite3_open_v2` creates or opens the database file.
//!    At this point the file is opaque (encrypted) and no data can be read.
//!
//! 2. **Key** -- `PRAGMA key = "x'<hex>'"` passes the 32-byte
//!    `K_intermediate` (hex-encoded) to `sqlite3mc`. Internally, `sqlite3mc`
//!    derives a page-level encryption key from this material using the
//!    configured KDF (PBKDF2-SHA256 by default for ChaCha20-Poly1305).
//!    After this point, every page read from disk is decrypted and every
//!    page written to disk is encrypted.
//!
//! 3. **Verify** -- We immediately read from `sqlite_master` to confirm
//!    the key is correct. If the key is wrong, `sqlite3mc` returns
//!    `SQLITE_NOTADB` because the decrypted page header won't match the
//!    expected `SQLite` magic bytes. We surface this as a clear error.
//!
//! 4. **Configure** -- WAL journal mode and `synchronous=FULL` are set for
//!    crash consistency. Foreign keys are enabled.
//!
//! The default cipher is **ChaCha20-Poly1305** (authenticated encryption).
//! All crypto is built into the `sqlite3mc` amalgamation -- no OpenSSL or
//! other external crypto library is needed on any platform.

use std::path::Path;

use secrecy::{ExposeSecret, SecretBox};
use zeroize::Zeroizing;

use super::connection::Connection;
use super::error::{DbError, DbResult};

/// Opens a database, applies the encryption key, and configures the connection.
///
/// This is the standard open sequence used by both vault and cache databases:
/// open -> key -> verify -> configure (WAL + foreign keys).
///
/// See the [module-level documentation](self) for the full encryption flow.
///
/// # Errors
///
/// Returns `DbError` if opening, keying, or configuring the connection fails.
pub fn open_encrypted(
    path: &Path,
    k_intermediate: &SecretBox<[u8; 32]>,
    read_only: bool,
) -> DbResult<Connection> {
    let conn = Connection::open(path, read_only)?;
    apply_key(&conn, k_intermediate)?;
    configure_connection(&conn)?;
    Ok(conn)
}

/// Applies the `sqlite3mc` encryption key to an open connection.
///
/// The 32-byte `k_intermediate` is hex-encoded and passed as a raw key via
/// `PRAGMA key = "x'<64-hex-chars>'"`. `sqlite3mc` interprets the `x'...'`
/// prefix as a raw key (as opposed to a passphrase that would be run through
/// a KDF first).
///
/// After keying, a lightweight read (`SELECT count(*) FROM sqlite_master`)
/// verifies the key is correct. If it's wrong, `sqlite3mc` fails with
/// `SQLITE_NOTADB` on the first page read.
fn apply_key(conn: &Connection, k_intermediate: &SecretBox<[u8; 32]>) -> DbResult<()> {
    // Hex-encode the key and build the PRAGMA. Both are zeroized on drop.
    let key_hex = Zeroizing::new(hex::encode(k_intermediate.expose_secret()));
    let pragma = Zeroizing::new(format!("PRAGMA key = \"x'{}'\";", key_hex.as_str()));

    // execute_batch_zeroized ensures the internal CString copy of the PRAGMA
    // (which contains the hex key) is zeroized after the FFI call returns.
    conn.execute_batch_zeroized(&pragma)?;

    // Touch a page to verify the key works. On failure this produces a clear
    // error rather than a confusing "not a database" later during schema setup.
    conn.execute_batch("SELECT count(*) FROM sqlite_master;")
        .map_err(|e| {
            DbError::new(
                e.code.0,
                format!(
                    "encryption key verification failed (is the key correct?): {}",
                    e.message
                ),
            )
        })?;

    // k_intermediate, key_hex, and pragma are all Zeroizing — zeroed on drop
    // regardless of which exit path we took.
    Ok(())
}

/// Configures durable WAL settings, foreign keys, and secure deletion.
///
/// - `journal_mode = WAL` -- enables concurrent readers during writes.
/// - `synchronous = FULL` -- maximizes crash consistency (all WAL pages are
///   fsynced before the transaction is reported as committed).
/// - `foreign_keys = ON` -- enforces referential integrity constraints.
/// - `secure_delete = ON` -- overwrites deleted content with zeroes so
///   sensitive data does not linger in free pages.
fn configure_connection(conn: &Connection) -> DbResult<()> {
    conn.execute_batch(
        "PRAGMA foreign_keys = ON;
         PRAGMA journal_mode = WAL;
         PRAGMA synchronous = FULL;
         PRAGMA secure_delete = ON;",
    )
}

/// Tables included in plaintext vault backups.
///
/// `vault_meta` is intentionally excluded: on restore, the destination vault
/// already has its own `vault_meta` (created by `ensure_schema` + `init_leaf_index`)
/// with the authoritative `leaf_index` from the authenticator.
///
/// **Note:** If new tables are added to the vault schema, this list must be
/// updated to include them.
pub const BACKUP_TABLES: &[&str] = &["credential_records", "blob_objects"];

/// Creates a plaintext (unencrypted) copy of an already-open encrypted database.
///
/// The copy is produced by `ATTACH`-ing a new unencrypted database and copying
/// all rows via `CREATE TABLE ... AS SELECT *`. The destination file must not
/// already exist.
///
/// We use `ATTACH` + SQL instead of the `sqlite3_backup` API because
/// `sqlite3mc` requires both source and destination to share the same
/// encryption configuration. Since the destination is unencrypted, the
/// backup API cannot be used.
///
/// # Errors
///
/// Returns `DbError` if the `ATTACH`, copy, or `DETACH` fails.
pub fn export_plaintext_copy(conn: &Connection, dest_path: &Path) -> DbResult<()> {
    let dest_str = dest_path.to_string_lossy();
    let attach_sql = format!(
        "ATTACH DATABASE '{}' AS backup KEY '';",
        dest_str.replace('\'', "''")
    );
    conn.execute_batch(&attach_sql)?;

    let result = (|| {
        let tx = conn.transaction()?;
        for table in BACKUP_TABLES {
            tx.execute_batch(&format!(
                "CREATE TABLE backup.{table} AS SELECT * FROM {table};"
            ))?;
        }
        tx.commit()
    })();

    // Always detach, even if the copy failed.
    let detach_result = conn.execute_batch("DETACH DATABASE backup;");

    result?;
    detach_result?;
    Ok(())
}

/// Imports data from a plaintext (unencrypted) database into an already-open
/// encrypted database.
///
/// The source database is `ATTACH`ed with an empty key and its contents are
/// copied into the main (empty) encrypted database. This is intended for
/// restore on a fresh install where the vault tables exist but contain no data.
///
/// See [`export_plaintext_copy`] for why `ATTACH` + SQL is used instead of
/// the `sqlite3_backup` API.
///
/// **Schema migration:** The import uses `SELECT *`, so column changes are
/// handled automatically as long as both sides share the same schema. If the
/// vault schema evolves (e.g. new columns with `NOT NULL` constraints),
/// restoring an older backup into a newer schema will fail. When that happens,
/// this function will need version-aware import logic.
///
/// # Errors
///
/// Returns `DbError` if the `ATTACH`, copy, or `DETACH` fails.
pub fn import_plaintext_copy(conn: &Connection, source_path: &Path) -> DbResult<()> {
    if !source_path.exists() {
        return Err(DbError::new(
            -1,
            format!("backup file does not exist: {}", source_path.display()),
        ));
    }

    let source_str = source_path.to_string_lossy();
    let attach_sql = format!(
        "ATTACH DATABASE '{}' AS backup KEY '';",
        source_str.replace('\'', "''")
    );
    conn.execute_batch(&attach_sql)?;

    // Verify the destination tables are empty before importing. Importing into
    // a non-empty vault could silently merge data if primary keys don't collide.
    let result = (|| {
        for table in BACKUP_TABLES {
            let count: i64 =
                conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), &[], |row| {
                    Ok(row.column_i64(0))
                })?;
            if count > 0 {
                return Err(DbError::new(
                    -1,
                    format!("cannot import into non-empty table: {table}"),
                ));
            }
        }

        // Wrap in a transaction so the restore is atomic — if any INSERT fails,
        // everything is rolled back and the vault stays empty for a retry.
        let tx = conn.transaction()?;
        for table in BACKUP_TABLES {
            tx.execute_batch(&format!(
                "INSERT INTO {table} SELECT * FROM backup.{table};"
            ))?;
        }
        tx.commit()
    })();

    // Always detach, even if the import failed.
    let detach_result = conn.execute_batch("DETACH DATABASE backup;");

    result?;
    detach_result?;
    Ok(())
}

/// Runs `PRAGMA integrity_check` and returns whether the database is healthy.
///
/// # Errors
///
/// Returns `DbError` if the integrity check query fails.
pub fn integrity_check(conn: &Connection) -> DbResult<bool> {
    let result = conn.query_row("PRAGMA integrity_check;", &[], |stmt| {
        Ok(stmt.column_text(0))
    })?;
    Ok(result.trim() == "ok")
}
