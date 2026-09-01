//! `sqlite3mc` encryption configuration.
//!
//! # Encryption flow
//!
//! This crate uses `sqlite3mc` (`SQLite3` Multiple Ciphers) to encrypt
//! `SQLite` databases at rest. The encryption is transparent to SQL -- once a
//! database is opened and keyed, all reads and writes are automatically
//! encrypted/decrypted by the `SQLite` pager layer.
//!
//! The flow when opening a database is:
//!
//! 1. **Open** -- `sqlite3_open_v2` creates or opens the database file.
//!    At this point the file is opaque (encrypted) and no data can be read.
//!
//! 2. **Configure cipher** -- `PRAGMA cipher = 'chacha20'` fixes the on-disk
//!    cipher before the key activates it.
//!
//! 3. **Key** -- `PRAGMA key = "x'<hex>'"` passes the 32-byte
//!    `K_intermediate` (hex-encoded) to `sqlite3mc` as a raw key. The `x'...'`
//!    syntax tells `sqlite3mc` to use the bytes directly as the page-encryption
//!    key, bypassing the passphrase KDF (PBKDF2-SHA256) that a plain-string
//!    key would otherwise be run through. After this point, every page read
//!    from disk is decrypted and every page written to disk is encrypted.
//!
//! 4. **Verify** -- We immediately read from `sqlite_master` to confirm
//!    the key is correct. If the key is wrong, `sqlite3mc` returns
//!    `SQLITE_NOTADB` because the decrypted page header won't match the
//!    expected `SQLite` magic bytes. We surface this as a clear error.
//!
//! 5. **Configure connection** -- The target-specific journal mode and every
//!    connection-level invariant are set and verified.
//!
//! The default cipher is **ChaCha20-Poly1305** (authenticated encryption).
//! All crypto is built into the `sqlite3mc` amalgamation -- no OpenSSL or
//! other external crypto library is needed on any platform.

use std::path::Path;

use secrecy::{ExposeSecret, SecretBox};
use zeroize::Zeroizing;

use super::connection::Connection;
use super::error::{DbResult, Error};

const CIPHER_CHACHA20: &str = "chacha20";
const FOREIGN_KEYS_ON: i64 = 1;
const SYNCHRONOUS_FULL: i64 = 2;
const SECURE_DELETE_ON: i64 = 1;
const TEMP_STORE_MEMORY: i64 = 2;

/// Opens a database, applies the encryption key, and configures the connection.
///
/// This is the standard open sequence for encrypted databases: open -> select
/// cipher -> key and verify -> configure connection policy.
///
/// See the [module-level documentation](self) for the full encryption flow.
///
/// # Errors
///
/// Returns `Error` if opening, keying, or configuring the connection fails.
pub fn open_encrypted(
    path: &Path,
    k_intermediate: &SecretBox<[u8; 32]>,
    read_only: bool,
) -> DbResult<Connection> {
    #[cfg(not(target_arch = "wasm32"))]
    let conn = Connection::open(path, read_only)?;
    #[cfg(target_arch = "wasm32")]
    let conn = {
        if !crate::opfs::is_installed() {
            return Err(Error::new(
                -1,
                "persistent OPFS storage must be installed before opening a database",
            ));
        }
        Connection::open_with_vfs(
            path,
            read_only,
            Some(crate::opfs::ENCRYPTED_VFS_NAME),
        )?
    };
    configure_connection(&conn, k_intermediate)?;
    Ok(conn)
}

/// Selects and verifies the on-disk cipher before the key activates it.
///
/// Pinning the cipher prevents a future compile-time default change from
/// silently creating or interpreting databases with a different format.
fn ensure_cipher(conn: &Connection) -> DbResult<()> {
    conn.execute_batch(&format!("PRAGMA cipher = '{CIPHER_CHACHA20}';"))?;
    let actual = conn.query_row("PRAGMA cipher;", &[], |row| Ok(row.column_text(0)))?;
    if actual.eq_ignore_ascii_case(CIPHER_CHACHA20) {
        Ok(())
    } else {
        Err(Error::new(
            -1,
            format!(
                "could not ensure sqlite3mc cipher {CIPHER_CHACHA20}: SQLite selected {actual}"
            ),
        ))
    }
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
            Error::new(
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

/// Configures durable journal settings, foreign keys, and secure deletion.
///
/// - Native uses WAL for concurrent readers during writes.
/// - WASM uses a rollback journal because SAH-pool has no WAL shared-memory
///   methods; WAL would require exclusive locking and provide no concurrency.
/// - `synchronous = FULL` -- maximizes crash consistency by flushing required
///   journal writes before the transaction is reported as committed.
/// - `foreign_keys = ON` -- enforces referential integrity constraints.
/// - `secure_delete = ON` -- overwrites deleted content with zeroes so
///   sensitive data does not linger in free pages.
fn configure_connection(
    conn: &Connection,
    k_intermediate: &SecretBox<[u8; 32]>,
) -> DbResult<()> {
    ensure_cipher(conn)?;
    apply_key(conn, k_intermediate)?;

    #[cfg(not(target_arch = "wasm32"))]
    ensure_journal_mode(conn, "WAL")?;
    // SAH-pool does not expose WAL shared-memory methods. WAL would therefore
    // require locking_mode=EXCLUSIVE before the first database access and
    // provide no concurrency benefit, so WASM deliberately uses the rollback
    // journal until benchmarks justify that extra complexity.
    #[cfg(target_arch = "wasm32")]
    ensure_journal_mode(conn, "DELETE")?;

    ensure_foreign_keys(conn)?;
    ensure_synchronous_full(conn)?;
    ensure_secure_delete(conn)?;
    ensure_temp_store_memory(conn)?;
    Ok(())
}

/// Ensures the target-specific journal policy actually took effect.
///
/// Assigning `journal_mode` returns the effective mode because `SQLite` may
/// retain the previous mode when the requested transition is unavailable.
fn ensure_journal_mode(conn: &Connection, requested: &str) -> DbResult<()> {
    let actual =
        conn.query_row(&format!("PRAGMA journal_mode = {requested};"), &[], |row| {
            Ok(row.column_text(0))
        })?;
    if actual.eq_ignore_ascii_case(requested) {
        Ok(())
    } else {
        Err(Error::new(
            -1,
            format!(
                "could not ensure journal mode {requested}: SQLite selected {actual}"
            ),
        ))
    }
}

/// Enables foreign-key enforcement for every connection.
///
/// `SQLite` defaults this setting to off and may silently ignore the assignment
/// inside a transaction or when foreign-key support was omitted at build time.
fn ensure_foreign_keys(conn: &Connection) -> DbResult<()> {
    conn.execute_batch("PRAGMA foreign_keys = ON;")?;
    let actual =
        conn.query_row("PRAGMA foreign_keys;", &[], |row| Ok(row.column_i64(0)))?;
    if actual == FOREIGN_KEYS_ON {
        Ok(())
    } else {
        Err(Error::new(
            -1,
            format!(
                "could not ensure PRAGMA foreign_keys = ON: expected {FOREIGN_KEYS_ON}, got {actual}"
            ),
        ))
    }
}

/// Uses `SQLite`'s strongest ordinary durability policy.
///
/// `FULL` ensures `SQLite` flushes journal content before reporting a transaction
/// as committed, reducing the risk of corruption after a crash or power loss.
fn ensure_synchronous_full(conn: &Connection) -> DbResult<()> {
    conn.execute_batch("PRAGMA synchronous = FULL;")?;
    let actual =
        conn.query_row("PRAGMA synchronous;", &[], |row| Ok(row.column_i64(0)))?;
    if actual == SYNCHRONOUS_FULL {
        Ok(())
    } else {
        Err(Error::new(
            -1,
            format!(
                "could not ensure PRAGMA synchronous = FULL: expected {SYNCHRONOUS_FULL}, got {actual}"
            ),
        ))
    }
}

/// Overwrites deleted content instead of leaving it in reusable database pages.
///
/// This limits plaintext remnants while the encrypted database is open and
/// accessible with its key.
fn ensure_secure_delete(conn: &Connection) -> DbResult<()> {
    conn.execute_batch("PRAGMA secure_delete = ON;")?;
    let actual =
        conn.query_row("PRAGMA secure_delete;", &[], |row| Ok(row.column_i64(0)))?;
    if actual == SECURE_DELETE_ON {
        Ok(())
    } else {
        Err(Error::new(
            -1,
            format!(
                "could not ensure PRAGMA secure_delete = ON: expected {SECURE_DELETE_ON}, got {actual}"
            ),
        ))
    }
}

/// Keeps temporary tables and indices in memory.
///
/// `sqlite3mc` does not encrypt temporary databases, so allowing temporary
/// storage to spill to a filesystem could expose plaintext at rest.
fn ensure_temp_store_memory(conn: &Connection) -> DbResult<()> {
    conn.execute_batch("PRAGMA temp_store = MEMORY;")?;
    let actual =
        conn.query_row("PRAGMA temp_store;", &[], |row| Ok(row.column_i64(0)))?;
    if actual == TEMP_STORE_MEMORY {
        Ok(())
    } else {
        Err(Error::new(
            -1,
            format!(
                "could not ensure PRAGMA temp_store = MEMORY: expected {TEMP_STORE_MEMORY}, got {actual}"
            ),
        ))
    }
}

/// Creates a plaintext (unencrypted) copy of an already-open encrypted database.
///
/// The copy is produced by `ATTACH`-ing a new unencrypted database and copying
/// the caller-specified tables via `CREATE TABLE ... AS SELECT *`. The
/// destination file must not already exist.
///
/// We use `ATTACH` + SQL instead of the `sqlite3_backup` API because
/// `sqlite3mc` requires both source and destination to share the same
/// encryption configuration. Since the destination is unencrypted, the
/// backup API cannot be used.
///
/// # Errors
///
/// Returns `Error` if the `ATTACH`, copy, or `DETACH` fails.
pub fn export_plaintext_copy(
    conn: &Connection,
    dest_path: &Path,
    tables: &[&str],
) -> DbResult<()> {
    let dest_str = dest_path.to_string_lossy();
    let attach_sql = format!(
        "ATTACH DATABASE '{}' AS backup KEY '';",
        dest_str.replace('\'', "''")
    );
    conn.execute_batch(&attach_sql)?;

    let result = (|| {
        let tx = conn.transaction()?;
        for table in tables {
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
/// copied into the main (empty) encrypted database.
///
/// See [`export_plaintext_copy`] for why `ATTACH` + SQL is used instead of
/// the `sqlite3_backup` API.
///
/// **Schema migration:** The import uses `SELECT *`, so column changes are
/// handled automatically as long as both sides share the same schema. If a
/// caller's schema evolves (e.g. new columns with `NOT NULL` constraints),
/// restoring an older backup into a newer schema will fail. When that happens,
/// the caller needs version-aware import logic.
///
/// # Errors
///
/// Returns `Error` if the `ATTACH`, copy, or `DETACH` fails.
pub fn import_plaintext_copy(
    conn: &Connection,
    source_path: &Path,
    tables: &[&str],
) -> DbResult<()> {
    if !source_path.exists() {
        return Err(Error::new(
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
    // a non-empty destination could silently merge data if primary keys don't
    // collide.
    let result = (|| {
        for table in tables {
            let count: i64 =
                conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), &[], |row| {
                    Ok(row.column_i64(0))
                })?;
            if count > 0 {
                return Err(Error::new(
                    -1,
                    format!("cannot import into non-empty table: {table}"),
                ));
            }
        }

        // Wrap in a transaction so the restore is atomic — if any INSERT
        // fails, everything is rolled back and the destination stays empty for
        // a retry.
        let tx = conn.transaction()?;
        for table in tables {
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
/// Returns `Error` if the integrity check query fails.
pub fn integrity_check(conn: &Connection) -> DbResult<bool> {
    let result = conn.query_row("PRAGMA integrity_check;", &[], |stmt| {
        Ok(stmt.column_text(0))
    })?;
    Ok(result.trim() == "ok")
}

#[cfg(test)]
mod tests {
    use super::{
        export_plaintext_copy, import_plaintext_copy, integrity_check, open_encrypted,
    };
    use crate::params;
    use crate::test_utils::init_sqlite;
    use crate::Connection;
    use secrecy::SecretBox;

    #[test]
    fn test_cipher_encrypted_round_trip() {
        init_sqlite();
        let dir = tempfile::tempdir().expect("create temp dir");
        let path = dir.path().join("cipher-test.sqlite");
        let key = SecretBox::init_with(|| [0xABu8; 32]);

        // Create and write
        {
            let conn = open_encrypted(&path, &key, false).expect("open encrypted");
            conn.execute_batch(
                "CREATE TABLE secret (id INTEGER PRIMARY KEY, val TEXT);",
            )
            .expect("create table");
            conn.execute("INSERT INTO secret (id, val) VALUES (1, 'top-secret')", &[])
                .expect("insert");
        }

        // Re-open with correct key
        {
            let conn = open_encrypted(&path, &key, false).expect("reopen encrypted");
            let val = conn
                .query_row("SELECT val FROM secret WHERE id = 1", &[], |stmt| {
                    Ok(stmt.column_text(0))
                })
                .expect("query");
            assert_eq!(val, "top-secret");
        }

        // Wrong key should fail
        {
            let wrong_key = SecretBox::init_with(|| [0xCDu8; 32]);
            let result = open_encrypted(&path, &wrong_key, false);
            assert!(result.is_err(), "wrong key should fail");
        }
    }

    #[test]
    fn test_integrity_check() {
        init_sqlite();
        let conn = Connection::open_in_memory().expect("open in-memory db");
        let ok = integrity_check(&conn).expect("check");
        assert!(ok);
    }

    #[test]
    fn test_cipher_plaintext_export_import_roundtrip() {
        init_sqlite();
        let dir = tempfile::tempdir().expect("create temp dir");
        let src_path = dir.path().join("source.sqlite");
        let dest_path = dir.path().join("backup.plain.sqlite");
        let restore_path = dir.path().join("restore.sqlite");
        let key = SecretBox::init_with(|| [0x11u8; 32]);

        {
            let conn = open_encrypted(&src_path, &key, false).expect("open src");
            conn.execute_batch(
                "CREATE TABLE widgets (id INTEGER PRIMARY KEY, val TEXT NOT NULL);",
            )
            .expect("create table");
            conn.execute(
                "INSERT INTO widgets (id, val) VALUES (?1, ?2)",
                params![1_i64, "alpha"],
            )
            .expect("insert");
            conn.execute(
                "INSERT INTO widgets (id, val) VALUES (?1, ?2)",
                params![2_i64, "beta"],
            )
            .expect("insert");

            export_plaintext_copy(&conn, &dest_path, &["widgets"]).expect("export");
        }

        {
            let conn =
                open_encrypted(&restore_path, &key, false).expect("open restore");
            conn.execute_batch(
                "CREATE TABLE widgets (id INTEGER PRIMARY KEY, val TEXT NOT NULL);",
            )
            .expect("create table");
            import_plaintext_copy(&conn, &dest_path, &["widgets"]).expect("import");

            let count: i64 = conn
                .query_row("SELECT COUNT(*) FROM widgets", &[], |row| {
                    Ok(row.column_i64(0))
                })
                .expect("count");
            assert_eq!(count, 2);

            let val = conn
                .query_row("SELECT val FROM widgets WHERE id = 2", &[], |row| {
                    Ok(row.column_text(0))
                })
                .expect("query");
            assert_eq!(val, "beta");
        }
    }

    #[test]
    fn test_cipher_import_rejects_non_empty_destination() {
        init_sqlite();
        let dir = tempfile::tempdir().expect("create temp dir");
        let src_path = dir.path().join("source.sqlite");
        let dest_path = dir.path().join("backup.plain.sqlite");
        let restore_path = dir.path().join("restore.sqlite");
        let key = SecretBox::init_with(|| [0x22u8; 32]);

        {
            let conn = open_encrypted(&src_path, &key, false).expect("open src");
            conn.execute_batch(
                "CREATE TABLE widgets (id INTEGER PRIMARY KEY, val TEXT NOT NULL);",
            )
            .expect("create table");
            conn.execute(
                "INSERT INTO widgets (id, val) VALUES (?1, ?2)",
                params![1_i64, "alpha"],
            )
            .expect("insert");
            export_plaintext_copy(&conn, &dest_path, &["widgets"]).expect("export");
        }

        let conn = open_encrypted(&restore_path, &key, false).expect("open restore");
        conn.execute_batch(
            "CREATE TABLE widgets (id INTEGER PRIMARY KEY, val TEXT NOT NULL);",
        )
        .expect("create table");
        conn.execute(
            "INSERT INTO widgets (id, val) VALUES (?1, ?2)",
            params![99_i64, "preexisting"],
        )
        .expect("insert");

        let err = import_plaintext_copy(&conn, &dest_path, &["widgets"])
            .expect_err("import should refuse non-empty destination");
        assert!(
            err.to_string().contains("non-empty table"),
            "expected non-empty-table error, got: {err}"
        );
    }
}
