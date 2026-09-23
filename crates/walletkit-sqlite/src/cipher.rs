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
//! 3. **Detect and encrypt or unlock** -- A read from `sqlite_master` succeeds
//!    for a plaintext (or new) database. Such a database is moved out of WAL
//!    mode and atomically encrypted with `PRAGMA rekey`. Existing databases
//!    with a fully encrypted header are unlocked using their old settings and
//!    migrated in place. Both `key` and `rekey` receive the 32-byte
//!    `K_intermediate` as a raw hex key, bypassing the passphrase KDF.
//!
//! 4. **Verify** -- We read from `sqlite_master` after rekeying or keying. A
//!    wrong key returns `SQLITE_NOTADB` because the decrypted page header does
//!    not match the expected `SQLite` magic bytes.
//!
//! 5. **Configure connection** -- The target-specific journal mode and every
//!    connection-level invariant are set and verified.
//!
//! The default cipher is **ChaCha20-Poly1305** (authenticated encryption).
//! All crypto is built into the `sqlite3mc` amalgamation -- no OpenSSL or
//! other external crypto library is needed on any platform.
//!
//! The first 32 bytes of every database header remain plaintext. This gives
//! all targets one on-disk format and lets iOS recognize shared-container
//! databases in WAL mode. Existing databases with fully encrypted headers are
//! migrated in place on their first successful open.

use std::path::Path;

use secrecy::{ExposeSecret, SecretBox};
use zeroize::Zeroizing;

use super::connection::Connection;
use super::error::{DbResult, Error};

const CIPHER_CHACHA20: &str = "chacha20";
const PLAINTEXT_HEADER_SIZE: i64 = 32;
const SQLITE_ERROR: i32 = 1;
const SQLITE_CORRUPT: i32 = 11;
const FOREIGN_KEYS_ON: i64 = 1;
const SYNCHRONOUS_FULL: i64 = 2;
const SECURE_DELETE_ON: i64 = 1;
const TEMP_STORE_MEMORY: i64 = 2;

/// Opens a writable database, applies the encryption key, and configures the connection.
///
/// This is the standard open sequence for databases: open -> select cipher ->
/// encrypt plaintext or unlock encrypted data -> verify -> configure policy.
///
/// See the [module-level documentation](self) for the full encryption flow.
///
/// # Errors
///
/// Returns `Error` if opening, keying, or configuring the connection fails.
pub fn open_encrypted(
    path: &Path,
    k_intermediate: &SecretBox<[u8; 32]>,
) -> DbResult<Connection> {
    #[cfg(not(target_arch = "wasm32"))]
    let conn = Connection::open(path, false)?;
    #[cfg(target_arch = "wasm32")]
    let conn = Connection::open_with_opfs_vfs(path, false)?;
    configure_connection(&conn, k_intermediate)?;
    Ok(conn)
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
    encrypt_or_unlock(conn, k_intermediate)?;

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

/// Encrypts or unlocks a database with a plaintext `SQLite` header.
///
/// Earlier `WalletKit` versions encrypted the header completely. Those databases
/// must first be opened with the old settings, moved out of WAL mode, and rekeyed
/// after configuring the plaintext header. Databases that already start with the
/// `SQLite` magic bytes are either plaintext or already use the new format;
/// probing the schema before applying the key distinguishes the two cases.
fn encrypt_or_unlock(
    conn: &Connection,
    k_intermediate: &SecretBox<[u8; 32]>,
) -> DbResult<()> {
    match verify_schema_readable(conn) {
        Ok(()) => {
            // Plaintext (or newly-created) database. Configure the new format
            // before the first rekey so it is never written with an encrypted
            // header.
            ensure_journal_mode(conn, "DELETE")?;
            ensure_plaintext_header(conn)?;
            apply_rekey(conn, k_intermediate)?;
            verify_encryption(conn, "plaintext database encryption verification failed")
        }
        Err(error) if is_plaintext_header_probe_error(&error) => {
            // The SQLite header is visible but the schema is not readable
            // without the codec: this is already the plaintext-header format.
            ensure_plaintext_header(conn)?;
            apply_key(conn, k_intermediate)
        }
        Err(error) if error.code.0 & 0xff == super::ffi::SQLITE_NOTADB => {
            // Legacy WalletKit format. Unlock it with the encrypted-header
            // settings, checkpoint WAL, then atomically rekey with the same raw
            // key after selecting the common plaintext-header format.
            apply_key(conn, k_intermediate)?;
            ensure_journal_mode(conn, "DELETE")?;
            ensure_plaintext_header(conn)?;
            apply_rekey(conn, k_intermediate)?;
            verify_encryption(conn, "plaintext-header migration verification failed")
        }
        Err(error) => Err(error),
    }
}

/// A plaintext-header encrypted page exposes format fields that vanilla
/// `SQLite` tries to parse before the codec is configured. Depending on the
/// encrypted page bytes, that probe can fail either while validating the
/// header fields or while parsing the page body.
fn is_plaintext_header_probe_error(error: &Error) -> bool {
    let primary_code = error.code.0 & 0xff;
    (primary_code == SQLITE_ERROR && error.message == "unsupported file format")
        || (primary_code == SQLITE_CORRUPT
            && error.message == "database disk image is malformed")
}

fn ensure_plaintext_header(conn: &Connection) -> DbResult<()> {
    conn.execute_batch(&format!(
        "PRAGMA plaintext_header_size = {PLAINTEXT_HEADER_SIZE};"
    ))?;
    let actual = conn.query_row("PRAGMA plaintext_header_size;", &[], |row| {
        Ok(row.column_i64(0))
    })?;
    if actual == PLAINTEXT_HEADER_SIZE {
        Ok(())
    } else {
        Err(Error::new(
            -1,
            format!(
                "could not ensure plaintext header size {PLAINTEXT_HEADER_SIZE}: SQLite selected {actual}"
            ),
        ))
    }
}

/// Encrypts or unlocks a database using `WalletKit`'s legacy fully encrypted
/// header format. Kept only to construct migration fixtures.
#[cfg(test)]
fn encrypt_or_unlock_fully_encrypted(
    conn: &Connection,
    k_intermediate: &SecretBox<[u8; 32]>,
) -> DbResult<()> {
    match verify_schema_readable(conn) {
        Ok(()) => {
            ensure_journal_mode(conn, "DELETE")?;
            apply_rekey(conn, k_intermediate)?;
            verify_encryption(conn, "plaintext database encryption verification failed")
        }
        Err(error) if error.code.0 & 0xff == super::ffi::SQLITE_NOTADB => {
            apply_key(conn, k_intermediate)
        }
        Err(error) => Err(error),
    }
}

fn verify_encryption(conn: &Connection, context: &str) -> DbResult<()> {
    verify_schema_readable(conn).map_err(|error| {
        Error::new(error.code.0, format!("{context}: {}", error.message))
    })
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
    let pragma = raw_key_pragma("key", k_intermediate);

    // execute_batch_zeroized ensures the internal CString copy of the PRAGMA
    // (which contains the hex key) is zeroized after the FFI call returns.
    conn.execute_batch_zeroized(&pragma)?;

    // Touch a page to verify the key works. On failure this produces a clear
    // error rather than a confusing "not a database" later during schema setup.
    verify_schema_readable(conn).map_err(|e| {
        Error::new(
            e.code.0,
            format!(
                "encryption key verification failed (is the key correct?): {}",
                e.message
            ),
        )
    })?;

    // k_intermediate and pragma are zeroized on drop regardless of which exit
    // path we took. raw_key_pragma zeroizes its temporary hex buffer too.
    Ok(())
}

/// Encrypts a readable plaintext database in place with the supplied raw key.
fn apply_rekey(
    conn: &Connection,
    k_intermediate: &SecretBox<[u8; 32]>,
) -> DbResult<()> {
    let pragma = raw_key_pragma("rekey", k_intermediate);
    conn.execute_batch_zeroized(&pragma).map_err(|e| {
        Error::new(
            e.code.0,
            format!("failed to encrypt plaintext database: {}", e.message),
        )
    })
}

fn raw_key_pragma(
    operation: &str,
    k_intermediate: &SecretBox<[u8; 32]>,
) -> Zeroizing<String> {
    let key_hex = Zeroizing::new(hex::encode(k_intermediate.expose_secret()));
    Zeroizing::new(format!("PRAGMA {operation} = \"x'{}'\";", key_hex.as_str()))
}

fn verify_schema_readable(conn: &Connection) -> DbResult<()> {
    conn.execute_batch("SELECT count(*) FROM sqlite_master;")
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
        encrypt_or_unlock_fully_encrypted, ensure_cipher, ensure_journal_mode,
        export_plaintext_copy, import_plaintext_copy, integrity_check,
        is_plaintext_header_probe_error, open_encrypted, Error, SQLITE_CORRUPT,
        SQLITE_ERROR,
    };
    use crate::params;
    use crate::test_utils::init_sqlite;
    use crate::Connection;
    use secrecy::SecretBox;

    fn open_fully_encrypted(
        path: &std::path::Path,
        key: &SecretBox<[u8; 32]>,
    ) -> crate::DbResult<Connection> {
        let conn = Connection::open(path, false)?;
        ensure_cipher(&conn)?;
        encrypt_or_unlock_fully_encrypted(&conn, key)?;
        ensure_journal_mode(&conn, "WAL")?;
        Ok(conn)
    }

    #[test]
    fn test_plaintext_header_probe_errors() {
        assert!(is_plaintext_header_probe_error(&Error::new(
            SQLITE_ERROR,
            "unsupported file format",
        )));
        assert!(is_plaintext_header_probe_error(&Error::new(
            SQLITE_CORRUPT,
            "database disk image is malformed",
        )));
        assert!(!is_plaintext_header_probe_error(&Error::new(
            SQLITE_CORRUPT,
            "database or disk is full",
        )));
    }

    #[test]
    fn test_cipher_encrypted_round_trip() {
        init_sqlite();
        let dir = tempfile::tempdir().expect("create temp dir");
        let path = dir.path().join("cipher-test.sqlite");
        let key = SecretBox::init_with(|| [0xABu8; 32]);

        // Create and write
        {
            let conn = open_encrypted(&path, &key).expect("open encrypted");
            conn.execute_batch(
                "CREATE TABLE secret (id INTEGER PRIMARY KEY, val TEXT);",
            )
            .expect("create table");
            conn.execute("INSERT INTO secret (id, val) VALUES (1, 'top-secret')", &[])
                .expect("insert");
        }

        // Re-open with correct key
        {
            let conn = open_encrypted(&path, &key).expect("reopen encrypted");
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
            let result = open_encrypted(&path, &wrong_key);
            assert!(result.is_err(), "wrong key should fail");
        }
    }

    #[test]
    fn test_plaintext_wal_database_migrates_to_plaintext_header() {
        init_sqlite();
        let dir = tempfile::tempdir().expect("create temp dir");
        let path = dir.path().join("plaintext.sqlite");
        let key = SecretBox::init_with(|| [0x42u8; 32]);

        {
            let conn = Connection::open(&path, false).expect("open plaintext");
            let mode = conn
                .query_row("PRAGMA journal_mode = WAL", &[], |row| {
                    Ok(row.column_text(0))
                })
                .expect("enable plaintext WAL");
            assert_eq!(mode.to_ascii_lowercase(), "wal");
            conn.execute_batch(
                "CREATE TABLE secret (id INTEGER PRIMARY KEY, val TEXT);\
                 INSERT INTO secret VALUES (1, 'preserve-me');",
            )
            .expect("write plaintext data");
        }
        assert!(
            std::fs::read(&path)
                .expect("read plaintext")
                .starts_with(b"SQLite format 3\0"),
            "fixture must start as plaintext SQLite"
        );

        {
            let conn = open_encrypted(&path, &key).expect("migrate plaintext");
            let value = conn
                .query_row("SELECT val FROM secret WHERE id = 1", &[], |row| {
                    Ok(row.column_text(0))
                })
                .expect("read migrated data");
            assert_eq!(value, "preserve-me");
        }

        let encrypted_bytes = std::fs::read(&path).expect("read encrypted");
        assert!(
            encrypted_bytes.starts_with(b"SQLite format 3\0"),
            "migration must retain the plaintext SQLite header"
        );
        assert_eq!(encrypted_bytes[18], 2, "database must use WAL read mode");
        assert_eq!(encrypted_bytes[19], 2, "database must use WAL write mode");
        assert_eq!(
            encrypted_bytes[20], 32,
            "header must advertise the cipher's reserved bytes"
        );
        assert!(
            !encrypted_bytes
                .windows("preserve-me".len())
                .any(|window| window == b"preserve-me"),
            "database contents must be encrypted"
        );

        {
            let conn = open_encrypted(&path, &key).expect("reopen migrated database");
            let value = conn
                .query_row("SELECT val FROM secret WHERE id = 1", &[], |row| {
                    Ok(row.column_text(0))
                })
                .expect("read migrated data after reopen");
            assert_eq!(value, "preserve-me");
        }

        let wrong_key = SecretBox::init_with(|| [0x43u8; 32]);
        assert!(
            open_encrypted(&path, &wrong_key).is_err(),
            "migrated database must reject the wrong key"
        );
        assert_eq!(
            std::fs::read(&path).expect("read after wrong-key open"),
            encrypted_bytes,
            "wrong-key open must not modify migrated data"
        );
    }

    #[test]
    fn test_plaintext_header_encrypted_round_trip() {
        init_sqlite();
        let dir = tempfile::tempdir().expect("create temp dir");
        let path = dir.path().join("plaintext-header.sqlite");
        let key = SecretBox::init_with(|| [0x51_u8; 32]);

        {
            let conn =
                open_encrypted(&path, &key).expect("create plaintext-header database");
            conn.execute_batch(
                "CREATE TABLE secret (id INTEGER PRIMARY KEY, val TEXT);\
                 INSERT INTO secret VALUES (1, 'visible-header');",
            )
            .expect("write encrypted data");
        }

        let encrypted_bytes = std::fs::read(&path).expect("read encrypted database");
        assert!(
            encrypted_bytes.starts_with(b"SQLite format 3\0"),
            "the SQLite file header must remain visible"
        );
        assert_eq!(encrypted_bytes[18], 2, "database must use WAL read mode");
        assert_eq!(encrypted_bytes[19], 2, "database must use WAL write mode");
        assert_eq!(
            encrypted_bytes[20], 32,
            "header must advertise the cipher's reserved bytes"
        );
        assert!(
            !encrypted_bytes
                .windows("visible-header".len())
                .any(|window| window == b"visible-header"),
            "database contents must remain encrypted"
        );

        {
            let conn =
                open_encrypted(&path, &key).expect("reopen plaintext-header database");
            let value = conn
                .query_row("SELECT val FROM secret WHERE id = 1", &[], |row| {
                    Ok(row.column_text(0))
                })
                .expect("read encrypted data");
            assert_eq!(value, "visible-header");
        }

        let wrong_key = SecretBox::init_with(|| [0x52_u8; 32]);
        assert!(
            open_encrypted(&path, &wrong_key).is_err(),
            "plaintext-header database must reject the wrong key"
        );
        assert_eq!(
            std::fs::read(&path).expect("read after wrong-key open"),
            encrypted_bytes,
            "wrong-key open must not modify encrypted data"
        );
    }

    /// Key for [`LEGACY_ENCRYPTED_HEADER_FIXTURE`]. `WalletKit` releases before
    /// the plaintext-header change encrypted the header with this raw key.
    const LEGACY_FIXTURE_KEY: [u8; 32] = [0x61; 32];

    /// Database written by a pre-plaintext-header `WalletKit` release, frozen so
    /// compatibility is measured against real old bytes rather than whatever
    /// the current codec happens to produce. Regenerate only when the legacy
    /// format itself must change:
    /// `cargo test -p walletkit-sqlite --lib -- --ignored regenerate_legacy_encrypted_header_fixture`.
    const LEGACY_ENCRYPTED_HEADER_FIXTURE: &[u8] =
        include_bytes!("../tests/fixtures/legacy_encrypted_header.sqlite");

    #[test]
    #[ignore = "regenerates the checked-in legacy migration fixture"]
    fn regenerate_legacy_encrypted_header_fixture() {
        init_sqlite();
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/legacy_encrypted_header.sqlite");
        std::fs::create_dir_all(path.parent().expect("fixture has a parent"))
            .expect("create fixtures directory");
        let _ = std::fs::remove_file(&path);
        let key = SecretBox::init_with(|| LEGACY_FIXTURE_KEY);

        {
            let conn =
                open_fully_encrypted(&path, &key).expect("create legacy fixture");
            conn.execute_batch(
                "CREATE TABLE secret (id INTEGER PRIMARY KEY, val TEXT);\
                 INSERT INTO secret VALUES (1, 'preserve-me');",
            )
            .expect("write legacy fixture");
        }

        let bytes = std::fs::read(&path).expect("read regenerated fixture");
        assert!(
            !bytes.starts_with(b"SQLite format 3\0"),
            "regenerated fixture must use the fully-encrypted legacy header"
        );
    }

    #[test]
    fn test_frozen_legacy_encrypted_header_database_migrates() {
        init_sqlite();
        let dir = tempfile::tempdir().expect("create temp dir");
        let path = dir.path().join("legacy-encrypted-header.sqlite");
        let key = SecretBox::init_with(|| LEGACY_FIXTURE_KEY);
        std::fs::write(&path, LEGACY_ENCRYPTED_HEADER_FIXTURE)
            .expect("write fixture copy");

        assert!(
            !LEGACY_ENCRYPTED_HEADER_FIXTURE.starts_with(b"SQLite format 3\0"),
            "fixture must use the fully-encrypted legacy header"
        );
        assert!(
            !LEGACY_ENCRYPTED_HEADER_FIXTURE
                .windows("preserve-me".len())
                .any(|window| window == b"preserve-me"),
            "fixture contents must be encrypted"
        );

        let wrong_key = SecretBox::init_with(|| [0x62u8; 32]);
        assert!(
            open_encrypted(&path, &wrong_key).is_err(),
            "legacy fixture must reject the wrong key before migration"
        );
        assert_eq!(
            std::fs::read(&path)
                .expect("read fixture after wrong-key open")
                .as_slice(),
            LEGACY_ENCRYPTED_HEADER_FIXTURE,
            "wrong-key open must not migrate or modify the frozen fixture"
        );

        {
            let conn = open_encrypted(&path, &key).expect("migrate legacy fixture");
            let value = conn
                .query_row("SELECT val FROM secret WHERE id = 1", &[], |row| {
                    Ok(row.column_text(0))
                })
                .expect("read migrated data");
            assert_eq!(value, "preserve-me");
        }

        let migrated_bytes = std::fs::read(&path).expect("read migrated database");
        assert!(
            migrated_bytes.starts_with(b"SQLite format 3\0"),
            "migration must expose the SQLite header"
        );
        assert_eq!(migrated_bytes[18], 2, "database must use WAL read mode");
        assert_eq!(migrated_bytes[19], 2, "database must use WAL write mode");
        assert_eq!(
            migrated_bytes[20], 32,
            "header must advertise the cipher's reserved bytes"
        );
        assert_ne!(
            migrated_bytes.as_slice(),
            LEGACY_ENCRYPTED_HEADER_FIXTURE,
            "migration must rewrite the encrypted on-disk format"
        );
        assert!(
            !migrated_bytes
                .windows("preserve-me".len())
                .any(|window| window == b"preserve-me"),
            "migrated database contents must remain encrypted"
        );

        {
            let conn = open_encrypted(&path, &key).expect("reopen migrated database");
            let value = conn
                .query_row("SELECT val FROM secret WHERE id = 1", &[], |row| {
                    Ok(row.column_text(0))
                })
                .expect("read migrated data after reopen");
            assert_eq!(value, "preserve-me");
        }

        assert!(
            open_encrypted(&path, &wrong_key).is_err(),
            "migrated database must reject the wrong key"
        );
        assert_eq!(
            std::fs::read(&path).expect("read migrated database after wrong-key open"),
            migrated_bytes,
            "wrong-key open must not modify migrated data"
        );
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
            let conn = open_encrypted(&src_path, &key).expect("open src");
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
            let conn = open_encrypted(&restore_path, &key).expect("open restore");
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
            let conn = open_encrypted(&src_path, &key).expect("open src");
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

        let conn = open_encrypted(&restore_path, &key).expect("open restore");
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
