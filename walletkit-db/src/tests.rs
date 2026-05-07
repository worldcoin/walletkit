//! Unit tests for the safe `SQLite` db wrapper.

use std::sync::OnceLock;

use crate::params;
use crate::sqlite::{cipher, Connection, Value};
use secrecy::SecretBox;

/// Ensures sqlite3mc's global codec registration is complete before any test
/// body runs.
///
/// sqlite3mc registers its cipher implementations the first time
/// `sqlite3_open_v2` is called.  When the test binary runs all tests in
/// parallel threads, two threads can race inside that one-time
/// initialization and one of them sees an "unknown cipher 'chacha20'"
/// error even though chacha20 is compiled in.
///
/// Calling this at the start of every test ensures exactly one thread
/// performs the first open (all others block on the `OnceLock`) so that
/// by the time any test-specific code runs, sqlite3mc is fully initialized.
fn init_sqlite() {
    static INIT: OnceLock<()> = OnceLock::new();
    INIT.get_or_init(|| {
        drop(Connection::open_in_memory().expect("sqlite3mc pre-init"));
    });
}

#[test]
fn test_open_in_memory() {
    init_sqlite();
    let conn = Connection::open_in_memory().expect("open in-memory db");
    conn.execute_batch("CREATE TABLE t (id INTEGER PRIMARY KEY, val TEXT);")
        .expect("create table");
    conn.execute(
        "INSERT INTO t (id, val) VALUES (?1, ?2)",
        params![1_i64, "hello"],
    )
    .expect("insert");
    let result = conn
        .query_row("SELECT val FROM t WHERE id = ?1", params![1_i64], |stmt| {
            Ok(stmt.column_text(0))
        })
        .expect("query");
    assert_eq!(result, "hello");
}

#[test]
fn test_query_row_optional_none() {
    init_sqlite();
    let conn = Connection::open_in_memory().expect("open in-memory db");
    conn.execute_batch("CREATE TABLE t (id INTEGER PRIMARY KEY);")
        .expect("create table");
    let result = conn
        .query_row_optional("SELECT id FROM t WHERE id = 999", &[], |stmt| {
            Ok(stmt.column_i64(0))
        })
        .expect("query");
    assert!(result.is_none());
}

#[test]
fn test_transaction_commit() {
    init_sqlite();
    let conn = Connection::open_in_memory().expect("open in-memory db");
    conn.execute_batch("CREATE TABLE t (id INTEGER PRIMARY KEY);")
        .expect("create table");
    {
        let tx = conn.transaction().expect("begin tx");
        tx.execute("INSERT INTO t (id) VALUES (?1)", params![42_i64])
            .expect("insert");
        tx.commit().expect("commit");
    }
    let result = conn
        .query_row("SELECT id FROM t WHERE id = 42", &[], |stmt| {
            Ok(stmt.column_i64(0))
        })
        .expect("query");
    assert_eq!(result, 42);
}

#[test]
fn test_transaction_rollback_on_drop() {
    init_sqlite();
    let conn = Connection::open_in_memory().expect("open in-memory db");
    conn.execute_batch("CREATE TABLE t (id INTEGER PRIMARY KEY);")
        .expect("create table");
    {
        let tx = conn.transaction().expect("begin tx");
        tx.execute("INSERT INTO t (id) VALUES (?1)", params![99_i64])
            .expect("insert");
        // Drop without commit -> rollback
    }
    let result = conn
        .query_row_optional("SELECT id FROM t WHERE id = 99", &[], |stmt| {
            Ok(stmt.column_i64(0))
        })
        .expect("query");
    assert!(result.is_none());
}

#[test]
fn test_blob_round_trip() {
    init_sqlite();
    let conn = Connection::open_in_memory().expect("open in-memory db");
    conn.execute_batch("CREATE TABLE t (id INTEGER PRIMARY KEY, data BLOB);")
        .expect("create table");
    let data = vec![0xDE, 0xAD, 0xBE, 0xEF];
    conn.execute(
        "INSERT INTO t (id, data) VALUES (?1, ?2)",
        params![1_i64, data.as_slice()],
    )
    .expect("insert");
    let result = conn
        .query_row("SELECT data FROM t WHERE id = 1", &[], |stmt| {
            Ok(stmt.column_blob(0))
        })
        .expect("query");
    assert_eq!(result, data);
}

#[test]
fn test_null_handling() {
    init_sqlite();
    let conn = Connection::open_in_memory().expect("open in-memory db");
    conn.execute_batch("CREATE TABLE t (id INTEGER PRIMARY KEY, val TEXT);")
        .expect("create table");
    conn.execute(
        "INSERT INTO t (id, val) VALUES (?1, ?2)",
        params![1_i64, Value::Null],
    )
    .expect("insert");
    let result = conn
        .query_row("SELECT val FROM t WHERE id = 1", &[], |stmt| {
            Ok(stmt.is_column_null(0))
        })
        .expect("query");
    assert!(result);
}

#[test]
fn test_cipher_encrypted_round_trip() {
    init_sqlite();
    let dir = tempfile::tempdir().expect("create temp dir");
    let path = dir.path().join("cipher-test.sqlite");
    let key = SecretBox::init_with(|| [0xABu8; 32]);

    // Create and write
    {
        let conn = cipher::open_encrypted(&path, &key, false).expect("open encrypted");
        conn.execute_batch("CREATE TABLE secret (id INTEGER PRIMARY KEY, val TEXT);")
            .expect("create table");
        conn.execute("INSERT INTO secret (id, val) VALUES (1, 'top-secret')", &[])
            .expect("insert");
    }

    // Re-open with correct key
    {
        let conn =
            cipher::open_encrypted(&path, &key, false).expect("reopen encrypted");
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
        let result = cipher::open_encrypted(&path, &wrong_key, false);
        assert!(result.is_err(), "wrong key should fail");
    }

    // dir is cleaned up on drop
}

#[test]
fn test_integrity_check() {
    init_sqlite();
    let conn = Connection::open_in_memory().expect("open in-memory db");
    let ok = cipher::integrity_check(&conn).expect("check");
    assert!(ok);
}
