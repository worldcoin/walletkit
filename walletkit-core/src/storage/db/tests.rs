//! Unit tests for the safe SQLite db wrapper.

use super::*;

#[test]
fn test_open_in_memory() {
    let conn = Connection::open_in_memory().expect("open in-memory db");
    conn.execute_batch("CREATE TABLE t (id INTEGER PRIMARY KEY, val TEXT);")
        .expect("create table");
    conn.execute(
        "INSERT INTO t (id, val) VALUES (?1, ?2)",
        params![Value::Integer(1), Value::from("hello")],
    )
    .expect("insert");
    let result = conn
        .query_row("SELECT val FROM t WHERE id = ?1", params![Value::Integer(1)], |stmt| {
            Ok(stmt.column_text(0))
        })
        .expect("query");
    assert_eq!(result, "hello");
}

#[test]
fn test_query_row_optional_none() {
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
    let conn = Connection::open_in_memory().expect("open in-memory db");
    conn.execute_batch("CREATE TABLE t (id INTEGER PRIMARY KEY);")
        .expect("create table");
    {
        let tx = conn.transaction().expect("begin tx");
        tx.execute("INSERT INTO t (id) VALUES (?1)", params![Value::Integer(42)])
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
    let conn = Connection::open_in_memory().expect("open in-memory db");
    conn.execute_batch("CREATE TABLE t (id INTEGER PRIMARY KEY);")
        .expect("create table");
    {
        let tx = conn.transaction().expect("begin tx");
        tx.execute("INSERT INTO t (id) VALUES (?1)", params![Value::Integer(99)])
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
    let conn = Connection::open_in_memory().expect("open in-memory db");
    conn.execute_batch("CREATE TABLE t (id INTEGER PRIMARY KEY, data BLOB);")
        .expect("create table");
    let data = vec![0xDE, 0xAD, 0xBE, 0xEF];
    conn.execute(
        "INSERT INTO t (id, data) VALUES (?1, ?2)",
        params![Value::Integer(1), data.as_slice()],
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
    let conn = Connection::open_in_memory().expect("open in-memory db");
    conn.execute_batch("CREATE TABLE t (id INTEGER PRIMARY KEY, val TEXT);")
        .expect("create table");
    conn.execute(
        "INSERT INTO t (id, val) VALUES (?1, ?2)",
        params![Value::Integer(1), Value::Null],
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
    use std::path::PathBuf;
    let path = PathBuf::from(format!(
        "{}/walletkit-db-cipher-test-{}.sqlite",
        std::env::temp_dir().display(),
        uuid::Uuid::new_v4()
    ));
    let key = [0xABu8; 32];

    // Create and write
    {
        let conn = cipher::open_encrypted(&path, key, false).expect("open encrypted");
        conn.execute_batch("CREATE TABLE secret (id INTEGER PRIMARY KEY, val TEXT);")
            .expect("create table");
        conn.execute(
            "INSERT INTO secret (id, val) VALUES (1, 'top-secret')",
            &[],
        )
        .expect("insert");
    }

    // Re-open with correct key
    {
        let conn = cipher::open_encrypted(&path, key, false).expect("reopen encrypted");
        let val = conn
            .query_row("SELECT val FROM secret WHERE id = 1", &[], |stmt| {
                Ok(stmt.column_text(0))
            })
            .expect("query");
        assert_eq!(val, "top-secret");
    }

    // Wrong key should fail
    {
        let wrong_key = [0xCDu8; 32];
        let result = cipher::open_encrypted(&path, wrong_key, false);
        assert!(result.is_err(), "wrong key should fail");
    }

    // Clean up
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(path.with_extension("sqlite-wal"));
    let _ = std::fs::remove_file(path.with_extension("sqlite-shm"));
}

#[test]
fn test_integrity_check() {
    let conn = Connection::open_in_memory().expect("open in-memory db");
    let ok = cipher::integrity_check(&conn).expect("check");
    assert!(ok);
}
