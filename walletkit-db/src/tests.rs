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

#[test]
fn test_cipher_plaintext_export_import_roundtrip() {
    init_sqlite();
    let dir = tempfile::tempdir().expect("create temp dir");
    let src_path = dir.path().join("source.sqlite");
    let dest_path = dir.path().join("backup.plain.sqlite");
    let restore_path = dir.path().join("restore.sqlite");
    let key = SecretBox::init_with(|| [0x11u8; 32]);

    {
        let conn = cipher::open_encrypted(&src_path, &key, false).expect("open src");
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

        cipher::export_plaintext_copy(&conn, &dest_path, &["widgets"]).expect("export");
    }

    {
        let conn =
            cipher::open_encrypted(&restore_path, &key, false).expect("open restore");
        conn.execute_batch(
            "CREATE TABLE widgets (id INTEGER PRIMARY KEY, val TEXT NOT NULL);",
        )
        .expect("create table");
        cipher::import_plaintext_copy(&conn, &dest_path, &["widgets"]).expect("import");

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
        let conn = cipher::open_encrypted(&src_path, &key, false).expect("open src");
        conn.execute_batch(
            "CREATE TABLE widgets (id INTEGER PRIMARY KEY, val TEXT NOT NULL);",
        )
        .expect("create table");
        conn.execute(
            "INSERT INTO widgets (id, val) VALUES (?1, ?2)",
            params![1_i64, "alpha"],
        )
        .expect("insert");
        cipher::export_plaintext_copy(&conn, &dest_path, &["widgets"]).expect("export");
    }

    let conn =
        cipher::open_encrypted(&restore_path, &key, false).expect("open restore");
    conn.execute_batch(
        "CREATE TABLE widgets (id INTEGER PRIMARY KEY, val TEXT NOT NULL);",
    )
    .expect("create table");
    conn.execute(
        "INSERT INTO widgets (id, val) VALUES (?1, ?2)",
        params![99_i64, "preexisting"],
    )
    .expect("insert");

    let err = cipher::import_plaintext_copy(&conn, &dest_path, &["widgets"])
        .expect_err("import should refuse non-empty destination");
    assert!(
        err.to_string().contains("non-empty table"),
        "expected non-empty-table error, got: {err}"
    );
}

// -------------------------------------------------------------------------
// Storage primitives: blobs, envelope, lock, vault
// -------------------------------------------------------------------------

mod primitives {
    //! Storage-primitive tests: `compute_content_id` and `KeyEnvelope`
    //! frozen-byte format guards, `Lock` exclusivity and cross-thread
    //! serialization, `init_or_open_envelope_key` round-trip, and
    //! `Vault::open` schema-callback / wrong-key behavior.

    use super::init_sqlite;
    use crate::envelope::KeyEnvelope;
    use crate::{
        blobs, compute_content_id, init_or_open_envelope_key, AtomicBlobStore,
        Keystore, Lock, StoreError, StoreResult, Vault,
    };
    use secrecy::{ExposeSecret, SecretBox};
    use std::sync::Mutex;

    #[test]
    fn test_compute_content_id_byte_stable() {
        // SHA-256(b"worldid:blob" || [0x01] || b"hello"). Frozen value;
        // changing this hash means breaking every existing user database.
        let cid = compute_content_id(1, b"hello");
        let expected: [u8; 32] = hex::decode(
            "ed4eba40f11beec64d0607586f09b7529418ef31bf2c46cf9b8b905615f2e7ca",
        )
        .expect("decode hex")
        .try_into()
        .expect("32 bytes");
        assert_eq!(cid, expected);

        let cid2 = compute_content_id(2, b"hello");
        assert_ne!(cid, cid2, "kind tag must affect content id");
    }

    #[test]
    fn test_key_envelope_round_trip() {
        let envelope = KeyEnvelope::new(vec![1, 2, 3], 123);
        let bytes = envelope.serialize().expect("serialize");
        let decoded = KeyEnvelope::deserialize(&bytes).expect("deserialize");
        assert_eq!(decoded.version, 1);
        assert_eq!(decoded.wrapped_k_intermediate, vec![1, 2, 3]);
        assert_eq!(decoded.created_at, 123);
        assert_eq!(decoded.updated_at, 123);
    }

    #[test]
    fn test_key_envelope_cbor_bytes_frozen() {
        // Frozen CBOR encoding for the canonical envelope. Round-trip alone
        // doesn't catch field-order or type drift; this byte-level check
        // does. Updating this hex without an on-disk format review breaks
        // every existing user database.
        let envelope = KeyEnvelope::new(vec![1, 2, 3], 123);
        let bytes = envelope.serialize().expect("serialize");
        // CBOR map of 4 entries: version=1, wrapped_k_intermediate=[1,2,3],
        // created_at=123, updated_at=123. Reproducible from the struct;
        // hex captured by serializing the canonical envelope above.
        let expected = hex::decode(
            "a46776657273696f6e0176777261707065645f6b5f696e7465726d656469617465830102036a637265617465645f6174187b6a757064617465645f6174187b",
        ).expect("decode hex");
        assert_eq!(
            bytes, expected,
            "KeyEnvelope CBOR layout changed; on-disk envelope format would drift"
        );
    }

    #[test]
    fn test_key_envelope_unsupported_version() {
        let mut envelope = KeyEnvelope::new(vec![1, 2, 3], 123);
        envelope.version = 99;
        let bytes = envelope.serialize().expect("serialize");
        match KeyEnvelope::deserialize(&bytes) {
            Err(StoreError::UnsupportedEnvelopeVersion(v)) => assert_eq!(v, 99),
            Err(err) => panic!("expected UnsupportedEnvelopeVersion, got: {err}"),
            Ok(_) => panic!("expected UnsupportedEnvelopeVersion, got Ok"),
        }
    }

    #[test]
    #[cfg(not(target_arch = "wasm32"))]
    fn test_lock_is_exclusive() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let path = dir.path().join("lock.lock");
        let lock_a = Lock::open(&path).expect("open lock");
        let guard = lock_a.lock().expect("acquire lock");

        let lock_b = Lock::open(&path).expect("open lock");
        let blocked = lock_b.try_lock().expect("try lock");
        assert!(blocked.is_none());

        drop(guard);
        let guard = lock_b.try_lock().expect("try lock");
        assert!(guard.is_some());
    }

    #[test]
    #[cfg(not(target_arch = "wasm32"))]
    fn test_lock_serializes_across_threads() {
        use std::sync::mpsc;
        use std::thread;

        let dir = tempfile::tempdir().expect("create temp dir");
        let path = dir.path().join("lock.lock");
        let lock = Lock::open(&path).expect("open lock");

        let (locked_tx, locked_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let (released_tx, released_rx) = mpsc::channel();

        let thread_a = thread::spawn(move || {
            let guard = lock.lock().expect("lock in thread");
            locked_tx.send(()).expect("signal locked");
            release_rx.recv().expect("wait release");
            drop(guard);
            released_tx.send(()).expect("signal released");
        });

        locked_rx.recv().expect("wait locked");
        let lock_b = Lock::open(&path).expect("open lock");
        let blocked = lock_b.try_lock().expect("try lock");
        assert!(blocked.is_none());

        release_tx.send(()).expect("release");
        released_rx.recv().expect("wait released");

        let guard = lock_b.try_lock().expect("try lock");
        assert!(guard.is_some());

        thread_a.join().expect("thread join");
    }

    /// Stub `Keystore` that XORs with a fixed pad. Good enough to verify
    /// the seal → persist → open round-trip on the envelope wiring.
    struct XorKeystore {
        pad: [u8; 32],
    }

    impl Keystore for XorKeystore {
        fn seal(&self, _ad: Vec<u8>, plaintext: Vec<u8>) -> StoreResult<Vec<u8>> {
            Ok(plaintext
                .iter()
                .enumerate()
                .map(|(i, b)| b ^ self.pad[i % 32])
                .collect())
        }
        fn open_sealed(
            &self,
            _ad: Vec<u8>,
            ciphertext: Vec<u8>,
        ) -> StoreResult<Vec<u8>> {
            Ok(ciphertext
                .iter()
                .enumerate()
                .map(|(i, b)| b ^ self.pad[i % 32])
                .collect())
        }
    }

    struct InMemoryBlobs {
        inner: Mutex<std::collections::HashMap<String, Vec<u8>>>,
    }
    impl InMemoryBlobs {
        fn new() -> Self {
            Self {
                inner: Mutex::new(std::collections::HashMap::new()),
            }
        }
    }
    impl AtomicBlobStore for InMemoryBlobs {
        fn read(&self, path: String) -> StoreResult<Option<Vec<u8>>> {
            Ok(self.inner.lock().unwrap().get(&path).cloned())
        }
        fn write_atomic(&self, path: String, bytes: Vec<u8>) -> StoreResult<()> {
            self.inner.lock().unwrap().insert(path, bytes);
            Ok(())
        }
        fn delete(&self, path: String) -> StoreResult<()> {
            self.inner.lock().unwrap().remove(&path);
            Ok(())
        }
    }

    #[test]
    #[cfg(not(target_arch = "wasm32"))]
    fn test_init_or_open_envelope_key_round_trip() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let lock_path = dir.path().join("envelope.lock");
        let lock = Lock::open(&lock_path).expect("open lock");

        let keystore = XorKeystore { pad: [0xAA; 32] };
        let blob_store = InMemoryBlobs::new();
        let key_a = init_or_open_envelope_key(
            &keystore,
            &blob_store,
            &lock,
            "k.bin",
            b"test-ad",
            100,
        )
        .expect("init");
        let key_b = init_or_open_envelope_key(
            &keystore,
            &blob_store,
            &lock,
            "k.bin",
            b"test-ad",
            200,
        )
        .expect("re-open");

        assert_eq!(key_a.expose_secret(), key_b.expose_secret());
    }

    #[test]
    #[cfg(not(target_arch = "wasm32"))]
    fn test_vault_open_runs_schema_callback() {
        init_sqlite();
        let dir = tempfile::tempdir().expect("create temp dir");
        let db_path = dir.path().join("vault.sqlite");
        let lock_path = dir.path().join("vault.lock");
        let lock = Lock::open(&lock_path).expect("open lock");
        let key = SecretBox::init_with(|| [0x42u8; 32]);

        let vault = Vault::open(&db_path, &key, lock, |conn| {
            blobs::ensure_schema(conn)?;
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS items (id INTEGER PRIMARY KEY);",
            )
        })
        .expect("open vault");

        let cid: crate::ContentId = vault
            .mutate::<_, StoreError, _>(|conn| blobs::put(conn, 7, b"payload", 1000))
            .expect("put");
        let bytes = blobs::get(vault.read(), &cid)
            .expect("get")
            .expect("present");
        assert_eq!(bytes, b"payload");
    }

    #[test]
    #[cfg(not(target_arch = "wasm32"))]
    fn test_vault_open_rejects_wrong_key() {
        init_sqlite();
        let dir = tempfile::tempdir().expect("create temp dir");
        let db_path = dir.path().join("vault.sqlite");
        let lock_path = dir.path().join("vault.lock");
        let lock = Lock::open(&lock_path).expect("open lock");
        let key = SecretBox::init_with(|| [0x11u8; 32]);
        let _ = Vault::open(&db_path, &key, lock.clone(), blobs::ensure_schema)
            .expect("create vault");
        let wrong = SecretBox::init_with(|| [0x22u8; 32]);
        let err =
            Vault::open(&db_path, &wrong, lock, |_| Ok(())).expect_err("wrong key");
        assert!(matches!(err, StoreError::Db(_)));
    }

    #[test]
    #[cfg(not(target_arch = "wasm32"))]
    fn test_vault_mutate_serializes_writes() {
        init_sqlite();
        let dir = tempfile::tempdir().expect("create temp dir");
        let db_path = dir.path().join("vault.sqlite");
        let lock_path = dir.path().join("vault.lock");
        let lock = Lock::open(&lock_path).expect("open lock");
        let key = SecretBox::init_with(|| [0x55u8; 32]);

        let vault = Vault::open(&db_path, &key, lock, blobs::ensure_schema)
            .expect("open vault");

        // Two mutations in sequence; lock acquired/released around each.
        vault
            .mutate::<_, StoreError, _>(|conn| {
                blobs::put(conn, 1, b"a", 100)?;
                Ok(())
            })
            .expect("first mutate");
        vault
            .mutate::<_, StoreError, _>(|conn| {
                blobs::put(conn, 1, b"b", 200)?;
                Ok(())
            })
            .expect("second mutate");

        // Reads after the lock is released.
        let cid_a = blobs::compute_content_id(1, b"a");
        let cid_b = blobs::compute_content_id(1, b"b");
        assert_eq!(blobs::get(vault.read(), &cid_a).unwrap().unwrap(), b"a");
        assert_eq!(blobs::get(vault.read(), &cid_b).unwrap().unwrap(), b"b");
    }
}
