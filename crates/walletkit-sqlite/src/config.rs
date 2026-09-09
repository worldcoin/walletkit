//! Shared connection policy for encrypted and plaintext databases.

use crate::{Connection, DbResult, Error};

const FOREIGN_KEYS_ON: i64 = 1;
const SYNCHRONOUS_FULL: i64 = 2;
const SECURE_DELETE_ON: i64 = 1;
const TEMP_STORE_MEMORY: i64 = 2;

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
pub fn configure_connection(conn: &Connection) -> DbResult<()> {
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
#[cfg(test)]
mod tests {
    use crate::{
        cipher::open_encrypted, plaintext::open_plaintext, test_utils::init_sqlite,
    };
    use secrecy::SecretBox;

    #[test]
    fn both_open_paths_enforce_connection_policy() {
        init_sqlite();
        let dir = tempfile::tempdir().expect("create temp dir");
        let key = SecretBox::init_with(|| [0xAB; 32]);
        let encrypted =
            open_encrypted(&dir.path().join("encrypted.sqlite"), &key, false)
                .expect("open encrypted");
        let plaintext = open_plaintext(&dir.path().join("plaintext.sqlite"), false)
            .expect("open plaintext");
        for conn in [encrypted, plaintext] {
            for (pragma, expected) in
                [("synchronous", 2), ("secure_delete", 1), ("temp_store", 2)]
            {
                let actual = conn
                    .query_row(&format!("PRAGMA {pragma}"), &[], |row| {
                        Ok(row.column_i64(0))
                    })
                    .expect("read setting");
                assert_eq!(actual, expected, "{pragma}");
            }
            let journal = conn
                .query_row("PRAGMA journal_mode", &[], |row| Ok(row.column_text(0)))
                .expect("read journal mode");
            assert_eq!(journal, "wal");
            conn.execute_batch("CREATE TABLE parent(id INTEGER PRIMARY KEY); CREATE TABLE child(parent_id INTEGER REFERENCES parent(id));").expect("create tables");
            assert!(
                conn.execute_batch("INSERT INTO child VALUES (1)").is_err(),
                "foreign keys must be enforced"
            );
        }
    }
}
