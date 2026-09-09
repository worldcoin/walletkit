//! Persistent, unencrypted databases with the standard connection policy.

use std::path::Path;

use crate::{config::configure_connection, Connection, DbResult};

/// Opens an unencrypted database and applies the shared connection settings.
///
/// Uses the native filesystem or, on WASM, the initialized OPFS SAH pool.
/// Callers storing secrets must seal them before writing to this database.
///
/// # Errors
/// Returns an error if storage is unavailable, opening fails, or the connection
/// settings cannot be applied and verified.
pub fn open_plaintext(path: &Path, read_only: bool) -> DbResult<Connection> {
    #[cfg(not(target_arch = "wasm32"))]
    let conn = Connection::open(path, read_only)?;
    #[cfg(target_arch = "wasm32")]
    let conn =
        Connection::open_with_opfs_vfs(path, read_only, crate::opfs::OPFS_VFS_NAME)?;
    configure_connection(&conn)?;
    Ok(conn)
}

#[cfg(test)]
mod tests {
    use super::open_plaintext;
    use crate::test_utils::init_sqlite;

    #[test]
    fn plaintext_database_reopens_without_a_key() {
        init_sqlite();
        let dir = tempfile::tempdir().expect("create temp dir");
        let path = dir.path().join("plaintext.sqlite");
        {
            let conn = open_plaintext(&path, false).expect("open plaintext");
            conn.execute_batch("CREATE TABLE items(value TEXT NOT NULL); INSERT INTO items VALUES ('sealed blob');").expect("write");
        }
        assert!(std::fs::read(&path)
            .expect("read file")
            .starts_with(b"SQLite format 3\0"));
        let conn = open_plaintext(&path, true).expect("reopen read only");
        let value = conn
            .query_row("SELECT value FROM items", &[], |row| Ok(row.column_text(0)))
            .expect("read");
        assert_eq!(value, "sealed blob");
        assert!(conn.execute_batch("DELETE FROM items").is_err());
    }
}
