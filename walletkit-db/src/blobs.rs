//! Content-addressed blob storage shared across consumer vaults.
//!
//! Blobs are stored in a single table (`blob_objects`) keyed by the SHA-256
//! of `b"worldid:blob" || [kind] || plaintext`. Each consumer passes its own
//! one-byte `kind` tag so credential payloads, PCP packages, etc. share the
//! table without colliding by content.
//!
//! ### On-disk schema (must remain byte-stable)
//!
//! ```sql
//! CREATE TABLE IF NOT EXISTS blob_objects (
//!     content_id  BLOB    NOT NULL,
//!     blob_kind   INTEGER NOT NULL,
//!     created_at  INTEGER NOT NULL,
//!     bytes       BLOB    NOT NULL,
//!     PRIMARY KEY (content_id)
//! );
//! ```

use sha2::{Digest, Sha256};

use crate::error::{StoreError, StoreResult};
use crate::params;
use crate::sqlite::{Connection, DbResult, Error as DbError};

const CONTENT_ID_PREFIX: &[u8] = b"worldid:blob";

/// 32-byte content identifier for a stored blob.
pub type ContentId = [u8; 32];

/// Computes the content id for a blob.
///
/// Layout: `SHA-256(b"worldid:blob" || [kind] || plaintext)`. The output is
/// byte-stable; changes to this function break every existing user database.
#[must_use]
pub fn compute_content_id(kind: u8, plaintext: &[u8]) -> ContentId {
    let mut hasher = Sha256::new();
    hasher.update(CONTENT_ID_PREFIX);
    hasher.update([kind]);
    hasher.update(plaintext);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Creates the `blob_objects` table if it does not exist.
///
/// Idempotent. The exact DDL is part of the on-disk format contract;
/// callers must not alter the schema.
///
/// # Errors
///
/// Returns a database error if the `CREATE TABLE` statement fails.
pub fn ensure_schema(conn: &Connection) -> DbResult<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS blob_objects (
            content_id  BLOB    NOT NULL,
            blob_kind   INTEGER NOT NULL,
            created_at  INTEGER NOT NULL,
            bytes       BLOB    NOT NULL,
            PRIMARY KEY (content_id)
        );",
    )
}

/// Inserts a blob with `INSERT OR IGNORE` semantics.
///
/// Returns the content id (deterministic from `kind` + `bytes`); if a row
/// with that id already exists the call is a no-op and the existing row is
/// left in place.
///
/// # Errors
///
/// Returns a [`StoreError`] if `now` overflows `i64` or the insert fails.
pub fn put(
    conn: &Connection,
    kind: u8,
    bytes: &[u8],
    now: u64,
) -> StoreResult<ContentId> {
    let now_i64 = i64::try_from(now).map_err(|_| {
        StoreError::Db(DbError::new(-1, format!("now out of range for i64: {now}")))
    })?;
    let cid = compute_content_id(kind, bytes);
    conn.execute(
        "INSERT OR IGNORE INTO blob_objects (content_id, blob_kind, created_at, bytes)
         VALUES (?1, ?2, ?3, ?4)",
        params![cid.as_ref(), i64::from(kind), now_i64, bytes],
    )?;
    Ok(cid)
}

/// Fetches blob bytes by content id, if present.
///
/// Accepts any byte slice so callers can pass `&ContentId`, a slice read
/// out of another table column, or a `Vec<u8>` without copying. The slice
/// must be exactly 32 bytes — non-32-byte input would silently match no row
/// and is rejected up front.
///
/// # Errors
///
/// Returns a [`StoreError`] if `cid` is not 32 bytes or the query fails.
pub fn get(conn: &Connection, cid: &[u8]) -> StoreResult<Option<Vec<u8>>> {
    check_cid_len(cid)?;
    let bytes = conn.query_row_optional(
        "SELECT bytes FROM blob_objects WHERE content_id = ?1",
        params![cid],
        |row| Ok(row.column_blob(0)),
    )?;
    Ok(bytes)
}

/// Deletes the blob row with the given content id, if it exists.
///
/// Consumers handling status transitions that orphan bytes (e.g. a credential
/// or PCP becoming unreferenced) call this to GC the row. Same 32-byte
/// requirement as [`get`].
///
/// # Errors
///
/// Returns a [`StoreError`] if `cid` is not 32 bytes or the delete fails.
pub fn delete(conn: &Connection, cid: &[u8]) -> StoreResult<()> {
    check_cid_len(cid)?;
    conn.execute(
        "DELETE FROM blob_objects WHERE content_id = ?1",
        params![cid],
    )?;
    Ok(())
}

fn check_cid_len(cid: &[u8]) -> StoreResult<()> {
    if cid.len() == 32 {
        Ok(())
    } else {
        Err(StoreError::Db(DbError::new(
            -1,
            format!("content_id must be 32 bytes, got {}", cid.len()),
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::{compute_content_id, delete, ensure_schema, get, put};
    use crate::params;
    use crate::test_utils::init_sqlite;
    use crate::Connection;

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
    fn test_put_get_delete_round_trip() {
        init_sqlite();

        let conn = Connection::open_in_memory().expect("open in-memory db");
        ensure_schema(&conn).expect("ensure schema");

        let cid = put(&conn, 7, b"payload", 1000).expect("put");
        assert_eq!(
            hex::encode(cid),
            "1b108fbc2839877f0df50296ab8db5254efe9bb85864c2fc1ac9285a0f55081d"
        );
        assert_eq!(cid, compute_content_id(7, b"payload"));

        let stored = get(&conn, &cid).expect("get").expect("present");
        assert_eq!(stored.as_slice(), b"payload");

        let duplicate_cid = put(&conn, 7, b"payload", 2000).expect("put duplicate");
        assert_eq!(duplicate_cid, cid);
        let row_count = conn
            .query_row(
                "SELECT COUNT(*) FROM blob_objects WHERE content_id = ?1",
                params![cid.as_ref()],
                |row| Ok(row.column_i64(0)),
            )
            .expect("count rows");
        assert_eq!(row_count, 1);

        delete(&conn, &cid).expect("delete");
        assert!(get(&conn, &cid).expect("get after delete").is_none());
    }
}
