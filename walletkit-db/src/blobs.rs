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
use crate::sqlite::{Connection, Error as DbError, Result as DbResult};

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
/// # Errors
///
/// Returns a [`StoreError`] if the query fails.
pub fn get(conn: &Connection, cid: &ContentId) -> StoreResult<Option<Vec<u8>>> {
    let bytes = conn.query_row_optional(
        "SELECT bytes FROM blob_objects WHERE content_id = ?1",
        params![cid.as_ref()],
        |row| Ok(row.column_blob(0)),
    )?;
    Ok(bytes)
}
