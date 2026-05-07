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

use crate::params;
use crate::sqlite::{Connection, Result as DbResult};

const CONTENT_ID_PREFIX: &[u8] = b"worldid:blob";

/// 32-byte content identifier for a stored blob.
///
/// Content ids are deterministic functions of `(kind, plaintext)` — see
/// [`compute_content_id`] for the exact derivation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ContentId([u8; 32]);

impl ContentId {
    /// Constructs a [`ContentId`] from raw bytes (no derivation).
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrows the underlying 32-byte buffer.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Consumes the [`ContentId`] and returns the underlying buffer.
    #[must_use]
    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl AsRef<[u8]> for ContentId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; 32]> for ContentId {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

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
    ContentId(out)
}

/// Content-addressed blob table operations.
///
/// Type-only namespace; methods are associated functions taking a
/// [`Connection`] so callers can compose them into their own transactions.
pub struct Blobs;

impl Blobs {
    /// Creates the `blob_objects` table if it does not exist.
    ///
    /// Idempotent. The exact DDL is part of the on-disk format contract;
    /// callers should not attempt to alter the schema.
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
    /// with that id already exists the call is a no-op and the existing row
    /// is left in place.
    ///
    /// # Errors
    ///
    /// Returns a database error if the insert fails.
    pub fn put(
        conn: &Connection,
        kind: u8,
        bytes: &[u8],
        now: i64,
    ) -> DbResult<ContentId> {
        let cid = compute_content_id(kind, bytes);
        conn.execute(
            "INSERT OR IGNORE INTO blob_objects (content_id, blob_kind, created_at, bytes)
             VALUES (?1, ?2, ?3, ?4)",
            params![cid.as_ref(), i64::from(kind), now, bytes],
        )?;
        Ok(cid)
    }

    /// Fetches blob bytes by content id, if present.
    ///
    /// # Errors
    ///
    /// Returns a database error if the query fails.
    pub fn get(conn: &Connection, cid: &ContentId) -> DbResult<Option<Vec<u8>>> {
        conn.query_row_optional(
            "SELECT bytes FROM blob_objects WHERE content_id = ?1",
            params![cid.as_ref()],
            |row| Ok(row.column_blob(0)),
        )
    }
}
