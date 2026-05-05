//! Content-addressed blob table shared across consumer schemas.
//!
//! [`Blobs::ensure_schema`] creates the `blob_objects` table; [`Blobs::put`]
//! and [`Blobs::get`] insert and read rows by [`ContentId`]. Consumers
//! reference blob rows from their own tables via a `BLOB NOT NULL` column
//! holding the content id (no foreign-key constraint — matches existing
//! `walletkit-core` behaviour).

use walletkit_db::{params, Connection, StepResult, Transaction, Value};

use crate::content_id::{compute_content_id, ContentId};
use crate::error::{StoreError, StoreResult};

/// Helper functions for the shared `blob_objects` table.
///
/// `Blobs` is a zero-sized namespace, not a stateful struct.
pub struct Blobs;

impl Blobs {
    /// Idempotently creates the `blob_objects` table.
    ///
    /// **Backup sensitivity:** the `blob_objects` table participates in
    /// `walletkit-db`'s plaintext export/import. Schema changes here flow
    /// through to existing backups.
    ///
    /// # Errors
    ///
    /// Returns an error if the `CREATE TABLE` statement fails.
    pub fn ensure_schema(conn: &Connection) -> StoreResult<()> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS blob_objects (
                content_id  BLOB    NOT NULL,
                blob_kind   INTEGER NOT NULL,
                created_at  INTEGER NOT NULL,
                bytes       BLOB    NOT NULL,
                PRIMARY KEY (content_id)
            );",
        )
        .map_err(StoreError::from)
    }

    /// Inserts `bytes` into the `blob_objects` table (idempotent on
    /// `content_id`) and returns the computed [`ContentId`].
    ///
    /// `kind_tag` is a consumer-defined `u8` identifier. It is stored as
    /// `INTEGER` and folded into the content id via [`compute_content_id`].
    ///
    /// # Errors
    ///
    /// Returns an error if the insert fails or `now` cannot be represented
    /// as `i64`.
    pub fn put(
        tx: &Transaction,
        kind_tag: u8,
        bytes: &[u8],
        now: u64,
    ) -> StoreResult<ContentId> {
        let content_id = compute_content_id(kind_tag, bytes);
        let now_i64 = u64_to_i64(now, "now")?;
        tx.execute(
            "INSERT OR IGNORE INTO blob_objects (content_id, blob_kind, created_at, bytes)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                content_id.as_ref(),
                i64::from(kind_tag),
                now_i64,
                bytes,
            ],
        )
        .map_err(StoreError::from)?;
        Ok(content_id)
    }

    /// Reads the bytes for `content_id`, returning `None` if absent.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub fn get(
        conn: &Connection,
        content_id: &ContentId,
    ) -> StoreResult<Option<Vec<u8>>> {
        let mut stmt = conn
            .prepare("SELECT bytes FROM blob_objects WHERE content_id = ?1")
            .map_err(StoreError::from)?;
        stmt.bind_values(&[Value::Blob(content_id.to_vec())])
            .map_err(StoreError::from)?;
        match stmt.step().map_err(StoreError::from)? {
            StepResult::Row(row) => Ok(Some(row.column_blob(0))),
            StepResult::Done => Ok(None),
        }
    }
}

fn u64_to_i64(value: u64, label: &str) -> StoreResult<i64> {
    i64::try_from(value).map_err(|_| {
        StoreError::Db(format!("{label} out of range for i64: {value}"))
    })
}
