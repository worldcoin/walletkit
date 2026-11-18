//! Content-addressed local blobs, independent of credential lifetime and backups.

use std::sync::Arc;

use super::BlobId;

/// Metadata returned without reading a blob's data. No fields are logged by `Debug`.
#[derive(Clone, PartialEq, Eq, uniffi::Record)]
pub struct BlobRecord {
    /// The blob id computed from the stored plaintext archive with [`super::blob_id()`].
    pub blob_id: Arc<BlobId>,
    /// Opaque owner tag, for example `oxide.orb`.
    pub kind: String,
    /// Opaque owner-defined metadata.
    pub metadata: Option<Vec<u8>>,
    /// Opaque positive counter, randomly seeded on creation and incremented on each
    /// put or metadata write. Recreating identical data draws a fresh 62-bit seed
    /// to reduce stale metadata CAS matches across deletion/recreation.
    pub revision: u64,
    /// Unix timestamp of the first write.
    pub created_at: u64,
    /// Unix timestamp of the latest data or metadata write.
    pub updated_at: u64,
}

/// A local blob, including its plaintext archive protected at rest by vault encryption.
#[derive(Clone, PartialEq, Eq, uniffi::Record)]
pub struct StoredBlob {
    /// The blob's metadata and revision.
    pub record: BlobRecord,
    /// The exact PCP archive with the outer device seal removed. Backup-sealed
    /// inner members remain unchanged; the outer device seal is never stored.
    pub data: Vec<u8>,
}

impl std::fmt::Debug for BlobRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlobRecord").finish_non_exhaustive()
    }
}

impl std::fmt::Debug for StoredBlob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoredBlob").finish_non_exhaustive()
    }
}
