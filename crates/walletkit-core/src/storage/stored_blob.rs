//! Owner-addressed local blobs, independent of credential lifetime and backups.

use std::sync::Arc;

use super::BlobId;

/// Metadata returned without reading a blob's data. No fields are logged by `Debug`.
#[derive(Clone, PartialEq, Eq, uniffi::Record)]
pub struct BlobRecord {
    /// Caller-supplied id, not a hash of the sealed bytes stored here.
    pub content_id: Arc<BlobId>,
    /// Opaque owner tag, for example `oxide.orb`.
    pub kind: String,
    /// Opaque owner-defined metadata.
    pub metadata: Option<Vec<u8>>,
    /// Starts at one and increases on each data or metadata write.
    pub revision: u64,
    /// Unix timestamp of the first write.
    pub created_at: u64,
    /// Unix timestamp of the latest data or metadata write.
    pub updated_at: u64,
}

/// A local blob, including the bytes supplied by its owner.
#[derive(Clone, PartialEq, Eq, uniffi::Record)]
pub struct StoredBlob {
    /// The blob's metadata and revision.
    pub record: BlobRecord,
    /// Owner-defined bytes, such as a device-sealed PCP archive.
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
