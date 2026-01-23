//! Public types for credential storage.

use super::error::{StorageError, StorageResult};

/// Kind of blob stored in the vault.
///
/// Blob records (stored in the `blob_objects` table) carry a kind tag that
/// distinguishes credential payloads from associated data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
#[repr(u8)]
pub enum BlobKind {
    /// Credential blob payload.
    CredentialBlob = 1,
    /// Associated data payload.
    AssociatedData = 2,
}

impl BlobKind {
    pub(crate) const fn as_i64(self) -> i64 {
        self as i64
    }
}

impl TryFrom<i64> for BlobKind {
    type Error = StorageError;

    fn try_from(value: i64) -> StorageResult<Self> {
        match value {
            1 => Ok(Self::CredentialBlob),
            2 => Ok(Self::AssociatedData),
            _ => Err(StorageError::VaultDb(format!("invalid blob kind {value}"))),
        }
    }
}

/// Content identifier for stored blobs.
pub type ContentId = [u8; 32];

/// Request identifier for replay guard.
pub type RequestId = [u8; 32];

/// Nullifier identifier used for replay safety.
pub type Nullifier = [u8; 32];

/// In-memory representation of stored credential metadata.
///
/// This is intentionally small and excludes blobs; full credential payloads can
/// be fetched separately to avoid heavy list queries.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct CredentialRecord {
    /// Credential identifier.
    pub credential_id: u64,
    /// Issuer schema identifier.
    pub issuer_schema_id: u64,
    /// Optional expiry timestamp (seconds).
    pub expires_at: Option<u64>,
}

/// Result of replay guard enforcement.
///
/// The replay guard is idempotent: repeated calls with the same request return
/// the original proof bytes rather than generating a new disclosure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplayGuardResult {
    /// Stored bytes for the first disclosure of a request.
    Fresh(Vec<u8>),
    /// Stored bytes replayed for an existing request.
    Replay(Vec<u8>),
}

/// FFI-friendly replay guard result kind.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum ReplayGuardKind {
    /// Stored bytes for the first disclosure of a request.
    Fresh,
    /// Stored bytes replayed for an existing request.
    Replay,
}

/// FFI-friendly replay guard result.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ReplayGuardResultFfi {
    /// Result kind.
    pub kind: ReplayGuardKind,
    /// Stored proof package bytes.
    pub bytes: Vec<u8>,
}

impl From<ReplayGuardResult> for ReplayGuardResultFfi {
    fn from(result: ReplayGuardResult) -> Self {
        match result {
            ReplayGuardResult::Fresh(bytes) => Self {
                kind: ReplayGuardKind::Fresh,
                bytes,
            },
            ReplayGuardResult::Replay(bytes) => Self {
                kind: ReplayGuardKind::Replay,
                bytes,
            },
        }
    }
}
