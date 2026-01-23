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

/// Credential identifier.
pub type CredentialId = [u8; 16];

/// Request identifier for replay guard.
pub type RequestId = [u8; 32];

/// Nullifier identifier used for replay safety.
pub type Nullifier = [u8; 32];

/// In-memory representation of a stored credential.
///
/// This struct joins vault metadata with the blob bytes so callers can consume
/// a single, self-contained record without additional lookups.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialRecord {
    /// Credential identifier.
    pub credential_id: CredentialId,
    /// Issuer schema identifier.
    pub issuer_schema_id: u64,
    /// Subject blinding factor tied to the credential subject.
    pub subject_blinding_factor: [u8; 32],
    /// Genesis issuance timestamp (seconds).
    pub genesis_issued_at: u64,
    /// Optional expiry timestamp (seconds).
    pub expires_at: Option<u64>,
    /// Last updated timestamp (seconds).
    pub updated_at: u64,
    /// Raw credential blob bytes.
    pub credential_blob: Vec<u8>,
    /// Optional associated data blob bytes.
    pub associated_data: Option<Vec<u8>>,
}

/// FFI-friendly credential record.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct CredentialRecordFfi {
    /// Credential identifier.
    pub credential_id: Vec<u8>,
    /// Issuer schema identifier.
    pub issuer_schema_id: u64,
    /// Subject blinding factor tied to the credential subject.
    pub subject_blinding_factor: Vec<u8>,
    /// Genesis issuance timestamp (seconds).
    pub genesis_issued_at: u64,
    /// Optional expiry timestamp (seconds).
    pub expires_at: Option<u64>,
    /// Last updated timestamp (seconds).
    pub updated_at: u64,
    /// Raw credential blob bytes.
    pub credential_blob: Vec<u8>,
    /// Optional associated data blob bytes.
    pub associated_data: Option<Vec<u8>>,
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

impl From<CredentialRecord> for CredentialRecordFfi {
    fn from(record: CredentialRecord) -> Self {
        Self {
            credential_id: record.credential_id.to_vec(),
            issuer_schema_id: record.issuer_schema_id,
            subject_blinding_factor: record.subject_blinding_factor.to_vec(),
            genesis_issued_at: record.genesis_issued_at,
            expires_at: record.expires_at,
            updated_at: record.updated_at,
            credential_blob: record.credential_blob,
            associated_data: record.associated_data,
        }
    }
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
