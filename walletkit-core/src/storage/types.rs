//! Public types for credential storage.

use super::error::{StorageError, StorageResult};

/// Status of a stored credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CredentialStatus {
    /// Credential is active and can be used.
    Active = 1,
    /// Credential has been revoked.
    Revoked = 2,
    /// Credential has expired.
    Expired = 3,
}

impl CredentialStatus {
    pub(crate) const fn as_i64(self) -> i64 {
        self as i64
    }
}

impl TryFrom<i64> for CredentialStatus {
    type Error = StorageError;

    fn try_from(value: i64) -> StorageResult<Self> {
        match value {
            1 => Ok(Self::Active),
            2 => Ok(Self::Revoked),
            3 => Ok(Self::Expired),
            _ => Err(StorageError::VaultDb(format!(
                "invalid credential status {value}"
            ))),
        }
    }
}

/// Kind of blob stored in the vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
            _ => Err(StorageError::VaultDb(format!(
                "invalid blob kind {value}"
            ))),
        }
    }
}

/// Content identifier for stored blobs.
pub type ContentId = [u8; 32];

/// Credential identifier.
pub type CredentialId = [u8; 16];

/// In-memory representation of a stored credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialRecord {
    pub credential_id: CredentialId,
    pub issuer_schema_id: u64,
    pub status: CredentialStatus,
    pub subject_blinding_factor: [u8; 32],
    pub genesis_issued_at: u64,
    pub expires_at: Option<u64>,
    pub updated_at: u64,
    pub credential_blob: Vec<u8>,
    pub associated_data: Option<Vec<u8>>,
}
