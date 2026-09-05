//! Public types for credential storage.

use strum::{Display, EnumString};

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

pub use walletkit_db::ContentId;

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
    /// Genesis issuance timestamp (seconds).
    pub genesis_issued_at: u64,
    /// Expiry timestamp (seconds).
    pub expires_at: u64,
    /// Whether the credential is expired at query time (`now >= expires_at`).
    ///
    /// This value is computed when listing credentials and is not persisted.
    pub is_expired: bool,
}

/// FFI-friendly replay guard result kind.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum ReplayGuardKind {
    /// Stored bytes for the first disclosure of a request.
    Fresh,
    /// Stored bytes replayed for an existing request.
    Replay,
}

/// Replay guard result.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ReplayGuardResult {
    /// Result kind.
    pub kind: ReplayGuardKind,
    /// Stored proof package bytes.
    pub bytes: Vec<u8>,
}

/// Which World ID protocol handled a proof-share request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
#[repr(u8)]
pub enum ProtocolVersion {
    /// Legacy Semaphore-based protocol.
    V3 = 3,
    /// Current. Reference: <https://github.com/worldcoin/world-id-protocol/tree/main/docs/world-id-4-specs>
    V4 = 4,
}

impl ProtocolVersion {
    pub(crate) const fn as_i64(self) -> i64 {
        self as i64
    }
}

impl TryFrom<i64> for ProtocolVersion {
    type Error = StorageError;

    fn try_from(value: i64) -> StorageResult<Self> {
        match value {
            3 => Ok(Self::V3),
            4 => Ok(Self::V4),
            _ => Err(StorageError::ActivityDb(format!(
                "invalid protocol version {value}"
            ))),
        }
    }
}

/// Terminal outcome of a proof-share request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumString, Display, uniffi::Enum)]
#[strum(serialize_all = "lowercase")]
pub enum ActivityOutcome {
    /// Proof request was completed successfully.
    Completed,
    /// The user declined the request.
    Declined,
    /// The user cancelled or dismissed the request without an explicit decline.
    Cancelled,
    /// The request failed (see [`ActivityFailureReason`]).
    Failed,
    /// The request never reached a terminal outcome (e.g. the app was killed
    /// or backgrounded before completion).
    Incomplete,
}

/// Reasons a proof fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumString, Display, uniffi::Enum)]
#[strum(serialize_all = "lowercase")]
pub enum ActivityFailureReason {
    /// A network request failed.
    NetworkError,
    /// The request timed out.
    Timeout,
    /// Device authentication (e.g. Face ID/passcode) failed.
    DeviceAuthenticationFailed,
    /// Proof generation itself failed.
    ProofGenerationFailed,
    /// The relying party rejected the proof.
    RelyingPartyRejected,
}

/// A single row of credential activity history.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ActivityEntry {
    /// Unique identifier for this entry.
    pub id: Option<u64>,
    /// The relying party identifier.
    pub rp_id: u64,
    /// Host-app-defined identifier correlating this entry with its request.
    pub client_id: String,
    /// Protocol used for this request.
    pub protocol: ProtocolVersion,
    /// Activity time.
    pub timestamp: Option<u64>,
    /// The result of the activity.
    pub outcome: ActivityOutcome,
    /// The credentials which produced an output proof for the request.
    pub issuer_schema_ids: Vec<u64>,
    /// Present only when `outcome` is `Failed`.
    pub failure_reason: Option<ActivityFailureReason>,
}

/// Aggregate counts over credential activity history.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct ActivityMetadata {
    /// Total number of recorded entries.
    pub total_count: u64,
}

/// Filtering/sorting options for [`super::CredentialStore::list_activities`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, uniffi::Record)]
pub struct ActivityQuery {}
