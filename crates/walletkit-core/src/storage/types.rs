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
///
/// Set explicitly by whichever orchestration code invokes the write path,
/// based on which module actually handled the request — it is not derived
/// from any field on the request itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum CredentialActivityProtocol {
    /// Legacy Semaphore-based protocol.
    V3,
    /// Current, RP-signature-verifiable protocol.
    V4,
}

/// Terminal outcome of a proof-share request recorded in credential activity
/// history.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum CredentialActivityOutcome {
    /// The proof was generated and shared with the relying party.
    Shared,
    /// The user declined the request.
    Declined,
    /// The user cancelled or dismissed the request without an explicit decline.
    Cancelled,
    /// The request failed (see [`CredentialActivityFailureReason`]).
    Failed,
    /// The app was killed or backgrounded before a terminal outcome was
    /// recorded. Entries land in this state via reconciliation on the next
    /// [`super::CredentialStore`] open, not via an explicit finalize call.
    Incomplete,
}

/// Closed vocabulary of reasons a proof-share request can fail.
///
/// Closed (enforced in Rust, not free-form `TEXT`) so nothing can write raw,
/// potentially sensitive error text into what must remain "a short,
/// non-sensitive explanation" for the user-facing history.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum CredentialActivityFailureReason {
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

/// Broad category of credential involved in a proof-share request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum CredentialActivityCredentialType {
    /// Proof of unique personhood, regardless of verification method.
    Human,
    /// A government-issued document credential.
    Document,
    /// A face-biometric credential (device-local selfie liveness).
    Face,
    /// A semi-unique device credential.
    Device,
}

/// Specific verification method that produced a credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum CredentialActivityCredentialSource {
    /// Biometrically verified at an Orb.
    Orb,
    /// NFC-verified government-issued document.
    Document,
    /// NFC-verified document with additional presence checks.
    SecureDocument,
    /// v4 passport verification.
    Passport,
    /// v4 mobile network carrier verification.
    Mnc,
    /// Semi-unique device credential.
    Device,
    /// Device-local selfie liveness check.
    Selfie,
}

/// Kind of proof requested or produced for a credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum CredentialActivityProofKind {
    /// Proof of unique personhood.
    UniqueHuman,
    /// Proof derived from a government-issued document (e.g. age, nationality).
    DocumentProof,
    /// Proof derived from a device-local selfie liveness check.
    SelfieProof,
}

/// One credential/proof involved in a proof-share request.
///
/// A single request can involve more than one credential (e.g. "prove
/// uniqueness AND age over 18" in one approval).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct CredentialActivityCredential {
    /// Broad credential category.
    pub credential_type: CredentialActivityCredentialType,
    /// Specific verification method.
    pub credential_source: CredentialActivityCredentialSource,
    /// Kind of proof.
    pub proof_kind: CredentialActivityProofKind,
    /// Authoritative machine key for the credential schema/issuer used.
    /// v4 only; absent for v3.
    pub issuer_schema_id: Option<u64>,
    /// Local credential actually used. Unset when the entry is first
    /// recorded, filled in at finalize.
    pub credential_id: Option<u64>,
}

/// Input to [`super::CredentialActivityStore::record_activity_started`].
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct NewCredentialActivityEntry {
    /// The relying party identifier.
    pub app_identifier: String,
    /// Host-app-defined identifier correlating this entry with the request
    /// that produced it (e.g. a bridge request UUID).
    pub client_id: String,
    /// v4 only.
    pub request_id: Option<String>,
    /// Protocol attempted first; may be overwritten at finalize if it fell
    /// back (e.g. v4 to v3).
    pub protocol: CredentialActivityProtocol,
    /// Credentials involved. `credential_id` is `None` on every entry here.
    pub credentials: Vec<CredentialActivityCredential>,
}

/// Input to [`super::CredentialActivityStore::finalize_activity`].
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct CredentialActivityFinalization {
    /// Identifies the still-open entry to finalize — the same `client_id`
    /// passed to `record_activity_started`.
    pub client_id: String,
    /// The terminal outcome.
    pub outcome: CredentialActivityOutcome,
    /// Must be present if and only if `outcome` is `Failed` — any other
    /// combination is rejected.
    pub failure_reason: Option<CredentialActivityFailureReason>,
    /// Re-supplied; overwrites the value recorded at start if it changed.
    pub protocol: CredentialActivityProtocol,
    /// The final set of credentials actually used. Only applied when
    /// `outcome` is `Shared`, replacing whatever was recorded at start; for
    /// any other outcome this is ignored and the originally-recorded
    /// credentials are kept, preserving the record of what was requested.
    pub credentials: Vec<CredentialActivityCredential>,
}

/// A single row of credential activity history.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct CredentialActivityEntry {
    /// Unique identifier for this entry.
    pub entry_id: u64,
    /// Host-app-defined identifier correlating this entry with the request
    /// that produced it.
    pub client_id: String,
    /// v4 only.
    pub request_id: Option<String>,
    /// Protocol used for this request.
    pub protocol: CredentialActivityProtocol,
    /// When the entry was created (approval screen shown).
    pub created_at: u64,
    /// When the entry was last updated (terminal write time).
    pub updated_at: u64,
    /// The result of the activity. `None` while still pending.
    pub outcome: Option<CredentialActivityOutcome>,
    /// The relying party identifier.
    pub app_identifier: String,
    /// Credentials involved in this request.
    pub credentials: Vec<CredentialActivityCredential>,
    /// Present only when `outcome` is `Failed`.
    pub failure_reason: Option<CredentialActivityFailureReason>,
}

/// Aggregate counts over credential activity history.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct CredentialActivityMetadata {
    /// Total number of recorded entries.
    pub total_count: u64,
}

/// Filtering/sorting options for
/// [`super::CredentialActivityStore::list_activities`].
///
/// Intentionally empty for now — a placeholder so the API surface doesn't
/// need to change shape once filters are actually needed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, uniffi::Record)]
pub struct CredentialActivityQuery {}
