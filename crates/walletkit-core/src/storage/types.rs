//! Public types for credential storage.

use std::collections::{BTreeSet, HashSet};

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
    /// The relying party identifier the request was made against.
    pub rp_id: u64,
    /// The application that made the request.
    pub app_identifier: String,
    /// Host-app-defined identifier correlating this entry with its request.
    pub client_id: String,
    /// Protocol used for this request.
    pub protocol: ProtocolVersion,
    /// Activity time.
    pub timestamp: Option<u64>,
    /// The result of the activity.
    pub outcome: ActivityOutcome,
    /// The set of issuer schema ids whose credentials produced an output proof
    /// for the request. Order is not significant; duplicates are dropped.
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
///
/// Build one with [`ActivityQuery::new`] and add filters with the `with_*`
/// methods, so new filters can be added without changing constructors on the
/// foreign side.
#[derive(Debug, Clone, Default, PartialEq, Eq, uniffi::Object)]
pub struct ActivityQuery {
    pub(crate) issuer_schema_ids: Option<BTreeSet<u64>>,
}

#[uniffi::export]
impl ActivityQuery {
    /// Creates a query with no filters.
    #[uniffi::constructor]
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Restricts results to entries that include any of these issuer schema
    /// ids, replacing any previously set ids.
    ///
    /// The ids are a set: order and duplicates are ignored. An empty set
    /// matches no entries.
    #[must_use]
    pub fn with_issuer_schema_ids(&self, issuer_schema_ids: HashSet<u64>) -> Self {
        let mut next = self.clone();
        next.issuer_schema_ids = Some(issuer_schema_ids.into_iter().collect());

        next
    }
}

/// The RPs a WIP-107 Billing Contract bills, as the indexer reported them at `block_number`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BilledRpsSnapshot {
    /// The last block the indexer synced the Billing Contract's events through.
    pub block_number: u64,
    /// The timestamp of `block_number`, in Unix seconds.
    pub synced_at: u64,
    /// The billed RP ids, ascending and distinct.
    rp_ids: Vec<u64>,
}

impl BilledRpsSnapshot {
    /// A snapshot of `rp_ids`, sorted and deduplicated.
    #[must_use]
    pub fn new(block_number: u64, synced_at: u64, mut rp_ids: Vec<u64>) -> Self {
        rp_ids.sort_unstable();
        rp_ids.dedup();
        Self {
            block_number,
            synced_at,
            rp_ids,
        }
    }

    /// The billed RP ids, ascending.
    #[must_use]
    pub fn rp_ids(&self) -> &[u64] {
        &self.rp_ids
    }

    /// Whether the Billing Contract bills `rp_id`.
    #[must_use]
    pub fn is_billed(&self, rp_id: u64) -> bool {
        self.rp_ids.binary_search(&rp_id).is_ok()
    }

    /// `block_number || synced_at || rp_id*`, each 8 bytes big-endian.
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(16 + 8 * self.rp_ids.len());
        bytes.extend_from_slice(&self.block_number.to_be_bytes());
        bytes.extend_from_slice(&self.synced_at.to_be_bytes());
        for rp_id in &self.rp_ids {
            bytes.extend_from_slice(&rp_id.to_be_bytes());
        }
        bytes
    }

    /// Decodes [`Self::encode`]'s bytes.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::Serialization`] if `bytes` is not a whole number of 8-byte words
    /// after the two header words, or the RP ids are not ascending and distinct.
    pub(crate) fn decode(bytes: &[u8]) -> StorageResult<Self> {
        let malformed = |reason: &str| {
            StorageError::Serialization(format!(
                "malformed billed RP snapshot: {reason}"
            ))
        };
        let (words, rest) = bytes.as_chunks::<8>();
        if !rest.is_empty() {
            return Err(malformed("length is not a multiple of 8"));
        }
        let [block_number, synced_at, rp_ids @ ..] = words else {
            return Err(malformed("missing block number or sync time"));
        };
        let rp_ids: Vec<u64> = rp_ids
            .iter()
            .map(|word| u64::from_be_bytes(*word))
            .collect();
        if !rp_ids.windows(2).all(|pair| pair[0] < pair[1]) {
            return Err(malformed("RP ids are not ascending"));
        }
        Ok(Self {
            block_number: u64::from_be_bytes(*block_number),
            synced_at: u64::from_be_bytes(*synced_at),
            rp_ids,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::BilledRpsSnapshot;

    #[test]
    fn billed_rps_snapshot_encoding_is_frozen() {
        let snapshot = BilledRpsSnapshot::new(0x0102, 0x0304, vec![9, 0x2a, 9]);
        assert_eq!(snapshot.rp_ids(), [9, 0x2a]);

        let mut expected = Vec::new();
        for word in [0x0102_u64, 0x0304, 9, 0x2a] {
            expected.extend_from_slice(&word.to_be_bytes());
        }
        assert_eq!(snapshot.encode(), expected);
        assert_eq!(BilledRpsSnapshot::decode(&expected).unwrap(), snapshot);
    }

    #[test]
    fn billed_rps_snapshot_lookup() {
        let snapshot = BilledRpsSnapshot::new(1, 2, vec![42, 7]);
        assert!(snapshot.is_billed(7));
        assert!(snapshot.is_billed(42));
        assert!(!snapshot.is_billed(8));
        assert!(!BilledRpsSnapshot::new(1, 2, Vec::new()).is_billed(7));
    }

    #[test]
    fn malformed_billed_rps_snapshots_are_rejected() {
        let words = |words: &[u64]| -> Vec<u8> {
            words.iter().flat_map(|word| word.to_be_bytes()).collect()
        };
        for bytes in [
            Vec::new(),
            words(&[1]),
            [words(&[1, 2]), vec![0]].concat(),
            words(&[1, 2, 9, 9]),
            words(&[1, 2, 9, 3]),
        ] {
            assert!(BilledRpsSnapshot::decode(&bytes).is_err(), "{bytes:?}");
        }
        assert_eq!(
            BilledRpsSnapshot::decode(&words(&[1, 2])).unwrap().rp_ids(),
            [] as [u64; 0]
        );
    }
}
