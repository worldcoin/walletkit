//! Core type definitions for World ID credential storage.
//!
//! This module contains all the fundamental data structures used throughout
//! the credential storage system.

use serde::{Deserialize, Serialize};
use std::fmt;

// Identifiers

/// A 32-byte account identifier derived from the vault key.
///
/// The account ID uniquely identifies a World ID account and is derived
/// deterministically from `K_vault` using:
/// `account_id = SHA256("worldid:account-id" || K_vault)`
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AccountId(pub [u8; 32]);

impl AccountId {
    /// Creates a new `AccountId` from raw bytes.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the raw bytes of the account ID.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Converts the account ID to a hexadecimal string.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Creates an `AccountId` from a hexadecimal string.
    ///
    /// # Errors
    /// Returns an error if the string is not valid hex or not exactly 32 bytes.
    pub fn from_hex(s: &str) -> Result<Self, hex::FromHexError> {
        let bytes = hex::decode(s)?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| hex::FromHexError::InvalidStringLength)?;
        Ok(Self(arr))
    }
}

impl fmt::Debug for AccountId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AccountId({})", self.to_hex())
    }
}

impl fmt::Display for AccountId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl AsRef<[u8]> for AccountId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// A 16-byte credential identifier (UUID).
///
/// Each credential stored in the vault has a unique random ID.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CredentialId(pub [u8; 16]);

impl CredentialId {
    /// Creates a new `CredentialId` from raw bytes.
    #[must_use]
    pub const fn new(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Generates a new random credential ID.
    ///
    /// # Panics
    ///
    /// Panics if the system's random number generator fails.
    #[must_use]
    pub fn generate() -> Self {
        let mut bytes = [0u8; 16];
        getrandom::getrandom(&mut bytes).expect("getrandom failed");
        Self(bytes)
    }

    /// Returns the raw bytes of the credential ID.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Converts the credential ID to a hexadecimal string.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Creates a `CredentialId` from a hexadecimal string.
    ///
    /// # Errors
    /// Returns an error if the string is not valid hex or not exactly 16 bytes.
    pub fn from_hex(s: &str) -> Result<Self, hex::FromHexError> {
        let bytes = hex::decode(s)?;
        let arr: [u8; 16] = bytes
            .try_into()
            .map_err(|_| hex::FromHexError::InvalidStringLength)?;
        Ok(Self(arr))
    }
}

impl fmt::Debug for CredentialId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CredentialId({})", self.to_hex())
    }
}

impl fmt::Display for CredentialId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl AsRef<[u8]> for CredentialId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// A 32-byte content-addressable identifier for blobs.
///
/// The content ID is computed as `SHA256(plaintext)` of the blob data,
/// enabling deduplication of identical blobs.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ContentId(pub [u8; 32]);

impl ContentId {
    /// Creates a new `ContentId` from raw bytes.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the raw bytes of the content ID.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Converts the content ID to a hexadecimal string.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Creates a `ContentId` from a hexadecimal string.
    ///
    /// # Errors
    /// Returns an error if the string is not valid hex or not exactly 32 bytes.
    pub fn from_hex(s: &str) -> Result<Self, hex::FromHexError> {
        let bytes = hex::decode(s)?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| hex::FromHexError::InvalidStringLength)?;
        Ok(Self(arr))
    }
}

impl fmt::Debug for ContentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ContentId({})", self.to_hex())
    }
}

impl fmt::Display for ContentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl AsRef<[u8]> for ContentId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

// Enums

/// Status of a credential in the vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialStatus {
    /// Credential is active and can be used for proofs.
    #[default]
    Active,
    /// Credential has been retired and should not be used.
    Retired,
}

/// Classification of blob objects stored in the vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum BlobKind {
    /// The main credential blob (e.g., signed credential data).
    CredentialBlob = 0x01,
    /// Associated data for a credential (e.g., metadata, auxiliary info).
    AssociatedData = 0x02,
}

impl BlobKind {
    /// Returns the label used for AEAD associated data construction.
    #[must_use]
    pub const fn aead_label(&self) -> &'static [u8] {
        match self {
            Self::CredentialBlob => b"vault:blob:cred",
            Self::AssociatedData => b"vault:blob:ad",
        }
    }

    /// Converts from a u8 value.
    ///
    /// # Errors
    /// Returns `None` if the value doesn't correspond to a valid `BlobKind`.
    #[must_use]
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x01 => Some(Self::CredentialBlob),
            0x02 => Some(Self::AssociatedData),
            _ => None,
        }
    }
}

/// Outcome of importing a credential transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportOutcome {
    /// The credential was successfully imported/updated.
    Applied,
    /// No changes were made (e.g., incoming data is older than existing).
    NoOp,
}

// Credential Record

/// A credential record stored in the vault index.
///
/// This is the metadata for a credential; the actual credential data
/// is stored as encrypted blobs referenced by content IDs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialRecord {
    /// Unique identifier for this credential.
    pub credential_id: CredentialId,
    /// Schema identifier from the Credential Schema Issuer Registry.
    pub issuer_schema_id: u64,
    /// Unix timestamp when the credential was created.
    pub created_at: u64,
    /// Unix timestamp when the record was last updated.
    pub updated_at: u64,
    /// Optional Unix timestamp when the credential expires.
    pub expires_at: Option<u64>,
    /// Content ID of the encrypted credential blob.
    pub credential_blob_cid: ContentId,
    /// Optional content ID of encrypted associated data.
    pub associated_data_cid: Option<ContentId>,
    /// Current status of the credential.
    pub status: CredentialStatus,
}

impl CredentialRecord {
    /// Creates a new credential record.
    #[must_use]
    pub const fn new(
        credential_id: CredentialId,
        issuer_schema_id: u64,
        created_at: u64,
        expires_at: Option<u64>,
        credential_blob_cid: ContentId,
        associated_data_cid: Option<ContentId>,
    ) -> Self {
        Self {
            credential_id,
            issuer_schema_id,
            created_at,
            updated_at: created_at,
            expires_at,
            credential_blob_cid,
            associated_data_cid,
            status: CredentialStatus::Active,
        }
    }

    /// Checks if the credential is currently eligible for use.
    ///
    /// A credential is eligible if it is active and not expired.
    #[must_use]
    pub fn is_eligible(&self, now: u64) -> bool {
        self.status == CredentialStatus::Active
            && self.expires_at.is_none_or(|exp| exp > now)
    }

    /// Retires this credential.
    pub const fn retire(&mut self, now: u64) {
        self.status = CredentialStatus::Retired;
        self.updated_at = now;
    }
}

// Blob Pointer

/// Pointer to a blob object within the vault file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobPointer {
    /// Content-addressable ID of the blob.
    pub content_id: ContentId,
    /// Byte offset of the blob record in the vault file.
    pub offset: u64,
    /// Byte length of the blob record encoding.
    pub length: u32,
    /// Classification of this blob.
    pub kind: BlobKind,
}

impl BlobPointer {
    /// Creates a new blob pointer.
    #[must_use]
    pub const fn new(content_id: ContentId, offset: u64, length: u32, kind: BlobKind) -> Self {
        Self {
            content_id,
            offset,
            length,
            kind,
        }
    }
}

// Vault Index

/// Current version of the vault index format.
pub const VAULT_INDEX_VERSION: u32 = 1;

/// The canonical index stored in the vault.
///
/// This structure represents the complete state of credentials and blobs
/// for an account. It is encrypted and stored in the vault file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultIndex {
    /// Format version for migration support.
    pub index_version: u32,
    /// Account this index belongs to.
    pub account_id: AccountId,
    /// Monotonically increasing sequence number for conflict resolution.
    pub sequence: u64,
    /// Unix timestamp of last update.
    pub updated_at: u64,
    /// All credential records.
    pub records: Vec<CredentialRecord>,
    /// All blob pointers.
    pub blobs: Vec<BlobPointer>,
}

impl VaultIndex {
    /// Creates a new empty vault index for an account.
    #[must_use]
    pub const fn new(account_id: AccountId, now: u64) -> Self {
        Self {
            index_version: VAULT_INDEX_VERSION,
            account_id,
            sequence: 0,
            updated_at: now,
            records: Vec::new(),
            blobs: Vec::new(),
        }
    }

    /// Finds a credential record by ID.
    #[must_use]
    pub fn find_credential(&self, credential_id: &CredentialId) -> Option<&CredentialRecord> {
        self.records.iter().find(|r| &r.credential_id == credential_id)
    }

    /// Finds a credential record by ID (mutable).
    #[must_use]
    pub fn find_credential_mut(&mut self, credential_id: &CredentialId) -> Option<&mut CredentialRecord> {
        self.records.iter_mut().find(|r| &r.credential_id == credential_id)
    }

    /// Finds a blob pointer by content ID.
    #[must_use]
    pub fn find_blob(&self, content_id: &ContentId) -> Option<&BlobPointer> {
        self.blobs.iter().find(|b| &b.content_id == content_id)
    }

    /// Increments the sequence number and updates the timestamp.
    pub const fn bump_sequence(&mut self, now: u64) {
        self.sequence += 1;
        self.updated_at = now;
    }
}

// Account State

/// Current version of the account state format.
pub const ACCOUNT_STATE_VERSION: u32 = 1;

/// Device-protected account state.
///
/// This small record is stored locally per account per device,
/// encrypted with a device-bound key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountState {
    /// Format version for migration support.
    pub state_version: u32,
    /// Account this state belongs to.
    pub account_id: AccountId,
    /// Cached leaf index for the account in the registry (optimization).
    pub leaf_index_cache: Option<u64>,
    /// Seed for deriving issuer blinding factors.
    pub issuer_blind_seed: [u8; 32],
    /// Seed for deriving session blinding factors.
    pub session_blind_seed: [u8; 32],
    /// Device-wrapped vault key `K_vault`.
    pub vault_key_wrap: Vec<u8>,
    /// Random device identifier (stable per install).
    pub device_id: [u8; 16],
    /// Unix timestamp of last update.
    pub updated_at: u64,
}

impl AccountState {
    /// Constructs the associated data for device encryption.
    ///
    /// Format: `account_id || device_id || "worldid:device-state"`
    #[must_use]
    pub fn device_seal_aad(&self) -> Vec<u8> {
        let mut aad = Vec::with_capacity(32 + 16 + 20);
        aad.extend_from_slice(&self.account_id.0);
        aad.extend_from_slice(&self.device_id);
        aad.extend_from_slice(b"worldid:device-state");
        aad
    }

    /// Constructs the associated data for vault key wrapping.
    ///
    /// Format: `account_id || device_id || "worldid:vault-key-wrap"`
    #[must_use]
    pub fn vault_key_wrap_aad(&self) -> Vec<u8> {
        let mut aad = Vec::with_capacity(32 + 16 + 22);
        aad.extend_from_slice(&self.account_id.0);
        aad.extend_from_slice(&self.device_id);
        aad.extend_from_slice(b"worldid:vault-key-wrap");
        aad
    }
}

// Pending Actions

/// Current version of the pending action store format.
pub const PENDING_ACTION_VERSION: u32 = 1;

/// Maximum number of pending action entries.
pub const MAX_PENDING_ENTRIES: usize = 16;

/// TTL for pending action entries in seconds.
pub const PENDING_TTL_SECONDS: u64 = 900;

/// A pending action entry for nullifier disclosure tracking.
///
/// This ensures that the same nullifier is not disclosed in multiple
/// distinct proof packages (idempotent retransmission is allowed).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingActionEntry {
    /// Hash of RP ID and action ID: `SHA256("worldid:action-scope" || rp_id || action_id)`.
    pub action_scope: [u8; 32],
    /// Hash of the signed request: `SHA256("worldid:proof-request" || signed_request_bytes)`.
    pub request_id: [u8; 32],
    /// The nullifier being disclosed.
    pub nullifier: [u8; 32],
    /// The complete proof package (opaque bytes returned to RP).
    pub proof_package: Vec<u8>,
    /// Unix timestamp when this entry was created.
    pub created_at: u64,
    /// Unix timestamp when this entry expires.
    pub expires_at: u64,
}

impl PendingActionEntry {
    /// Creates a new pending action entry.
    #[must_use]
    pub const fn new(
        action_scope: [u8; 32],
        request_id: [u8; 32],
        nullifier: [u8; 32],
        proof_package: Vec<u8>,
        now: u64,
    ) -> Self {
        Self {
            action_scope,
            request_id,
            nullifier,
            proof_package,
            created_at: now,
            expires_at: now + PENDING_TTL_SECONDS,
        }
    }

    /// Checks if this entry has expired.
    #[must_use]
    pub const fn is_expired(&self, now: u64) -> bool {
        self.expires_at <= now
    }
}

/// Store for pending action entries.
///
/// This is device-protected storage that tracks in-progress proof disclosures
/// to ensure nullifier single-use.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingActionStore {
    /// Format version for migration support.
    pub pending_version: u32,
    /// Account this store belongs to.
    pub account_id: AccountId,
    /// Active pending entries.
    pub entries: Vec<PendingActionEntry>,
}

impl PendingActionStore {
    /// Creates a new empty pending action store.
    #[must_use]
    pub const fn new(account_id: AccountId) -> Self {
        Self {
            pending_version: PENDING_ACTION_VERSION,
            account_id,
            entries: Vec::new(),
        }
    }

    /// Removes expired entries.
    pub fn prune_expired(&mut self, now: u64) {
        self.entries.retain(|e| !e.is_expired(now));
    }

    /// Finds an entry by action scope.
    #[must_use]
    pub fn find_by_scope(&self, action_scope: &[u8; 32]) -> Option<&PendingActionEntry> {
        self.entries.iter().find(|e| &e.action_scope == action_scope)
    }

    /// Inserts a new entry.
    ///
    /// # Errors
    /// Returns `false` if the store is at capacity.
    pub fn insert(&mut self, entry: PendingActionEntry) -> bool {
        if self.entries.len() >= MAX_PENDING_ENTRIES {
            return false;
        }
        self.entries.push(entry);
        true
    }

    /// Removes an entry by action scope.
    ///
    /// Returns the removed entry if found.
    pub fn remove(&mut self, action_scope: &[u8; 32]) -> Option<PendingActionEntry> {
        if let Some(pos) = self.entries.iter().position(|e| &e.action_scope == action_scope) {
            Some(self.entries.remove(pos))
        } else {
            None
        }
    }
}

// Credential Filter

/// Filter criteria for listing credentials.
#[derive(Debug, Clone, Default)]
pub struct CredentialFilter {
    /// Filter by issuer schema ID.
    pub issuer_schema_id: Option<u64>,
    /// Filter by credential status.
    pub status: Option<CredentialStatus>,
    /// Whether to include expired credentials.
    pub include_expired: bool,
}

impl CredentialFilter {
    /// Creates a new filter with default settings (active, non-expired only).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            issuer_schema_id: None,
            status: Some(CredentialStatus::Active),
            include_expired: false,
        }
    }

    /// Sets the issuer schema ID filter.
    #[must_use]
    pub const fn with_issuer_schema_id(mut self, id: u64) -> Self {
        self.issuer_schema_id = Some(id);
        self
    }

    /// Sets the status filter.
    #[must_use]
    pub const fn with_status(mut self, status: CredentialStatus) -> Self {
        self.status = Some(status);
        self
    }

    /// Includes expired credentials in results.
    #[must_use]
    pub const fn include_expired(mut self) -> Self {
        self.include_expired = true;
        self
    }

    /// Clears the status filter to include all statuses.
    #[must_use]
    pub const fn any_status(mut self) -> Self {
        self.status = None;
        self
    }

    /// Tests if a record matches this filter.
    #[must_use]
    pub fn matches(&self, record: &CredentialRecord, now: u64) -> bool {
        // Check issuer schema ID
        if let Some(schema_id) = self.issuer_schema_id {
            if record.issuer_schema_id != schema_id {
                return false;
            }
        }

        // Check status
        if let Some(status) = self.status {
            if record.status != status {
                return false;
            }
        }

        // Check expiration
        if !self.include_expired {
            if let Some(expires_at) = record.expires_at {
                if expires_at <= now {
                    return false;
                }
            }
        }

        true
    }
}


/// Encrypted credential transfer bytes for device-to-device sync.
///
/// Transfer bytes are AEAD-encrypted under `K_vault` and safe to
/// store on untrusted backends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialTransferBytes(pub Vec<u8>);

impl CredentialTransferBytes {
    /// Creates new transfer bytes from raw data.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // Vec cannot be const
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Returns the raw bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consumes self and returns the inner bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

/// Encrypted provisioning envelope for adding a new authenticator.
///
/// Contains `K_vault` and blinding seeds encrypted to the recipient's
/// device public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultProvisioningEnvelope(pub Vec<u8>);

impl VaultProvisioningEnvelope {
    /// Creates a new provisioning envelope from raw data.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // Vec cannot be const
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Returns the raw bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consumes self and returns the inner bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_credential_filter() {
        let now = 1000;
        let cid = ContentId::new([0u8; 32]);
        let active = CredentialRecord::new(CredentialId::generate(), 1, now, Some(now + 100), cid, None);
        let mut retired = active.clone();
        retired.credential_id = CredentialId::generate();
        retired.retire(now);
        let filter = CredentialFilter::new();
        assert!(filter.matches(&active, now));
        assert!(!filter.matches(&retired, now));
        let filter = CredentialFilter::new().with_issuer_schema_id(1);
        assert!(filter.matches(&active, now));
    }

    #[test]
    fn test_credential_record_eligibility() {
        let now = 1000;
        let cid = ContentId::new([0u8; 32]);
        let mut record = CredentialRecord::new(CredentialId::generate(), 1, now, None, cid, None);
        assert!(record.is_eligible(now));
        record.expires_at = Some(now + 100);
        assert!(record.is_eligible(now));
        assert!(!record.is_eligible(now + 200));
        record.retire(now);
        assert!(!record.is_eligible(now));
    }
}
