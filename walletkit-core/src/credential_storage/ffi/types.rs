//! FFI-safe types for credential storage.
//!
//! These types are exported across the FFI boundary to Swift and Kotlin.
//! The internal types (e.g., `crate::credential_storage::AccountId`) are
//! implementation details - these FFI types are the public API.

use crate::credential_storage::{
    AccountId as InternalAccountId, CredentialFilter as InternalCredentialFilter,
    CredentialId as InternalCredentialId, CredentialRecord as InternalCredentialRecord,
    CredentialStatus as InternalCredentialStatus, CredentialTransferBytes,
    ImportOutcome as InternalImportOutcome, PendingActionEntry, VaultProvisioningEnvelope,
};

// =============================================================================
// Account ID
// =============================================================================

/// Account identifier (32-byte hex string).
#[derive(Debug, Clone, PartialEq, Eq, Hash, uniffi::Record)]
pub struct AccountId {
    /// Hex-encoded 32-byte account ID.
    pub hex: String,
}

impl AccountId {
    /// Creates a new account ID from bytes.
    #[must_use]
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self {
            hex: hex::encode(bytes),
        }
    }

    /// Converts to internal `AccountId`.
    ///
    /// # Errors
    ///
    /// Returns an error if the hex string is invalid.
    pub fn to_internal(&self) -> Result<InternalAccountId, String> {
        InternalAccountId::from_hex(&self.hex).map_err(|e| format!("Invalid account ID: {e}"))
    }
}

impl From<InternalAccountId> for AccountId {
    fn from(id: InternalAccountId) -> Self {
        Self {
            hex: id.to_string(),
        }
    }
}

impl From<&InternalAccountId> for AccountId {
    fn from(id: &InternalAccountId) -> Self {
        Self {
            hex: id.to_string(),
        }
    }
}

// =============================================================================
// Credential ID
// =============================================================================

/// Credential identifier (16-byte hex string).
#[derive(Debug, Clone, PartialEq, Eq, Hash, uniffi::Record)]
pub struct CredentialId {
    /// Hex-encoded 16-byte credential ID.
    pub hex: String,
}

impl CredentialId {
    /// Creates a new credential ID from bytes.
    #[must_use]
    pub fn from_bytes(bytes: &[u8; 16]) -> Self {
        Self {
            hex: hex::encode(bytes),
        }
    }

    /// Generates a new random credential ID.
    #[must_use]
    pub fn generate() -> Self {
        Self::from(InternalCredentialId::generate())
    }

    /// Converts to internal `CredentialId`.
    ///
    /// # Errors
    ///
    /// Returns an error if the hex string is invalid.
    pub fn to_internal(&self) -> Result<InternalCredentialId, String> {
        InternalCredentialId::from_hex(&self.hex).map_err(|e| format!("Invalid credential ID: {e}"))
    }
}

impl From<InternalCredentialId> for CredentialId {
    fn from(id: InternalCredentialId) -> Self {
        Self {
            hex: id.to_string(),
        }
    }
}

impl From<&InternalCredentialId> for CredentialId {
    fn from(id: &InternalCredentialId) -> Self {
        Self {
            hex: id.to_string(),
        }
    }
}

// =============================================================================
// Credential Status
// =============================================================================

/// Credential status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum CredentialStatus {
    /// Credential is active and can be used.
    Active,
    /// Credential has been retired (soft-deleted).
    Retired,
}

impl From<InternalCredentialStatus> for CredentialStatus {
    fn from(status: InternalCredentialStatus) -> Self {
        match status {
            InternalCredentialStatus::Active => CredentialStatus::Active,
            InternalCredentialStatus::Retired => CredentialStatus::Retired,
        }
    }
}

impl From<CredentialStatus> for InternalCredentialStatus {
    fn from(status: CredentialStatus) -> Self {
        match status {
            CredentialStatus::Active => InternalCredentialStatus::Active,
            CredentialStatus::Retired => InternalCredentialStatus::Retired,
        }
    }
}

// =============================================================================
// Credential Record
// =============================================================================

/// Credential record (metadata without blob data).
#[derive(Debug, Clone, uniffi::Record)]
pub struct CredentialRecord {
    /// Unique credential identifier.
    pub credential_id: CredentialId,
    /// Issuer schema ID from the Credential Schema Issuer Registry.
    pub issuer_schema_id: u64,
    /// Unix timestamp when the credential was created.
    pub created_at: u64,
    /// Unix timestamp when the credential was last updated.
    pub updated_at: u64,
    /// Optional Unix timestamp when the credential expires.
    pub expires_at: Option<u64>,
    /// Current status of the credential.
    pub status: CredentialStatus,
}

impl From<InternalCredentialRecord> for CredentialRecord {
    fn from(record: InternalCredentialRecord) -> Self {
        Self {
            credential_id: record.credential_id.into(),
            issuer_schema_id: record.issuer_schema_id,
            created_at: record.created_at,
            updated_at: record.updated_at,
            expires_at: record.expires_at,
            status: record.status.into(),
        }
    }
}

impl From<&InternalCredentialRecord> for CredentialRecord {
    fn from(record: &InternalCredentialRecord) -> Self {
        Self {
            credential_id: (&record.credential_id).into(),
            issuer_schema_id: record.issuer_schema_id,
            created_at: record.created_at,
            updated_at: record.updated_at,
            expires_at: record.expires_at,
            status: record.status.into(),
        }
    }
}

// =============================================================================
// Credential Filter
// =============================================================================

/// Credential filter for listing credentials.
#[derive(Debug, Clone, Default, uniffi::Record)]
pub struct CredentialFilter {
    /// Filter by issuer schema ID.
    pub issuer_schema_id: Option<u64>,
    /// Filter by status (if None, defaults to Active only).
    pub status: Option<CredentialStatus>,
    /// If true, includes expired credentials.
    pub include_expired: bool,
}

impl From<CredentialFilter> for InternalCredentialFilter {
    fn from(filter: CredentialFilter) -> Self {
        let mut f = InternalCredentialFilter::new();

        if let Some(schema_id) = filter.issuer_schema_id {
            f = f.with_issuer_schema_id(schema_id);
        }

        if let Some(status) = filter.status {
            f = f.with_status(status.into());
        }

        if filter.include_expired {
            f = f.include_expired();
        }

        f
    }
}

// =============================================================================
// Import Outcome
// =============================================================================

/// Import outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ImportOutcome {
    /// The credential was imported or updated.
    Applied,
    /// The credential was not imported (existing is newer or equal).
    NoOp,
}

impl From<InternalImportOutcome> for ImportOutcome {
    fn from(outcome: InternalImportOutcome) -> Self {
        match outcome {
            InternalImportOutcome::Applied => ImportOutcome::Applied,
            InternalImportOutcome::NoOp => ImportOutcome::NoOp,
        }
    }
}

// =============================================================================
// Credential Transfer
// =============================================================================

/// Credential transfer bytes.
///
/// This is an opaque encrypted blob that can be sent to another device
/// and imported using `importCredential`.
#[derive(Debug, Clone, uniffi::Record)]
pub struct CredentialTransfer {
    /// The encrypted transfer bytes.
    pub bytes: Vec<u8>,
}

impl From<CredentialTransferBytes> for CredentialTransfer {
    fn from(transfer: CredentialTransferBytes) -> Self {
        Self {
            bytes: transfer.into_bytes(),
        }
    }
}

impl From<CredentialTransfer> for CredentialTransferBytes {
    fn from(transfer: CredentialTransfer) -> Self {
        CredentialTransferBytes::new(transfer.bytes)
    }
}

// =============================================================================
// Provisioning Envelope
// =============================================================================

/// Vault provisioning envelope.
///
/// This is an opaque encrypted blob containing the vault key and blinding
/// seeds, used to provision a new device with an existing account.
#[derive(Debug, Clone, uniffi::Record)]
pub struct ProvisioningEnvelope {
    /// The encrypted envelope bytes.
    pub bytes: Vec<u8>,
}

impl From<VaultProvisioningEnvelope> for ProvisioningEnvelope {
    fn from(envelope: VaultProvisioningEnvelope) -> Self {
        Self {
            bytes: envelope.into_bytes(),
        }
    }
}

impl From<ProvisioningEnvelope> for VaultProvisioningEnvelope {
    fn from(envelope: ProvisioningEnvelope) -> Self {
        VaultProvisioningEnvelope::new(envelope.bytes)
    }
}

// =============================================================================
// Pending Action
// =============================================================================

/// Pending action entry.
#[derive(Debug, Clone, uniffi::Record)]
pub struct PendingAction {
    /// Action scope (32-byte hex).
    pub action_scope_hex: String,
    /// Request ID (32-byte hex).
    pub request_id_hex: String,
    /// Nullifier (32-byte hex).
    pub nullifier_hex: String,
    /// Unix timestamp when the entry was created.
    pub created_at: u64,
    /// The proof package bytes.
    pub proof_package: Vec<u8>,
}

impl From<PendingActionEntry> for PendingAction {
    fn from(entry: PendingActionEntry) -> Self {
        Self {
            action_scope_hex: hex::encode(entry.action_scope),
            request_id_hex: hex::encode(entry.request_id),
            nullifier_hex: hex::encode(entry.nullifier),
            created_at: entry.created_at,
            proof_package: entry.proof_package,
        }
    }
}

impl From<&PendingActionEntry> for PendingAction {
    fn from(entry: &PendingActionEntry) -> Self {
        Self {
            action_scope_hex: hex::encode(entry.action_scope),
            request_id_hex: hex::encode(entry.request_id),
            nullifier_hex: hex::encode(entry.nullifier),
            created_at: entry.created_at,
            proof_package: entry.proof_package.clone(),
        }
    }
}

// =============================================================================
// Credential Data
// =============================================================================

/// Credential data (blob and optional associated data).
///
/// Returned by `getCredential` to avoid tuple return types that aren't
/// supported by UniFFI.
#[derive(Debug, Clone, uniffi::Record)]
pub struct CredentialData {
    /// The main credential blob.
    pub credential_blob: Vec<u8>,
    /// Optional associated data.
    pub associated_data: Option<Vec<u8>>,
}

// =============================================================================
// Device Key Pair
// =============================================================================

/// Device key pair for provisioning.
///
/// This is used when adding a new device to an existing account.
#[derive(Debug, Clone, uniffi::Record)]
pub struct DeviceKeyPair {
    /// The public key (32 bytes).
    pub public_key: Vec<u8>,
    /// The secret key (32 bytes).
    pub secret_key: Vec<u8>,
}

/// Generates a new device key pair for provisioning.
#[uniffi::export]
pub fn generate_device_key_pair() -> DeviceKeyPair {
    use crate::credential_storage::provisioning::DeviceKeyPair as InternalDeviceKeyPair;

    let keypair = InternalDeviceKeyPair::generate();
    DeviceKeyPair {
        public_key: keypair.public_key().to_vec(),
        secret_key: keypair.secret_key().to_vec(),
    }
}

/// Generates a new random credential ID.
#[uniffi::export]
pub fn generate_credential_id() -> CredentialId {
    CredentialId::generate()
}
