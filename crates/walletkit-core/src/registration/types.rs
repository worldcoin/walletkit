//! Shared domain, status, and result types for WIP-109 authenticator registration.

use std::sync::Arc;

use alloy_core::primitives::Address;
use world_id_core::registration::{
    Attachment, KnownAuthenticator, RegistrationErrorReason, RegistrationRequest,
    RegistrationResult as CoreRegistrationResult,
};
use zeroize::Zeroizing;

use super::errors::RegistrationError;
use crate::Authenticator;

/// The class an authenticator registers with.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum RequestedClass {
    /// An Admin Authenticator, which registers the management key derived from its seed.
    Admin,
    /// A Proving Authenticator.
    Proving,
}

impl RequestedClass {
    /// Returns the class requested by `request`.
    pub(super) const fn of(request: &RegistrationRequest) -> Self {
        if request.new_authenticator_address.is_some() {
            Self::Admin
        } else {
            Self::Proving
        }
    }
}

/// Returns the requested display name as a `String`, if present.
pub(super) fn requested_name(request: &RegistrationRequest) -> Option<String> {
    request.name.as_ref().map(|name| name.as_str().to_string())
}

/// Returns the on-chain address the registry records for `request`: its management key, or the
/// zero address for a Proving Authenticator (WIP-104).
pub(super) fn onchain_address(request: &RegistrationRequest) -> Address {
    request.new_authenticator_address.unwrap_or(Address::ZERO)
}

/// The result of a successful registration: where the new authenticator was inserted, and the
/// credentials it needs to generate proofs.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Object)]
pub struct RegistrationResult(pub(super) CoreRegistrationResult);

#[uniffi::export]
impl RegistrationResult {
    /// Returns the index of the account the authenticator was registered on.
    #[must_use]
    pub const fn leaf_index(&self) -> u64 {
        self.0.leaf_index
    }

    /// Returns the slot the authenticator was inserted at.
    #[must_use]
    pub const fn pubkey_id(&self) -> u32 {
        self.0.pubkey_id
    }

    /// Returns the names of the account's other authenticators known to the Approving
    /// Authenticator.
    #[must_use]
    pub fn authenticators(&self) -> Vec<KnownAuthenticator> {
        self.0.authenticators.clone()
    }

    /// Returns whether the Approving Authenticator included a vault with the credentials the
    /// user selected.
    ///
    /// The vault bytes themselves are returned in [`Registered::vault_backup`] only after
    /// [`RegistrationRequester::verify`](super::RegistrationRequester::verify) confirms the
    /// on-chain registration.
    #[must_use]
    pub const fn has_vault(&self) -> bool {
        self.0.vault.is_some()
    }

    /// Returns how many attachments the Approving Authenticator included.
    ///
    /// The attachments themselves are returned in [`Registered::attachments`], together with
    /// the vault.
    #[must_use]
    pub fn attachment_count(&self) -> u64 {
        u64::try_from(self.0.attachments.len()).unwrap_or(u64::MAX)
    }
}

/// Data that an issuer's code attaches to a transferred credential, e.g. a Personal Custody
/// Package.
///
/// `WalletKit` carries `format` and `data` without interpreting them. The host passes both to
/// the code of the issuer of `issuer_schema_id`, which must treat received ones as untrusted
/// input. The data may be biometric: never log it.
#[derive(Clone, PartialEq, Eq, uniffi::Record)]
pub struct RegistrationAttachment {
    /// The issuer schema of the credential the attachment belongs to.
    pub issuer_schema_id: u64,
    /// The format of `data`, defined by the issuer's code.
    pub format: String,
    /// The attachment bytes.
    pub data: Vec<u8>,
}

impl std::fmt::Debug for RegistrationAttachment {
    /// Formats [`RegistrationAttachment`] with the length of `data` instead of its bytes.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegistrationAttachment")
            .field("issuer_schema_id", &self.issuer_schema_id)
            .field("format", &self.format)
            .field("len", &self.data.len())
            .finish_non_exhaustive()
    }
}

impl From<RegistrationAttachment> for Attachment {
    /// Moves the attachment into its wire form, whose bytes are zeroized on drop.
    fn from(attachment: RegistrationAttachment) -> Self {
        Self {
            issuer_schema_id: attachment.issuer_schema_id,
            format: attachment.format,
            data: Zeroizing::new(attachment.data),
        }
    }
}

impl From<&Attachment> for RegistrationAttachment {
    /// Copies a received attachment out for the host.
    fn from(attachment: &Attachment) -> Self {
        Self {
            issuer_schema_id: attachment.issuer_schema_id,
            format: attachment.format.clone(),
            data: attachment.data.to_vec(),
        }
    }
}

/// The credentials the user selected to transfer to the new authenticator, passed to
/// [`CheckedRegistration::approve`](super::CheckedRegistration::approve).
#[derive(Clone, PartialEq, Eq, uniffi::Record)]
pub struct CredentialTransfer {
    /// The `CredentialStore::export_vault_for_issuer_schemas` output for the issuer schemas the
    /// user selected.
    pub vault: Vec<u8>,
    /// Issuer-specific data for the credentials in `vault`.
    pub attachments: Vec<RegistrationAttachment>,
}

impl std::fmt::Debug for CredentialTransfer {
    /// Formats [`CredentialTransfer`] with the length of `vault` instead of its plaintext bytes.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredentialTransfer")
            .field("vault_len", &self.vault.len())
            .field("attachments", &self.attachments)
            .finish()
    }
}

/// What [`RegistrationRequester::poll`](super::RegistrationRequester::poll) found on the bridge.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum RequesterStatus {
    /// The Approving Authenticator has not opened the Pairing URI yet.
    Waiting,
    /// The Approving Authenticator took the request. Show the pairing code.
    Retrieved,
    /// The Approving Authenticator approved the registration. The result must be checked with
    /// [`RegistrationRequester::verify`](super::RegistrationRequester::verify) before it is used.
    Approved {
        /// The unverified registration result.
        result: Arc<RegistrationResult>,
    },
    /// The Approving Authenticator refused or could not complete the registration.
    Refused {
        /// The error reported by the Approving Authenticator.
        error: RegistrationError,
    },
    /// The session expired, was cancelled, or its response was lost. Start a new session with
    /// the same seed.
    Expired,
}

/// A verified registration.
#[derive(uniffi::Record)]
pub struct Registered {
    /// The new authenticator. Its storage is not initialized yet.
    pub authenticator: Arc<Authenticator>,
    /// The `CredentialStore::export_vault_for_issuer_schemas` output for the credentials the
    /// user selected on the Approving Authenticator, to import with
    /// `CredentialStore::merge_vault_from_backup` once storage is initialized. `None` if the
    /// user selected none.
    pub vault_backup: Option<Vec<u8>>,
    /// Issuer-specific data for the credentials in `vault_backup`, to hand to the code of each
    /// attachment's issuer as untrusted input. The Approving Authenticator is not bound to the
    /// issuer schemas this session declared, so the host should warn the user about an
    /// attachment it does not recognize, and drop it.
    pub attachments: Vec<RegistrationAttachment>,
}

impl std::fmt::Debug for Registered {
    /// Formats [`Registered`] without printing the plaintext `vault_backup` or attachment bytes.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Registered")
            .field("authenticator", &self.authenticator)
            .field(
                "vault_backup",
                &self.vault_backup.as_ref().map(|_| "<redacted>"),
            )
            .field("attachments", &self.attachments)
            .finish()
    }
}

/// How a checked registration will be carried out.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum RegistrationPlan {
    /// Insert the authenticator at `pubkey_id`.
    Insert {
        /// The slot the authenticator will be inserted at.
        pubkey_id: u32,
    },
    /// The authenticator is already registered as requested, e.g. by an earlier session whose
    /// response was lost. Approval only sends the result.
    AlreadyRegistered {
        /// The slot the authenticator is registered at.
        pubkey_id: u32,
    },
}

/// The result of [`CheckedRegistration::approve`](super::CheckedRegistration::approve).
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct ApprovalOutcome {
    /// Whether the authenticator was registered.
    pub result: ApprovalResult,
    /// Whether the response was delivered.
    pub delivered: bool,
}

/// Whether [`CheckedRegistration::approve`](super::CheckedRegistration::approve) registered the
/// authenticator.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum ApprovalResult {
    /// The authenticator is registered on-chain, even if the response was not delivered.
    Registered {
        /// The index of the account.
        leaf_index: u64,
        /// The slot the authenticator is registered at.
        pubkey_id: u32,
    },
    /// The registration did not succeed. `OutcomeUnknown` means that it may still land.
    Failed {
        /// The reason, which was sent to the Requesting Authenticator.
        reason: RegistrationErrorReason,
    },
}
