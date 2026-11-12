//! Shared domain, status, and result types for WIP-109 authenticator registration.

use std::sync::Arc;

use alloy_core::primitives::Address;
use world_id_core::registration::{
    KnownAuthenticator, RegistrationErrorReason, RegistrationRequest,
    RegistrationResult as CoreRegistrationResult,
};

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

    /// Returns whether the Approving Authenticator included a credential vault backup.
    ///
    /// The vault bytes themselves are returned in [`Registered::vault_backup`] only after
    /// [`RegistrationRequester::verify`](super::RegistrationRequester::verify) confirms the
    /// on-chain registration.
    #[must_use]
    pub const fn has_vault(&self) -> bool {
        self.0.vault.is_some()
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
    /// The shared `CredentialStore::export_vault_for_backup` output, to import with
    /// `CredentialStore::merge_vault_from_backup` once storage is initialized.
    pub vault_backup: Option<Vec<u8>>,
}

impl std::fmt::Debug for Registered {
    /// Formats [`Registered`] without printing the plaintext `vault_backup` bytes.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Registered")
            .field("authenticator", &self.authenticator)
            .field(
                "vault_backup",
                &self.vault_backup.as_ref().map(|_| "<redacted>"),
            )
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
    /// Whether the vault was left out because it exceeds [`MAX_VAULT_SIZE`](super::MAX_VAULT_SIZE).
    /// The host must tell the user that the vault was not shared.
    pub vault_omitted: bool,
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
