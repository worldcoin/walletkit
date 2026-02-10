//! FFI-friendly wrapper around [`CoreCredential`].

use std::ops::Deref;

use world_id_core::Credential as CoreCredential;

use crate::error::WalletKitError;
use crate::FieldElement;

/// A wrapper around [`CoreCredential`] to enable FFI interoperability.
///
/// Encapsulates the credential and exposes accessors for fields that FFI
/// callers need.
#[derive(Debug, Clone, uniffi::Object)]
pub struct Credential(CoreCredential);

#[uniffi::export]
impl Credential {
    /// Deserializes a `Credential` from a JSON byte blob.
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes cannot be deserialized.
    #[uniffi::constructor]
    #[allow(clippy::needless_pass_by_value)]
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, WalletKitError> {
        let credential: CoreCredential =
            serde_json::from_slice(&bytes).map_err(|e| {
                WalletKitError::InvalidInput {
                    attribute: "credential_bytes".to_string(),
                    reason: format!("Failed to deserialize credential: {e}"),
                }
            })?;
        Ok(Self(credential))
    }

    /// Returns the credential's `sub` field element.
    #[must_use]
    pub fn sub(&self) -> FieldElement {
        self.0.sub.into()
    }

    /// Returns the credential's issuer schema ID.
    #[must_use]
    pub const fn issuer_schema_id(&self) -> u64 {
        self.0.issuer_schema_id
    }
}

impl Credential {
    /// Serializes the credential to a JSON byte blob for storage.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    pub fn to_bytes(&self) -> Result<Vec<u8>, WalletKitError> {
        serde_json::to_vec(&self.0).map_err(|e| WalletKitError::SerializationError {
            error: format!("Failed to serialize credential: {e}"),
        })
    }

    /// Returns the credential's `genesis_issued_at` timestamp.
    #[must_use]
    pub const fn genesis_issued_at(&self) -> u64 {
        self.0.genesis_issued_at
    }
}

impl From<CoreCredential> for Credential {
    fn from(val: CoreCredential) -> Self {
        Self(val)
    }
}

impl From<Credential> for CoreCredential {
    fn from(val: Credential) -> Self {
        val.0
    }
}

impl Deref for Credential {
    type Target = CoreCredential;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
