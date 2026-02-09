use std::ops::Deref;

use world_id_core::Credential as CoreCredential;

use crate::FieldElement;

/// Base representation of a `Credential` in the World ID Protocol.
///
/// See [`CoreCredential`] for details.
#[derive(Debug, Clone, uniffi::Object)]
pub struct Credential(CoreCredential);

/// Compute the `sub` for a credential computed from `leaf_index` and a `blinding_factor`.
#[uniffi::export]
pub fn compute_credential_sub(
    leaf_index: u64,
    blinding_factor: &FieldElement,
) -> FieldElement {
    CoreCredential::compute_sub(leaf_index, blinding_factor.0).into()
}

#[uniffi::export]
impl Credential {
    /// Returns the credential's subject
    #[must_use]
    pub fn sub(&self) -> FieldElement {
        self.0.sub.into()
    }
}

impl From<CoreCredential> for Credential {
    fn from(credential: CoreCredential) -> Self {
        Self(credential)
    }
}

impl From<Credential> for CoreCredential {
    fn from(credential: Credential) -> Self {
        credential.0
    }
}

impl Deref for Credential {
    type Target = CoreCredential;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
