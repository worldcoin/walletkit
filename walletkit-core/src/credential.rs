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
