use world_id_core::Credential as CoreCredential;

use crate::FieldElement;

/// Compute the `sub` for a credential computed from `leaf_index` and a `blinding_factor`.
#[uniffi::export]
pub fn compute_credential_sub(
    leaf_index: u64,
    blinding_factor: &FieldElement,
) -> FieldElement {
    CoreCredential::compute_sub(leaf_index, blinding_factor.0).into()
}
