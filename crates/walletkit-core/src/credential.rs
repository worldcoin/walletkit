//! FFI-friendly wrapper around [`CoreCredential`].

use std::ops::Deref;

use world_id_core::Credential as CoreCredential;

use crate::error::WalletKitError;
use crate::FieldElement;

#[derive(serde::Deserialize)]
struct IssuanceResponse {
    credential: CoreCredential,
}

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

    /// Deserializes a `Credential` from an issuer response shaped as
    /// `{ "credential": ... }`.
    ///
    /// Accepting the complete response lets JavaScript callers pass its raw
    /// bytes to Rust without parsing signed `u64` fields as lossy JS numbers.
    ///
    /// # Errors
    ///
    /// Returns an error if the response or its credential cannot be deserialized.
    #[uniffi::constructor]
    #[expect(
        clippy::needless_pass_by_value,
        reason = "UniFFI constructors take owned byte buffers"
    )]
    pub fn from_issuance_response_bytes(
        bytes: Vec<u8>,
    ) -> Result<Self, WalletKitError> {
        let response: IssuanceResponse =
            serde_json::from_slice(&bytes).map_err(|e| {
                WalletKitError::InvalidInput {
                    attribute: "issuance_response_bytes".to_string(),
                    reason: format!("Failed to deserialize issuance response: {e}"),
                }
            })?;
        Ok(Self(response.credential))
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

    /// Returns the credential's expiration timestamp (unix seconds).
    #[must_use]
    pub const fn expires_at(&self) -> u64 {
        self.0.expires_at
    }

    /// Returns the credential's `associated_data_commitment` field element.
    ///
    /// The commitment scheme is issuer-defined.
    #[must_use]
    pub fn associated_data_commitment(&self) -> FieldElement {
        self.0.associated_data_commitment.into()
    }

    /// Returns the credential's raw claims, in schema order.
    ///
    /// Each claim is a field element; interpretation is defined by the issuer
    /// schema ([`Self::issuer_schema_id`]). Unset slots hold the zero field
    /// element. This exposes nothing [`Self::to_bytes`] doesn't already
    /// serialize — it is an accessor, not a disclosure mechanism; whether and
    /// which claims leave the device is entirely the host app's policy.
    #[must_use]
    pub fn claims(&self) -> Vec<std::sync::Arc<FieldElement>> {
        self.0
            .claims
            .iter()
            .map(|claim| std::sync::Arc::new((*claim).into()))
            .collect()
    }

    /// Returns the credential's raw claims as hex-encoded, padded strings, in
    /// schema order.
    ///
    /// Convenience over [`Self::claims`] using the same encoding claims carry
    /// in credential JSON.
    #[must_use]
    pub fn claims_hex(&self) -> Vec<String> {
        self.0.claims.iter().map(ToString::to_string).collect()
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

#[cfg(test)]
mod tests {
    use ruint::aliases::U256;
    use world_id_core::Credential as CoreCredential;

    use super::Credential;

    fn credential_with_claims() -> Credential {
        let core = CoreCredential::new()
            .claim_hash(0, U256::from(1u64))
            .expect("claim 0 in bounds")
            .claim_hash(1, U256::from(2u64))
            .expect("claim 1 in bounds");
        Credential(core)
    }

    #[test]
    fn claims_expose_field_elements_in_schema_order() {
        let credential = credential_with_claims();

        let claims = credential.claims();
        assert_eq!(claims.len(), credential.claims_hex().len());
        assert_eq!(
            claims[0].to_hex_string(),
            "0x0000000000000000000000000000000000000000000000000000000000000001"
        );
        assert_eq!(
            claims[1].to_hex_string(),
            "0x0000000000000000000000000000000000000000000000000000000000000002"
        );
    }

    #[test]
    fn claims_hex_matches_field_element_encoding() {
        let credential = credential_with_claims();

        let hex = credential.claims_hex();
        let from_elements: Vec<String> = credential
            .claims()
            .iter()
            .map(|claim| claim.to_hex_string())
            .collect();
        assert_eq!(hex, from_elements);

        // Unset slots are the zero field element.
        assert!(hex[2..].iter().all(|claim| claim
            == "0x0000000000000000000000000000000000000000000000000000000000000000"));
    }

    #[test]
    fn issuance_response_preserves_u64_fields_above_javascript_safe_integer() {
        let credential_id = 9_007_199_254_740_993;
        let credential = CoreCredential::new().id(credential_id);
        let response = serde_json::json!({ "credential": credential });
        let bytes = serde_json::to_vec(&response).unwrap();

        let parsed = Credential::from_issuance_response_bytes(bytes).unwrap();

        assert_eq!(parsed.0.id, credential_id);
    }
}
