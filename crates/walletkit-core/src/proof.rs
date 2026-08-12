use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use world_id_core::primitives::OwnershipProof as CoreOwnershipProof;

use crate::{error::WalletKitError, FieldElement};

/// A WIP-103 Ownership Proof available to foreign bindings
#[derive(Debug, Clone, uniffi::Object)]
pub struct OwnershipProof(pub(crate) CoreOwnershipProof);

#[uniffi::export]
impl OwnershipProof {
    /// Encodes the proof as raw bytes.
    ///
    /// # Errors
    /// An encoding error is theoretically possible, should not happen in practice.
    pub fn encode(&self) -> Result<Vec<u8>, WalletKitError> {
        let mut buffer = Vec::new();
        ciborium::into_writer(&self.0, &mut buffer).map_err(|_| {
            WalletKitError::SerializationError {
                error: "unexpected error serializing `OwnershipProof`".to_string(),
            }
        })?;
        Ok(buffer)
    }

    /// Encodes the proof as base-64 encoded bytes.
    ///
    /// # Errors
    /// An encoding error is theoretically possible, should not happen in practice.
    pub fn encode_b64(&self) -> Result<String, WalletKitError> {
        Ok(BASE64_URL_SAFE_NO_PAD.encode(self.encode()?))
    }

    /// The root hash of the Merkle root used for inclusion in the `WorldIDRegistry`.
    #[must_use]
    pub fn merkle_root(&self) -> FieldElement {
        self.0.merkle_root.into()
    }

    /// Serializes the proof to the verification service's JSON wire shape:
    /// `{"merkle_root": "0x...", "proof": {"narg_string": "<base64>", "hints": "<base64>"}}`.
    ///
    /// Delegates to the inner type's own `Serialize` impl rather than
    /// re-deriving the field-level encoding here, so this can never drift
    /// from what the verification service (which deserializes the same
    /// `world_id_primitives::proof::OwnershipProof` type) expects.
    ///
    /// # Errors
    /// An encoding error is theoretically possible, should not happen in practice.
    pub fn to_json_string(&self) -> Result<String, WalletKitError> {
        serde_json::to_string(&self.0).map_err(|_| WalletKitError::SerializationError {
            error: "unexpected error serializing `OwnershipProof` to JSON".to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use world_id_core::primitives::FieldElement as CoreFieldElement;
    use world_id_proof::WhirR1CSProof;

    fn sample_proof() -> OwnershipProof {
        OwnershipProof(CoreOwnershipProof {
            proof: WhirR1CSProof {
                narg_string: vec![0xde, 0xad, 0xbe, 0xef],
                hints: vec![0x01, 0x02],
            },
            merkle_root: CoreFieldElement::from(7u64),
        })
    }

    /// Asserted against the verifier's own shape (exact keys and base64, not
    /// hex, for the WHIR components) rather than round-tripped through our own
    /// deserializer, which would pass even if every key were wrong.
    #[test]
    fn json_matches_the_verifier_shape() {
        let json = sample_proof().to_json_string().expect("should serialize");
        let value: serde_json::Value = serde_json::from_str(&json).expect("should be valid JSON");

        assert_eq!(
            value["merkle_root"],
            FieldElement::from(CoreFieldElement::from(7u64)).to_hex_string()
        );
        assert_eq!(value["proof"]["narg_string"], "3q2+7w==");
        assert_eq!(value["proof"]["hints"], "AQI=");
    }
}
