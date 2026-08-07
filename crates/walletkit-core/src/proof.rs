use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use serde::Serialize;
use uuid::Uuid;
use world_id_core::primitives::{
    FieldElement as CoreFieldElement, OwnershipProof as CoreOwnershipProof,
};

use crate::{error::WalletKitError, FieldElement};

/// The only challenge type the verifier issues. A second type would need this to
/// become a parameter, which is a breaking change for foreign bindings either way.
const CHALLENGE_TYPE_ENROLLMENT: &str = "enrollment";

/// Mirrors the verifier's `OwnershipVerificationRequest`. The nonce is absent by
/// design: the service looks it up from its nonce store by `challenge_id` and
/// never accepts a client-supplied one.
#[derive(Serialize)]
struct OwnershipVerificationRequest<'a> {
    challenge_id: Uuid,
    challenge_type: &'static str,
    credential_sub: &'a CoreFieldElement,
    proof: &'a CoreOwnershipProof,
}

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

    /// Builds the complete JSON body for the verifier's `POST /api/v4/verify`.
    ///
    /// The whole body is assembled here rather than leaving the host to wrap the
    /// proof, so the request shape lives in the crate that owns the proof type
    /// and cannot drift per consumer.
    ///
    /// `challenge_id` is the value the host received from
    /// `POST /api/v4/zkp/challenge/enrollment`; walletkit does not fetch it.
    ///
    /// # Errors
    /// - [`WalletKitError::InvalidInput`] if `challenge_id` is not a UUID.
    /// - [`WalletKitError::SerializationError`] if serialization fails, which
    ///   should not happen in practice.
    pub fn to_verification_request_json(
        &self,
        challenge_id: &str,
        credential_sub: &FieldElement,
    ) -> Result<String, WalletKitError> {
        let challenge_id = Uuid::try_parse(challenge_id.trim()).map_err(|_| {
            WalletKitError::InvalidInput {
                attribute: "challenge_id".to_string(),
                reason: "expected the UUID issued by the challenge endpoint"
                    .to_string(),
            }
        })?;

        serde_json::to_string(&OwnershipVerificationRequest {
            challenge_id,
            challenge_type: CHALLENGE_TYPE_ENROLLMENT,
            credential_sub: &credential_sub.0,
            proof: &self.0,
        })
        .map_err(|_| WalletKitError::SerializationError {
            error: "unexpected error serializing the verification request".to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use world_id_proof::WhirR1CSProof;

    const CHALLENGE_ID: &str = "6f1a8b2c-0e4d-4a7b-9c3e-5d2f8a1b7c40";

    fn proof_fixture() -> OwnershipProof {
        OwnershipProof(CoreOwnershipProof {
            proof: WhirR1CSProof {
                narg_string: vec![0xde, 0xad, 0xbe, 0xef],
                hints: vec![0x01, 0x02],
            },
            merkle_root: CoreFieldElement::from(7u64),
        })
    }

    fn request_json() -> serde_json::Value {
        let json = proof_fixture()
            .to_verification_request_json(CHALLENGE_ID, &FieldElement::from_u64(42))
            .expect("request should serialize");
        serde_json::from_str(&json).expect("output should be valid JSON")
    }

    /// Asserted against the verifier's own `OwnershipVerificationRequest` shape
    /// rather than round-tripped through our own deserializer, which would pass
    /// even if every key name were wrong.
    #[test]
    fn request_matches_the_verifier_shape() {
        let value = request_json();
        let object = value.as_object().expect("top level is an object");

        let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            ["challenge_id", "challenge_type", "credential_sub", "proof"]
        );

        let mut proof_keys: Vec<&str> = value["proof"]
            .as_object()
            .expect("proof is an object")
            .keys()
            .map(String::as_str)
            .collect();
        proof_keys.sort_unstable();
        assert_eq!(proof_keys, ["merkle_root", "proof"]);

        let mut whir_keys: Vec<&str> = value["proof"]["proof"]
            .as_object()
            .expect("whir proof is an object")
            .keys()
            .map(String::as_str)
            .collect();
        whir_keys.sort_unstable();
        assert_eq!(whir_keys, ["hints", "narg_string"]);
    }

    #[test]
    fn challenge_type_is_the_snake_case_name_the_verifier_expects() {
        assert_eq!(request_json()["challenge_type"], "enrollment");
    }

    #[test]
    fn challenge_id_is_the_hyphenated_uuid() {
        assert_eq!(request_json()["challenge_id"], CHALLENGE_ID);
    }

    /// `ProveKit`'s `serde_hex` module is misnamed: in human-readable formats it
    /// emits standard base64, and only auto-detects hex when deserializing.
    /// Both sides are on provekit-common 0.1.4, so this is the agreed encoding.
    #[test]
    fn proof_components_are_base64_not_hex() {
        let value = request_json();
        assert_eq!(value["proof"]["proof"]["narg_string"], "3q2+7w==");
        assert_eq!(value["proof"]["proof"]["hints"], "AQI=");
    }

    #[test]
    fn field_elements_serialize_as_their_hex_string() {
        let value = request_json();
        assert_eq!(
            value["credential_sub"],
            FieldElement::from_u64(42).to_hex_string().as_str()
        );
        assert_eq!(
            value["proof"]["merkle_root"],
            FieldElement::from_u64(7).to_hex_string().as_str()
        );
    }

    #[test]
    fn rejects_a_challenge_id_that_is_not_a_uuid() {
        let error = proof_fixture()
            .to_verification_request_json("not-a-uuid", &FieldElement::from_u64(1))
            .expect_err("a malformed challenge id must not reach the verifier");
        assert!(matches!(error, WalletKitError::InvalidInput { .. }));
    }

    #[test]
    fn accepts_a_challenge_id_with_surrounding_whitespace() {
        let json = proof_fixture()
            .to_verification_request_json(
                &format!("  {CHALLENGE_ID}\n"),
                &FieldElement::from_u64(1),
            )
            .expect("surrounding whitespace should be tolerated");
        assert!(json.contains(CHALLENGE_ID));
    }
}
