use std::sync::Arc;

use sha2::{Digest as _, Sha256};
use world_id_core::{
    requests::{
        ProofRequest as CoreProofRequest, ProofResponse as CoreProofResponse,
        ProofType as CoreProofType,
    },
    FieldElement as CoreFieldElement,
};

use crate::{error::WalletKitError, FieldElement};

/// A request from the RP to the Authenticator. See [`CoreProofRequest`] for more details.
/// This is a wrapper type to expose to foreign language bindings.
#[derive(Debug, Clone, uniffi::Object)]
pub struct ProofRequest(pub(crate) CoreProofRequest);

#[uniffi::export]
impl ProofRequest {
    /// Deserializes a `ProofRequest` from a JSON string.
    ///
    /// # Errors
    /// Returns an error if the JSON is invalid or cannot be parsed.
    #[uniffi::constructor]
    pub fn from_json(json: &str) -> Result<Self, WalletKitError> {
        let core_request = CoreProofRequest::from_json(json).map_err(|e| {
            WalletKitError::InvalidInput {
                attribute: "proof_request".to_string(),
                reason: format!("invalid proof request json: {e}"),
            }
        })?;
        Ok(Self(core_request))
    }

    /// Serializes the proof request to a JSON string.
    ///
    /// # Errors
    /// Returns an error if serialization fails.
    pub fn to_json(&self) -> Result<String, WalletKitError> {
        serde_json::to_string(&self.0).map_err(|e| WalletKitError::Generic {
            error: format!("critical unexpected error serializing to json: {e}"),
        })
    }

    /// Returns the unique identifier for this request.
    #[must_use]
    pub fn id(&self) -> String {
        self.0.id.clone()
    }

    /// Returns the request format version as a `u8`.
    #[must_use]
    pub const fn version(&self) -> u8 {
        self.0.version as u8
    }

    /// Returns which kind of proof the RP requests.
    ///
    /// A [`ProofRequestType::EmbeddingSimilarity`] request is not proven by
    /// `Authenticator::generate_proof`; it needs a Flamingo Token first.
    #[must_use]
    pub const fn proof_type(&self) -> ProofRequestType {
        match self.0.proof_type {
            CoreProofType::Uniqueness { .. } => ProofRequestType::Uniqueness,
            CoreProofType::Session => ProofRequestType::Session,
            CoreProofType::EmbeddingSimilarity(_) => {
                ProofRequestType::EmbeddingSimilarity
            }
        }
    }

    /// Returns the parameters of a Proof of Embedding Similarity request (WIP-202 §4.4), or
    /// `None` for any other proof type.
    #[must_use]
    pub fn embedding_similarity(&self) -> Option<EmbeddingSimilarityRequest> {
        let CoreProofType::EmbeddingSimilarity(params) = &self.0.proof_type else {
            return None;
        };
        Some(EmbeddingSimilarityRequest {
            challenge_hash: Arc::new(params.challenge_hash.into()),
            aat_required: params.aat.as_ref().is_some_and(|aat| aat.required),
        })
    }

    /// Returns whether `challenge` is the image this request's `challenge_hash` commits to,
    /// `R(SHA-256(challenge))`. Always `false` for requests that are not a Proof of Embedding
    /// Similarity.
    ///
    /// The RP signs only the hash, so the challenge image it sends alongside must be checked
    /// before it is used.
    #[must_use]
    #[allow(
        clippy::needless_pass_by_value,
        reason = "challenge is passed by value so uniffi 0.32 maps it to a `RustBuffer` (Kotlin `ByteArray` / Swift `Data`) rather than the non-`Send` `ForeignBytes` view produced for `&[u8]`"
    )]
    pub fn matches_challenge(&self, challenge: Vec<u8>) -> bool {
        let CoreProofType::EmbeddingSimilarity(params) = &self.0.proof_type else {
            return false;
        };
        CoreFieldElement::from_digest(&Sha256::digest(&challenge).into())
            == params.challenge_hash
    }
}

/// The kind of proof a [`ProofRequest`] asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ProofRequestType {
    /// A uniqueness proof scoped by the RP's action.
    Uniqueness,
    /// A session proof.
    Session,
    /// A WIP-202 Proof of Embedding Similarity.
    EmbeddingSimilarity,
}

/// The parameters of a Proof of Embedding Similarity request (WIP-202 §4.4).
#[derive(Debug, Clone, uniffi::Record)]
pub struct EmbeddingSimilarityRequest {
    /// `R(SHA-256(challenge))` of the challenge image the RP chose; see
    /// [`ProofRequest::matches_challenge`].
    pub challenge_hash: Arc<FieldElement>,
    /// Whether the RP requires the proof to come with a verified Authenticator Assertion Token.
    pub aat_required: bool,
}

/// A response from the Authenticator to the RP. See [`CoreProofResponse`] for more details.
///
/// This is a wrapper type to expose to foreign language bindings.
#[derive(Debug, Clone, uniffi::Object)]
pub struct ProofResponse(pub CoreProofResponse);

#[uniffi::export]
impl ProofResponse {
    /// Serializes the proof response to a JSON string.
    ///
    /// # Errors
    /// Returns an error if serialization fails.
    pub fn to_json(&self) -> Result<String, WalletKitError> {
        serde_json::to_string(&self.0).map_err(|e| WalletKitError::Generic {
            error: format!("critical unexpected error serializing to json: {e}"),
        })
    }

    /// Returns the unique identifier for this response.
    #[must_use]
    pub fn id(&self) -> String {
        self.0.id.clone()
    }

    /// Returns the response format version as a `u8`.
    #[must_use]
    pub const fn version(&self) -> u8 {
        self.0.version as u8
    }

    /// Returns the top-level error message, if the entire proof request failed.
    #[must_use]
    pub fn error(&self) -> Option<String> {
        self.0.error.clone()
    }
}

impl ProofResponse {
    /// Consumes the wrapper and returns the inner `CoreProofResponse`.
    #[must_use]
    pub fn into_inner(self) -> CoreProofResponse {
        self.0
    }
}

impl From<CoreProofRequest> for ProofRequest {
    fn from(core_request: CoreProofRequest) -> Self {
        Self(core_request)
    }
}

impl From<CoreProofResponse> for ProofResponse {
    fn from(core_response: CoreProofResponse) -> Self {
        Self(core_response)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use alloy::signers::{local::PrivateKeySigner, SignerSync};
    use alloy_core::primitives::U160;
    use serde_json::Value;
    use world_id_core::{
        primitives::{
            authenticator_assertion::AatRequirements, rp::RpId, FieldElement,
            OprfKeyId, SessionRef,
        },
        requests::{EmbeddingSimilarityParams, ProofType, RequestItem, RequestVersion},
    };

    use super::*;

    fn test_signature() -> alloy::signers::Signature {
        let signer = PrivateKeySigner::from_bytes(&[1u8; 32].into())
            .expect("test signer should be valid");
        signer
            .sign_message_sync(b"test")
            .expect("test signature should sign")
    }

    fn base_core_request(proof_type: ProofType) -> CoreProofRequest {
        CoreProofRequest {
            id: "test_request".to_string(),
            version: RequestVersion::V1,
            proof_type,
            created_at: 1_700_000_000,
            expires_at: 1_700_000_300,
            rp_id: RpId::new(1),
            oprf_key_id: OprfKeyId::new(U160::from(1)),
            session_id: SessionRef::None,
            signature: test_signature(),
            nonce: FieldElement::from(2u64),
            requests: vec![RequestItem {
                identifier: "credential".to_string(),
                issuer_schema_id: 1,
                signal: None,
                genesis_issued_at_min: None,
                expires_at_min: None,
            }],
            constraints: None,
        }
    }

    /// A Proof of Embedding Similarity request whose `challenge_hash` commits to `challenge`.
    pub fn embedding_similarity_request(
        challenge: &[u8],
        aat: Option<AatRequirements>,
    ) -> ProofRequest {
        let mut action = [0u8; 32];
        action[0] = 0x03;
        action[31] = 7;
        let params = EmbeddingSimilarityParams {
            action: FieldElement::from_be_bytes(&action)
                .expect("action is in the field"),
            challenge_hash: FieldElement::from_digest(
                &Sha256::digest(challenge).into(),
            ),
            aat,
        };
        let json = serde_json::to_string(&base_core_request(
            ProofType::EmbeddingSimilarity(params),
        ))
        .expect("request should serialize");
        ProofRequest::from_json(&json)
            .expect("embedding similarity request should parse")
    }

    #[test]
    fn proof_type_reports_each_kind() {
        let uniqueness = ProofRequest(base_core_request(ProofType::Uniqueness {
            action: FieldElement::from(1u64),
        }));
        assert_eq!(uniqueness.proof_type(), ProofRequestType::Uniqueness);
        assert!(uniqueness.embedding_similarity().is_none());

        let embedding = embedding_similarity_request(b"challenge", None);
        assert_eq!(
            embedding.proof_type(),
            ProofRequestType::EmbeddingSimilarity
        );
    }

    #[test]
    fn embedding_similarity_exposes_the_signed_parameters() {
        let request = embedding_similarity_request(
            b"challenge",
            Some(AatRequirements { required: true }),
        );
        let params = request
            .embedding_similarity()
            .expect("embedding similarity request");

        assert_eq!(
            params.challenge_hash.0,
            FieldElement::from_digest(&Sha256::digest(b"challenge").into())
        );
        assert!(params.aat_required);

        let without_aat = embedding_similarity_request(b"challenge", None)
            .embedding_similarity()
            .expect("embedding similarity request");
        assert!(!without_aat.aat_required);
    }

    #[test]
    fn matches_challenge_checks_the_committed_image() {
        let request = embedding_similarity_request(b"challenge", None);
        assert!(request.matches_challenge(b"challenge".to_vec()));
        assert!(!request.matches_challenge(b"another image".to_vec()));

        let uniqueness = ProofRequest(base_core_request(ProofType::Uniqueness {
            action: FieldElement::from(1u64),
        }));
        assert!(!uniqueness.matches_challenge(b"challenge".to_vec()));
    }

    #[test]
    fn from_json_defaults_missing_proof_type_to_uniqueness() {
        let proof_type = ProofType::Uniqueness {
            action: FieldElement::from(1u64),
        };
        let core_request = base_core_request(proof_type.clone());
        let mut value =
            serde_json::to_value(core_request).expect("request should serialize");
        value
            .as_object_mut()
            .expect("request should be an object")
            .remove("proof_type");

        let json =
            serde_json::to_string(&value).expect("request json should serialize");
        let request = ProofRequest::from_json(&json).expect("request should parse");

        assert_eq!(request.0.proof_type, proof_type);
    }

    #[test]
    fn from_json_rejects_invalid_proof_type_fields() {
        let mut value =
            serde_json::to_value(base_core_request(ProofType::Uniqueness {
                action: FieldElement::from(1u64),
            }))
            .expect("request should serialize");
        let object = value.as_object_mut().expect("request should be an object");
        object.insert(
            "proof_type".to_string(),
            Value::String("session".to_string()),
        );
        object.remove("action");

        let json =
            serde_json::to_string(&value).expect("request json should serialize");
        let error = ProofRequest::from_json(&json)
            .expect_err("session request needs session_id");

        match error {
            WalletKitError::InvalidInput { attribute, reason } => {
                assert_eq!(attribute, "proof_request");
                assert!(reason.contains("session_id"));
            }
            other => panic!("expected invalid input error, got {other:?}"),
        }
    }
}
