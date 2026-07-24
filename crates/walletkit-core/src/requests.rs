use world_id_core::requests::{
    ProofRequest as CoreProofRequest, ProofResponse as CoreProofResponse,
};

use crate::error::WalletKitError;

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
mod tests {
    use alloy::signers::{local::PrivateKeySigner, SignerSync};
    use alloy_core::primitives::U160;
    use serde_json::Value;
    use taceo_oprf::types::OprfKeyId;
    use world_id_core::{
        primitives::{rp::RpId, FieldElement},
        requests::{ProofType, RequestItem, RequestVersion},
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
            session_id: None,
            action: Some(FieldElement::from(1u64)),
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

    #[test]
    fn from_json_defaults_missing_proof_type_to_uniqueness() {
        let core_request = base_core_request(ProofType::Uniqueness);
        let mut value =
            serde_json::to_value(core_request).expect("request should serialize");
        value
            .as_object_mut()
            .expect("request should be an object")
            .remove("proof_type");

        let json =
            serde_json::to_string(&value).expect("request json should serialize");
        let request = ProofRequest::from_json(&json).expect("request should parse");

        assert_eq!(request.0.proof_type, ProofType::Uniqueness);
    }

    #[test]
    fn from_json_rejects_invalid_proof_type_fields() {
        let mut value = serde_json::to_value(base_core_request(ProofType::Uniqueness))
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
