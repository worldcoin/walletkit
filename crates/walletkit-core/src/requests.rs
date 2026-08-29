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
pub struct ProofResponse {
    inner: CoreProofResponse,
    /// Claims of the credential used for each response item, keyed by issuer
    /// schema id and hex-encoded. Populated only by
    /// `Authenticator::generate_proof_disclosing_claims`; empty otherwise.
    disclosed_claims: std::collections::HashMap<u64, Vec<String>>,
}

#[uniffi::export]
impl ProofResponse {
    /// Serializes the proof response to a JSON string.
    ///
    /// When the response was generated with claim disclosure, every response
    /// item additionally carries a `claims` array of hex-encoded field
    /// elements, sourced from the stored credential the item was proven
    /// against. The protocol types are untouched: the field is injected into
    /// the serialized JSON only.
    ///
    /// # Errors
    /// Returns an error if serialization fails.
    pub fn to_json(&self) -> Result<String, WalletKitError> {
        let serialization_error = |e: serde_json::Error| WalletKitError::Generic {
            error: format!("critical unexpected error serializing to json: {e}"),
        };
        if self.disclosed_claims.is_empty() {
            return serde_json::to_string(&self.inner).map_err(serialization_error);
        }
        let mut value =
            serde_json::to_value(&self.inner).map_err(serialization_error)?;
        inject_claims(&mut value, &self.disclosed_claims);
        serde_json::to_string(&value).map_err(serialization_error)
    }

    /// Returns the unique identifier for this response.
    #[must_use]
    pub fn id(&self) -> String {
        self.inner.id.clone()
    }

    /// Returns the response format version as a `u8`.
    #[must_use]
    pub const fn version(&self) -> u8 {
        self.inner.version as u8
    }

    /// Returns the top-level error message, if the entire proof request failed.
    #[must_use]
    pub fn error(&self) -> Option<String> {
        self.inner.error.clone()
    }
}

impl ProofResponse {
    /// Wraps a core response together with the claims to disclose per issuer
    /// schema id. Claims are hex-encoded field elements in schema order.
    #[must_use]
    pub(crate) const fn with_disclosed_claims(
        inner: CoreProofResponse,
        disclosed_claims: std::collections::HashMap<u64, Vec<String>>,
    ) -> Self {
        Self {
            inner,
            disclosed_claims,
        }
    }

    /// Returns a reference to the inner `CoreProofResponse`.
    #[must_use]
    pub const fn inner(&self) -> &CoreProofResponse {
        &self.inner
    }

    /// Consumes the wrapper and returns the inner `CoreProofResponse`.
    #[must_use]
    pub fn into_inner(self) -> CoreProofResponse {
        self.inner
    }
}

/// Inserts a `claims` array into every serialized response item whose
/// `issuer_schema_id` has disclosed claims.
fn inject_claims(
    value: &mut serde_json::Value,
    disclosed_claims: &std::collections::HashMap<u64, Vec<String>>,
) {
    let Some(items) = value
        .get_mut("responses")
        .and_then(serde_json::Value::as_array_mut)
    else {
        return;
    };
    for item in items {
        let Some(claims) = item
            .get("issuer_schema_id")
            .and_then(serde_json::Value::as_u64)
            .and_then(|id| disclosed_claims.get(&id))
        else {
            continue;
        };
        if let Some(item) = item.as_object_mut() {
            item.insert(
                "claims".to_string(),
                serde_json::Value::Array(
                    claims
                        .iter()
                        .map(|claim| serde_json::Value::String(claim.clone()))
                        .collect(),
                ),
            );
        }
    }
}

impl From<CoreProofRequest> for ProofRequest {
    fn from(core_request: CoreProofRequest) -> Self {
        Self(core_request)
    }
}

impl From<CoreProofResponse> for ProofResponse {
    fn from(core_response: CoreProofResponse) -> Self {
        Self::with_disclosed_claims(core_response, std::collections::HashMap::new())
    }
}

#[cfg(test)]
mod tests {
    use alloy::signers::{local::PrivateKeySigner, SignerSync};
    use alloy_core::primitives::U160;
    use serde_json::Value;
    use world_id_core::{
        primitives::{rp::RpId, FieldElement, OprfKeyId, SessionRef},
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
            session_id: SessionRef::None,
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

    fn base_core_response() -> CoreProofResponse {
        let json = r#"{
  "id": "test_response",
  "version": 1,
  "responses": [
    {
      "identifier": "orb",
      "issuer_schema_id": 100,
      "proof": "00000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000000",
      "nullifier": "nil_00000000000000000000000000000000000000000000000000000000000003e9",
      "expires_at_min": 1700000000
    },
    {
      "identifier": "face",
      "issuer_schema_id": 200,
      "proof": "00000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000000",
      "nullifier": "nil_00000000000000000000000000000000000000000000000000000000000003ea",
      "expires_at_min": 1700000000
    }
  ]
}"#;
        serde_json::from_str(json).expect("response fixture should parse")
    }

    #[test]
    fn to_json_without_disclosure_matches_core_serialization() {
        let core = base_core_response();
        let expected =
            serde_json::to_string(&core).expect("core response should serialize");

        let wrapped: ProofResponse = core.into();
        let json = wrapped.to_json().expect("wrapper should serialize");

        assert_eq!(json, expected);
        assert!(!json.contains("claims"));
    }

    #[test]
    fn to_json_injects_disclosed_claims_on_matching_items_only() {
        let claims = std::collections::HashMap::from([(
            200u64,
            vec![
                "0x0000000000000000000000000000000000000000000000000000000000000001"
                    .to_string(),
                "0x0000000000000000000000000000000000000000000000000000000000000002"
                    .to_string(),
            ],
        )]);
        let wrapped =
            ProofResponse::with_disclosed_claims(base_core_response(), claims);

        let value: Value =
            serde_json::from_str(&wrapped.to_json().expect("wrapper should serialize"))
                .expect("output should be valid json");

        let items = value["responses"].as_array().expect("responses array");
        assert!(
            items[0].get("claims").is_none(),
            "item without disclosed claims must stay untouched"
        );
        let disclosed = items[1]["claims"].as_array().expect("claims array");
        assert_eq!(disclosed.len(), 2);
        assert_eq!(
            disclosed[0],
            "0x0000000000000000000000000000000000000000000000000000000000000001"
        );
        assert_eq!(
            disclosed[1],
            "0x0000000000000000000000000000000000000000000000000000000000000002"
        );
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
