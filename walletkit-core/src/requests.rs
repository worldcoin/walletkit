//! Proof requests and responses in World ID v4.

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
        let core_request: CoreProofRequest =
            serde_json::from_str(json).map_err(|e| WalletKitError::Generic {
                error: format!("invalid proof request json: {e}"),
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

    /// Returns the protocol version as a `u8`.
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

    /// Returns the protocol version as a `u8`.
    #[must_use]
    pub const fn version(&self) -> u8 {
        self.0.version as u8
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
