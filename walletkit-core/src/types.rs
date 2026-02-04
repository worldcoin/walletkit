use world_id_core::requests::ProofResponse as CoreProofResponse;

use crate::error::WalletKitError;

#[derive(Debug, Clone, uniffi::Object)]
pub struct ProofResponse(CoreProofResponse);

#[uniffi::export]
impl ProofResponse {
    fn to_json(&self) -> Result<String, WalletKitError> {
        serde_json::to_string(&self.0).map_err(|e| WalletKitError::Generic {
            error: format!("critical unexpected error serializing to json: {e}"),
        })
    }
}
