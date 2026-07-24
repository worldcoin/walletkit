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
}
