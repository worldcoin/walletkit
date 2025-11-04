use semaphore_rs::poseidon_tree::Proof;
use serde::{Deserialize, Serialize};

use crate::{error::WalletKitError, request::Request, u256::U256Wrapper};

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SequencerBody {
    identity_commitment: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct InclusionProofResponse {
    status: String, // we explicitly don't type this to avoid failing on unknown statuses when this wouldn't be an issue
    root: U256Wrapper,
    proof: Proof,
}

const CREDENTIAL_NOT_ISSUED_RESPONSE: &str = "provided identity commitment not found";
const MINED_STATUS: &str = "mined"; // https://github.com/worldcoin/signup-sequencer/blob/f6050fbb3131ee6a61b2f44db3813f9150a045f5/schemas/openapi.yaml#L163

#[derive(Debug)]
#[derive(uniffi::Object)]
#[allow(clippy::module_name_repetitions)]
pub struct MerkleTreeProof {
    poseidon_proof: Proof,
    pub merkle_root: U256Wrapper,
}

impl MerkleTreeProof {
    /// Returns the Poseidon proof.
    #[must_use]
    pub const fn as_poseidon_proof(&self) -> &Proof {
        &self.poseidon_proof
    }
}

#[uniffi::export]
impl MerkleTreeProof {
    /// Retrieves a Merkle inclusion proof from the sign up sequencer for a given identity commitment.
    /// Each credential/environment pair uses a different sign up sequencer.
    ///
    /// # Errors
    /// Will throw an error if the request fails or parsing the response fails.
    #[uniffi::constructor]
    pub async fn from_identity_commitment(
        identity_commitment: &U256Wrapper,
        sequencer_host: &str,
        require_mined_proof: bool,
    ) -> Result<Self, WalletKitError> {
        let url = format!("{sequencer_host}/inclusionProof");

        // TODO: Cache inclusion proof for 10-15 mins
        let body = SequencerBody {
            identity_commitment: identity_commitment.to_hex_string(),
        };

        let request = Request::new();
        let http_response = request.post(url.clone(), body).await?;

        let status = http_response.status();

        // Try to get the raw response text first to diagnose issues
        let response_text = match http_response.text().await {
            Ok(text) => text,
            Err(err) => {
                return Err(WalletKitError::SerializationError { error: format!(
                    "[MerkleTreeProof] Failed to read response body from {url} with status {status}: {err}"
                ) });
            }
        };

        if status == 400 && response_text == CREDENTIAL_NOT_ISSUED_RESPONSE {
            return Err(WalletKitError::CredentialNotIssued);
        }

        match serde_json::from_str::<InclusionProofResponse>(&response_text) {
            Ok(response) => {
                if require_mined_proof && response.status != MINED_STATUS {
                    return Err(WalletKitError::CredentialNotMined);
                }

                Ok(Self {
                    poseidon_proof: response.proof,
                    merkle_root: response.root,
                })
            }
            Err(parse_err) => {
                // Return a more detailed error with first 20 characters of the response (only 20 to avoid logging something sensitive)
                Err(WalletKitError::SerializationError { error: format!(
                        "[MerkleTreeProof] Failed to parse response from {url} with status {status}: {parse_err}, received: {}",
                        response_text.chars().take(20).collect::<String>()
                    ),
                })
            }
        }
    }

    #[uniffi::constructor]
    pub fn from_json_proof(
        json_proof: &str,
        merkle_root: &str,
    ) -> Result<Self, WalletKitError> {
        let proof: Proof = serde_json::from_str(json_proof)
            .map_err(|_| WalletKitError::InvalidInput)?;

        Ok(Self {
            poseidon_proof: proof,
            merkle_root: U256Wrapper::try_from_hex_string(merkle_root)
                .map_err(|_| WalletKitError::InvalidInput)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::{credential_type::CredentialType, world_id::WorldId, Environment};

    use super::*;

    #[tokio::test]
    async fn test_retrieve_merkle_proof_from_sequencer() {
        let mut mock_server = mockito::Server::new_async().await;

        mock_server
            .mock("POST", "/inclusionProof")
            .with_status(200)
            .with_body(include_bytes!("../tests/fixtures/inclusion_proof.json"))
            .create_async()
            .await;

        let world_id = WorldId::new(b"not_a_real_secret", &Environment::Staging);

        let merkle_proof = MerkleTreeProof::from_identity_commitment(
            &world_id.get_identity_commitment(&CredentialType::Device),
            &mock_server.url(),
            false,
        )
        .await
        .unwrap();

        drop(mock_server);

        assert_eq!(
            merkle_proof.merkle_root,
            U256Wrapper::try_from_hex_string(
                "0x2f3a95b6df9074a19bf46e2308d7f5696e9dca49e0d64ef49a1425bbf40e0c02"
            )
            .unwrap()
        );

        assert_eq!(merkle_proof.poseidon_proof.leaf_index(), 17_029_704);
    }

    #[tokio::test]
    async fn test_http_error_handling() {
        let mut mock_server = mockito::Server::new_async().await;

        // Mock a 404 Not Found response
        mock_server
            .mock("POST", "/inclusionProof")
            .with_status(404)
            .with_header("Content-Type", "application/json")
            .with_body(r#"{"error":"Identity commitment not found"}"#)
            .create_async()
            .await;

        let world_id = WorldId::new(b"not_a_real_secret", &Environment::Staging);

        let url = mock_server.url();

        let result = MerkleTreeProof::from_identity_commitment(
            &world_id.get_identity_commitment(&CredentialType::Device),
            &url,
            false,
        )
        .await;

        drop(mock_server);

        assert!(result.is_err());
        if let Err(err) = result {
            match err {
                WalletKitError::SerializationError { error: msg } => {
                    assert!(msg.contains("with status 404"));
                    assert!(msg.contains(&url));
                }
                _ => panic!("Expected SerializationError, got: {err:?}"),
            }
        }
    }

    #[tokio::test]
    async fn test_credential_not_issued() {
        let mut mock_server = mockito::Server::new_async().await;

        // Mock a not issued credential response which the sequencer returns as the identity commitment not found in the set
        mock_server
            .mock("POST", "/inclusionProof")
            .with_status(400)
            .with_body("provided identity commitment not found")
            .create_async()
            .await;

        let world_id = WorldId::new(b"not_a_real_secret", &Environment::Staging);

        let url = mock_server.url();

        let result = MerkleTreeProof::from_identity_commitment(
            &world_id.get_identity_commitment(&CredentialType::Device),
            &url,
            false,
        )
        .await;

        drop(mock_server);

        assert!(result.is_err());
        if let Err(err) = result {
            match err {
                WalletKitError::CredentialNotIssued => {}
                _ => panic!("Expected CredentialNotIssued, got: {err:?}"),
            }
        }
    }

    #[tokio::test]
    async fn test_fail_when_mined_proof_is_required_and_identity_is_not_ready() {
        let mut mock_server = mockito::Server::new_async().await;

        let response = include_str!("../tests/fixtures/inclusion_proof.json")
            .replace("\"mined\"", "\"pending\"");

        mock_server
            .mock("POST", "/inclusionProof")
            .with_status(200)
            .with_body(response.as_bytes())
            .create_async()
            .await;

        let world_id = WorldId::new(b"not_a_real_secret", &Environment::Staging);

        let result = MerkleTreeProof::from_identity_commitment(
            &world_id.get_identity_commitment(&CredentialType::Device),
            &mock_server.url(),
            true,
        )
        .await
        .unwrap_err();

        drop(mock_server);

        assert!(matches!(result, WalletKitError::CredentialNotMined));
    }
}
