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
    root: U256Wrapper,
    proof: Proof,
}

#[derive(Debug)]
#[cfg_attr(feature = "ffi", derive(uniffi::Object))]
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

#[cfg_attr(feature = "ffi", uniffi::export)]
impl MerkleTreeProof {
    /// Retrieves a Merkle inclusion proof from the sign up sequencer for a given identity commitment.
    /// Each credential/environment pair uses a different sign up sequencer.
    ///
    /// # Errors
    /// Will throw an error if the request fails or parsing the response fails.
    #[cfg_attr(feature = "ffi", uniffi::constructor)]
    pub async fn from_identity_commitment(
        identity_commitment: &U256Wrapper,
        sequencer_host: &str,
    ) -> Result<Self, WalletKitError> {
        let url = format!("{sequencer_host}/inclusionProof");

        // TODO: Cache inclusion proof for 10-15 mins
        let body = SequencerBody {
            identity_commitment: identity_commitment.to_hex_string(),
        };

        let request = Request::new();
        let response = request
            .post(url, body)
            .await?
            .json::<InclusionProofResponse>()
            .await?;

        Ok(Self {
            poseidon_proof: response.proof,
            merkle_root: response.root,
        })
    }

    #[cfg_attr(feature = "ffi", uniffi::constructor)]
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
}
