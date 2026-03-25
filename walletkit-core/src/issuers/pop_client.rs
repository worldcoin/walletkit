use crate::{error::WalletKitError, Environment};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use world_id_core::Authenticator as CoreAuthenticator;


/// Request payload for registering or unregistering a recovery agent.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct ManageRecoveryAgentRequest {
    pub sub: String,
    #[serde(rename = "leafIndex")]
    pub leaf_index: u64,
}

#[derive(Deserialize)]
struct ChallengeResponse {
    challenge: String,
}

/// POP (Proof of Personhood) API client for recovery agent operations.
#[derive(uniffi::Object)]
pub struct PopClient {
    base_url: String,
    client: reqwest::Client,
}

#[uniffi::export]
impl PopClient {
    /// Create a new POP client for the specified environment.
    ///
    /// # Errors
    ///
    /// Returns error if the HTTP client cannot be constructed.
    #[uniffi::constructor]
    pub fn new(environment: &Environment) -> Result<Self, WalletKitError> {
        let base_url = match environment {
            Environment::Staging => "https://app.stage.orb.worldcoin.org",
            Environment::Production => "https://app.orb.worldcoin.org",
        }
        .to_string();

        let timeout = Duration::from_secs(60);
        let user_agent = format!("walletkit-core/{}", env!("CARGO_PKG_VERSION"));
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .user_agent(user_agent)
            .build()
            .map_err(|e| WalletKitError::Generic {
                error: format!("Failed to create client: {e}"),
            })?;
        Ok(Self { base_url, client })
    }
}

impl PopClient {
    /// Register a recovery agent.
    ///
    /// # Errors
    ///
    /// Returns error on network failure, conflict, or unexpected status.
    pub async fn register_recovery_agent(
        &self,
        request: ManageRecoveryAgentRequest,
        authenticator: &CoreAuthenticator,
    ) -> Result<(), WalletKitError> {
        let challenge = self.get_challenge().await?;
        let security_token = self.generate_recovery_agent_security_token(
            authenticator,
            &request,
            &challenge,
        )?;
        let url = format!("{}/api/v1/recovery-agent", self.base_url);
        self.update_recovery_agent(url, request, security_token, challenge)
            .await
    }

    /// Unregister a recovery agent.
    ///
    /// # Errors
    ///
    /// Returns error on network failure or unexpected status.
    pub async fn unregister_recovery_agent(
        &self,
        request: ManageRecoveryAgentRequest,
        authenticator: &CoreAuthenticator,
    ) -> Result<(), WalletKitError> {
        let challenge = self.get_challenge().await?;
        let security_token = self.generate_recovery_agent_security_token(
            authenticator,
            &request,
            &challenge,
        )?;
        let url = format!("{}/api/v1/recovery-agent", self.base_url);
        self.update_recovery_agent(url, request, security_token, challenge)
            .await
            .map_err(|e| WalletKitError::Generic {
                error: format!("Failed to unregister recovery agent: {e}"),
            })
    }

    async fn update_recovery_agent(
        &self,
        url: String,
        request: ManageRecoveryAgentRequest,
        security_token: String,
        challenge: String,
    ) -> Result<(), WalletKitError> {
        let response = self
            .client
            .post(&url)
            .json(&request)
            .header("X-Auth-Signature", security_token)
            .header("X-Auth-Challenge", challenge)
            .send()
            .await?;
        let response_status = response.status();
        match response_status {
            reqwest::StatusCode::CREATED | reqwest::StatusCode::OK => Ok(()),
            reqwest::StatusCode::CONFLICT => Err(WalletKitError::Generic {
                error: "Recovery agent already registered".to_string(),
            }),
            _ => {
                let error_message = response
                    .text()
                    .await
                    .unwrap_or_else(|_| String::from("Unknown error"));
                Err(WalletKitError::NetworkError {
                    url,
                    status: Some(response_status.as_u16()),
                    error: error_message,
                })
            }
        }
    }

    /// Fetch a challenge token from the server.
    ///
    /// # Errors
    ///
    /// Returns error on network failure or invalid response.
    pub async fn get_challenge(&self) -> Result<String, WalletKitError> {
        let url = format!("{}/api/v1/challenge", self.base_url);
        let response = self.client.get(&url).send().await?;

        let response_status = response.status();
        if !response_status.is_success() {
            let error_message = response
                .text()
                .await
                .unwrap_or_else(|_| String::from("Unknown error"));
            return Err(WalletKitError::NetworkError {
                url,
                status: Some(response_status.as_u16()),
                error: error_message,
            });
        }

        let challenge_response: ChallengeResponse =
            response
                .json()
                .await
                .map_err(|e| WalletKitError::SerializationError {
                    error: format!("Failed to parse challenge response: {e}"),
                })?;

        Ok(challenge_response.challenge)
    }

    /// Generates the security token for the recovery agent.
    ///
    /// # Errors
    ///
    /// Returns error if the challenge cannot be signed or if the security token cannot be generated.
    fn generate_recovery_agent_security_token(
        &self,
        authenticator: &CoreAuthenticator,
        request: &ManageRecoveryAgentRequest,
        challenge: &str,
    ) -> Result<String, WalletKitError> {
        
        let message_bytes =
            self.create_bytes_to_sign(challenge, request.leaf_index, &request.sub)?;
        let signature = authenticator.danger_sign_challenge(message_bytes.as_slice())
            .map_err(|e| WalletKitError::Generic {
                error: format!("Failed to sign challenge: {e}"),
            })?;
        Ok(signature.to_string())
    }

    /// Creates the bytes to sign for the recovery agent.
    ///
    /// # Errors
    ///
    /// Returns error if the challenge cannot be decoded or if the leaf index or sub cannot be decoded.
    pub fn create_bytes_to_sign(
        &self,
        challenge: &str,
        leaf_index: u64,
        sub: &str,
    ) -> Result<Vec<u8>, WalletKitError> {
        let challenge_bytes =
            hex::decode(challenge.trim_start_matches("0x")).map_err(|e| {
                WalletKitError::Generic {
                    error: format!("Failed to decode challenge: {e}"),
                }
            })?;
        let leaf_index_bytes = leaf_index.to_be_bytes();
        let sub_bytes = hex::decode(sub.trim_start_matches("0x")).map_err(|e| {
            WalletKitError::Generic {
                error: format!("Failed to decode sub: {e}"),
            }
        })?;
        let mut message_bytes = Vec::with_capacity(
            challenge_bytes.len() + leaf_index_bytes.len() + sub_bytes.len(),
        );
        message_bytes.extend_from_slice(&challenge_bytes);
        message_bytes.extend_from_slice(&leaf_index_bytes);
        message_bytes.extend_from_slice(&sub_bytes);
        Ok(message_bytes)
    }
}

mod tests {
    use serde_json::{to_string, Value};

    use std::sync::Arc;
    use crate::storage::CredentialStore;
    use crate::storage::tests_utils::InMemoryStorageProvider;
    use crate::storage::tests_utils::temp_root_path;
    use crate::Authenticator;
    use crate::issuers::pop_client::ManageRecoveryAgentRequest;
    use crate::issuers::PopClient;
    use crate::Environment;
    use world_id_core::Authenticator as CoreAuthenticator;
    use world_id_core::primitives::Config;
    use alloy::primitives::address;
    use serde_json::to_string;
    use alloy::{primitives::Address, signers::local::PrivateKeySigner};
    
    #[tokio::test]
    async fn test_recovery_agent_token_generator_failure() {
        let leaf_index = 42;
        let sub = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
            .to_string();
        let challenge =
            "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
                .to_string();
        let private_key =
            "d1995ace62b15d907bfb351ffe3cac57a8a84089a1b034101d2d7c78da415d58";

        // Read private key into sead
        let seed = hex::decode(private_key)
            .unwrap_or_else(|_| panic!("Failed to decode private key"));

        let root = temp_root_path();
        let provider = InMemoryStorageProvider::new(&root);
        

        // When account doesn't exist, this should fail
        let authenticator = Authenticator::init_with_defaults(
            seed.as_slice(),
            Some("http://127.0.0.1:8545".to_string()),
            &Environment::Staging,
            Arc::new(CredentialStore::from_provider(&provider).expect("store")),
        )
        .await
        .unwrap();
    let config = Config::new(
        Some("http://127.0.0.1:8545".to_string()),
        480,
        address!("0x969947cFED008bFb5e3F32a25A1A2CDdf64d46fe"),
        "https://world-id-indexer.stage-crypto.worldcoin.org".to_string(),
        "https://world-id-gateway.stage-crypto.worldcoin.org".to_string(),
        vec![],
        2,
    ).unwrap();
    
    let core_authenticator = CoreAuthenticator::init(seed.as_slice(), &to_string(&config).unwrap()).await.unwrap();
        let pop_client = PopClient::new(&Environment::Staging).unwrap();
        let message_bytes = pop_client
            .create_bytes_to_sign(&challenge, leaf_index, &sub)
            .unwrap();
        let request = ManageRecoveryAgentRequest {
            sub: sub.clone(),
            leaf_index,
        };
        let security_token = pop_client
            .generate_recovery_agent_security_token(
                &core_authenticator,
                &request,
                &challenge,
            )
            .unwrap();
        let expect_signature = "0x72ec312737276c94e3ac32ab1c393a63b9474480d3a9eb434b8bf6927b7222ef7eb1fea0812ff62a7fb144db9631751e505969162a9c590cabb27bf0bd5005581c";
        assert_eq!(security_token, expect_signature);
    }
}
