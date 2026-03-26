//! Bindings for managing recovery agents via the Proof-of-Personhood (`PoP`) backend.
//!
//! A recovery agent is an entity authorized to initiate account recovery on behalf of
//! a user. This module provides [`RecoveryBindingManager`], which handles the authenticated
//! registration and removal of recovery agents through a challenge-response protocol
//! secured by the authenticator's signing key.
//!
//! ## Protocol
//!
//! 1. Fetch a one-time challenge from the `PoP` backend.
//! 2. Construct a commitment: `keccak256(challenge || leaf_index || sub)`.
//! 3. Sign the commitment with the authenticator's key to produce a security token.
//! 4. Submit the request with the signature and challenge as auth headers.

use crate::authenticator::Authenticator;
use crate::error::WalletKitError;
use crate::issuers::pop_backend_client::ManageRecoveryBindingRequest;
use crate::issuers::PopBackendClient;
use crate::Environment;
use alloy_primitives::keccak256;
use reqwest::ClientBuilder;
use std::time::Duration;

/// Client for registering and unregistering recovery agents with the `PoP` backend.
///
/// Each instance is bound to a specific [`Environment`] (staging or production),
/// which determines the backend URL used for all requests.
#[derive(Debug, uniffi::Object)]
pub struct RecoveryBindingManager {
    pop_backend_client: PopBackendClient,
}

#[uniffi::export]
impl RecoveryBindingManager {
    /// Creates a new `RecoveryBindingManager` for the specified environment.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP client cannot be built.
    #[uniffi::constructor]
    pub fn new(environment: &Environment) -> Result<Self, WalletKitError> {
        let base_url = match environment {
            Environment::Staging => "https://app.stage.orb.worldcoin.org",
            Environment::Production => "https://app.orb.worldcoin.org",
        }
        .to_string();
        let user_agent = format!("walletkit-core/{}", env!("CARGO_PKG_VERSION"));
        Self::new_base_url(base_url.as_str(), user_agent.as_str())
    }

    /// Creates a new `RecoveryBindingManager` for the specified base URL and user agent.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP client cannot be built.
    #[uniffi::constructor]
    pub fn new_base_url(
        base_url: &str,
        user_agent: &str,
    ) -> Result<Self, WalletKitError> {
        let client = ClientBuilder::new()
            .timeout(Duration::from_secs(60))
            .user_agent(user_agent.to_string())
            .build()
            .map_err(|e| WalletKitError::Generic {
                error: e.to_string(),
            })?;
        let pop_backend_client = PopBackendClient::new(client, base_url.to_string());
        Ok(Self { pop_backend_client })
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl RecoveryBindingManager {
    /// Registers a recovery agent for the given authenticator.
    ///
    /// # Arguments
    ///
    /// * `authenticator` — The authenticator whose signing key authorizes the request.
    /// * `leaf_index` — The authenticator's leaf index in the World ID Merkle tree.
    /// * `sub` — Hex-encoded subject identifier of the recovery agent to register.
    ///
    /// # Errors
    ///
    /// Returns an error if the challenge fetch, signing, or backend request fails,
    /// or if a recovery binding already exists ([`WalletKitError::RecoveryBindingManagerAlreadyExists`]).
    pub async fn register_recovery_binding(
        &self,
        authenticator: &Authenticator,
        leaf_index: u64,
        sub: String,
    ) -> Result<(), WalletKitError> {
        let challenge = self.pop_backend_client.get_challenge().await?;
        let request = ManageRecoveryBindingRequest { sub, leaf_index };
        let security_token = Self::generate_recovery_agent_security_token(
            authenticator,
            &request,
            &challenge,
        )?;

        self.pop_backend_client
            .register_recovery_binding(request, security_token, challenge)
            .await?;
        Ok(())
    }

    /// Removes a previously registered recovery agent.
    ///
    /// # Arguments
    ///
    /// * `authenticator` — The authenticator whose signing key authorizes the request.
    /// * `leaf_index` — The authenticator's leaf index in the World ID Merkle tree.
    /// * `sub` — Hex-encoded subject identifier of the recovery agent to remove.
    ///
    /// # Errors
    ///
    /// Returns an error if the challenge fetch, signing, or backend request fails,
    /// or if the account does not exist ([`WalletKitError::AccountDoesNotExist`]).
    pub async fn unregister_recovery_binding(
        &self,
        authenticator: &Authenticator,
        leaf_index: u64,
        sub: String,
    ) -> Result<(), WalletKitError> {
        let request = ManageRecoveryBindingRequest { sub, leaf_index };
        let challenge = self.pop_backend_client.get_challenge().await?;
        let security_token = Self::generate_recovery_agent_security_token(
            authenticator,
            &request,
            &challenge,
        )?;
        self.pop_backend_client
            .unregister_recovery_binding(request, security_token, challenge)
            .await?;
        Ok(())
    }
}

impl RecoveryBindingManager {
    /// Builds a hex-encoded security token by signing `keccak256(challenge || leaf_index || sub)`
    /// with the authenticator's key.
    fn generate_recovery_agent_security_token(
        authenticator: &Authenticator,
        request: &ManageRecoveryBindingRequest,
        challenge: &str,
    ) -> Result<String, WalletKitError> {
        let message_bytes =
            Self::create_bytes_to_sign(challenge, request.leaf_index, &request.sub)?;
        let commitment = keccak256(&message_bytes);
        let signature: Vec<u8> =
            authenticator.danger_sign_challenge(commitment.as_slice())?;
        Ok(format!("0x{}", hex::encode(signature)))
    }

    /// Assembles the byte payload `challenge || leaf_index || sub` used as the
    /// pre-image for the keccak256 commitment.
    ///
    /// Both `challenge` and `sub` are expected as hex strings (with optional `0x` prefix).
    /// `leaf_index` is encoded as 8 big-endian bytes.
    fn create_bytes_to_sign(
        challenge: &str,
        leaf_index: u64,
        sub: &str,
    ) -> Result<Vec<u8>, WalletKitError> {
        let challenge_bytes =
            hex::decode(challenge.trim_start_matches("0x")).map_err(|e| {
                WalletKitError::Generic {
                    error: e.to_string(),
                }
            })?;

        let leaf_index_bytes = leaf_index.to_be_bytes();

        let sub_bytes = hex::decode(sub.trim_start_matches("0x")).map_err(|e| {
            WalletKitError::Generic {
                error: e.to_string(),
            }
        })?;

        let mut concatenated = Vec::new();
        concatenated.extend_from_slice(&challenge_bytes);
        concatenated.extend_from_slice(&leaf_index_bytes);
        concatenated.extend_from_slice(&sub_bytes);

        Ok(concatenated)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::cache_embedded_groth16_material;
    use crate::storage::tests_utils::{temp_root_path, InMemoryStorageProvider};
    use crate::storage::CredentialStore;
    use mockito::ServerGuard;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_recovery_agent_token_generator_success() {
        let mut pop_api_server = mockito::Server::new_async().await;
        let leaf_index = 42;
        let sub = "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
            .to_string();

        // Mock the challenge endpoint
        let challenge_url_path = "/api/v1/challenge".to_string();
        let challenge =
            "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
                .to_string();
        let challenge_mock = pop_api_server
            .mock("GET", challenge_url_path.as_str())
            .with_status(200)
            .with_body(format!("{{\"challenge\": \"{challenge}\"}}"))
            .create_async()
            .await;

        // Mock the recovery binding registration endpoint
        let url_path = "/api/v1/recovery-binding".to_string();

        let mock = pop_api_server
            .mock("POST", url_path.as_str())
            .match_header(
                "X-Auth-Signature",
                mockito::Matcher::Regex(".*".to_string()),
            )
            .match_header("X-Auth-Challenge", challenge.as_str())
            .match_body(mockito::Matcher::Json(serde_json::json!({
                "sub": sub.as_str(),
                "leafIndex": leaf_index,
            })))
            .with_status(201)
            .with_body("{}")
            .create_async()
            .await;

        let recovery_binding_manager = RecoveryBindingManager::new_base_url(
            pop_api_server.url().as_str(),
            "walletkit-core/test",
        )
        .unwrap();

        let private_key =
            "d1995ace62b15d907bfb351ffe3cac57a8a84089a1b034101d2d7c78da415d58";
        let private_key_bytes = hex::decode(private_key).unwrap();
        let (mock_eth_server, eth_mock) = create_mock_eth_server().await;
        let rpc_url = mock_eth_server.url();
        let authenticator =
            create_test_authenticator(&private_key_bytes, rpc_url).await;

        let result = recovery_binding_manager
            .register_recovery_binding(&authenticator, leaf_index, sub.clone())
            .await;
        assert!(
            result.is_ok(),
            "Expected success, but got error: {result:?}"
        );
        challenge_mock.assert_async().await;

        mock.assert_async().await;
        eth_mock.assert_async().await;
        drop(pop_api_server);
        drop(mock_eth_server);
    }

    #[tokio::test]
    async fn test_recovery_bindings_signature() {
        let leaf_index = 42;
        let sub = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
            .to_string();
        let challenge =
            "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
                .to_string();
        let private_key =
            "d1995ace62b15d907bfb351ffe3cac57a8a84089a1b034101d2d7c78da415d58";
        let private_key_bytes = hex::decode(private_key).unwrap();

        let message_bytes =
            RecoveryBindingManager::create_bytes_to_sign(&challenge, leaf_index, &sub)
                .unwrap();
        log::info!("message_bytes: {:?}", hex::encode(message_bytes.clone()));
        assert_eq!(hex::encode(message_bytes.clone()), "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2000000000000002aabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890");

        let request = ManageRecoveryBindingRequest {
            sub: sub.clone(),
            leaf_index,
        };
        let (mock_eth_server, eth_mock) = create_mock_eth_server().await;
        let rpc_url = mock_eth_server.url();

        let authenticator =
            create_test_authenticator(&private_key_bytes, rpc_url).await;
        let security_token =
            RecoveryBindingManager::generate_recovery_agent_security_token(
                &authenticator,
                &request,
                &challenge,
            )
            .unwrap();
        assert!(
            !security_token.is_empty(),
            "Expected success, but got error: {security_token:?}"
        );
        let expect_signature = "0x72ec312737276c94e3ac32ab1c393a63b9474480d3a9eb434b8bf6927b7222ef7eb1fea0812ff62a7fb144db9631751e505969162a9c590cabb27bf0bd5005581c";
        assert_eq!(security_token, expect_signature);
        eth_mock.assert_async().await;
        drop(mock_eth_server);
    }

    async fn create_test_authenticator(seed: &[u8], rpc_url: String) -> Authenticator {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let store = create_test_credential_store();
        let paths = store.storage_paths().unwrap();
        cache_embedded_groth16_material(&paths).expect("cache groth16 material");

        let authenticator = Authenticator::init_with_defaults(
            seed,
            Some(rpc_url.clone()),
            &Environment::Staging,
            None,
            &paths,
            store.clone(),
        )
        .await
        .unwrap();

        authenticator
    }

    fn create_test_credential_store() -> Arc<CredentialStore> {
        let root = temp_root_path();
        let provider = InMemoryStorageProvider::new(&root);
        Arc::new(
            CredentialStore::from_provider(&provider).expect("create credential store"),
        )
    }

    async fn create_mock_eth_server() -> (ServerGuard, mockito::Mock) {
        let mut mock_eth_server = mockito::Server::new_async().await;
        let mock = mock_eth_server
            .mock("POST", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": "0x0000000000000000000000000000000000000000000000000000000000000001"
                })
                .to_string(),
            )
            .create_async()
            .await;
        (mock_eth_server, mock)
    }
}
