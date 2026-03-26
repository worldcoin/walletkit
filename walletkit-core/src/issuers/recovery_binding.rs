//! Bindings for managing recovery agents via the Proof-of-Personhood (PoP) backend.
//!
//! A recovery agent is an entity authorized to initiate account recovery on behalf of
//! a user. This module provides [`RecoveryBindingManager`], which handles the authenticated
//! registration and removal of recovery agents through a challenge-response protocol
//! secured by the authenticator's signing key.
//!
//! ## Protocol
//!
//! 1. Fetch a one-time challenge from the PoP backend.
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

/// Client for registering and unregistering recovery agents with the PoP backend.
///
/// Each instance is bound to a specific [`Environment`] (staging or production),
/// which determines the backend URL used for all requests.
#[derive(Debug, uniffi::Object)]
pub struct RecoveryBindingManager {
    pop_backend_client: PopBackendClient,
}

#[uniffi::export]
impl RecoveryBindingManager {
    /// Creates a new RecoveryBindingManager for the specified environment.
    #[uniffi::constructor]
    #[must_use]
    pub fn new(environment: &Environment) -> Result<Self, WalletKitError> {
        let base_url = match environment {
            Environment::Staging => "https://app.stage.orb.worldcoin.org",
            Environment::Production => "https://app.orb.worldcoin.org",
        }
        .to_string();
        let user_agent = format!("walletkit-core/{}", env!("CARGO_PKG_VERSION"));
        let client = ClientBuilder::new()
            .timeout(Duration::from_secs(60))
            .user_agent(user_agent)
            .build()
            .map_err(|e| WalletKitError::Generic {
                error: e.to_string(),
            })?;
        let pop_backend_client = PopBackendClient::new(client, base_url);
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
        let security_token = self
            .generate_recovery_agent_security_token(
                authenticator,
                &request,
                challenge.clone(),
            )
            .await?;

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
        let security_token = self
            .generate_recovery_agent_security_token(
                authenticator,
                &request,
                challenge.clone(),
            )
            .await?;
        self.pop_backend_client
            .unregister_recovery_binding(request, security_token, challenge)
            .await?;
        Ok(())
    }

    /// Builds a hex-encoded security token by signing `keccak256(challenge || leaf_index || sub)`
    /// with the authenticator's key.
    async fn generate_recovery_agent_security_token(
        &self,
        authenticator: &Authenticator,
        request: &ManageRecoveryBindingRequest,
        challenge: String,
    ) -> Result<String, WalletKitError> {
        let message_bytes = Self::create_bytes_to_sign(
            challenge,
            request.leaf_index,
            request.sub.clone(),
        )?;
        let commitment = keccak256(&message_bytes);
        let signature: Vec<u8> =
            authenticator.danger_sign_challenge(&commitment.as_slice())?;
        Ok(hex::encode(signature))
    }
}

impl RecoveryBindingManager {
    /// Assembles the byte payload `challenge || leaf_index || sub` used as the
    /// pre-image for the keccak256 commitment.
    ///
    /// Both `challenge` and `sub` are expected as hex strings (with optional `0x` prefix).
    /// `leaf_index` is encoded as 8 big-endian bytes.
    fn create_bytes_to_sign(
        challenge: String,
        leaf_index: u64,
        sub: String,
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
