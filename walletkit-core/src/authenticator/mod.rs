//! The Authenticator is the main component with which users interact with the World ID Protocol.

use alloy_primitives::Address;
use rand::rngs::OsRng;
use world_id_core::{
    primitives::Config,
    requests::{ProofResponse as CoreProofResponse, ResponseItem},
    types::GatewayRequestState,
    Authenticator as CoreAuthenticator, FieldElement,
    InitializingAuthenticator as CoreInitializingAuthenticator,
};

#[cfg(feature = "storage")]
use crate::storage::CredentialStore;
use crate::{
    defaults::DefaultConfig,
    error::WalletKitError,
    primitives::ParseFromForeignBinding,
    requests::{ProofRequest, ProofResponse},
    Environment, U256Wrapper,
};
#[cfg(feature = "storage")]
use std::sync::Arc;

#[cfg(feature = "storage")]
mod utils;
#[cfg(feature = "storage")]
mod with_storage;

/// The Authenticator is the main component with which users interact with the World ID Protocol.
#[derive(Debug, uniffi::Object)]
pub struct Authenticator {
    inner: CoreAuthenticator,
    #[cfg(feature = "storage")]
    store: Arc<CredentialStore>,
}

#[uniffi::export]
impl Authenticator {
    /// Returns the packed account data for the holder's World ID.
    ///
    /// The packed account data is a 256 bit integer which includes the user's leaf index, their recovery counter,
    /// and their pubkey id/commitment.
    #[must_use]
    pub fn packed_account_data(&self) -> U256Wrapper {
        self.inner.packed_account_data.into()
    }

    /// Returns the leaf index for the holder's World ID.
    ///
    /// This is the index in the Merkle tree where the holder's World ID account is registered. It
    /// should only be used inside the authenticator and never shared.
    #[must_use]
    pub fn leaf_index(&self) -> U256Wrapper {
        self.inner.leaf_index().into()
    }

    /// Returns the Authenticator's `onchain_address`.
    ///
    /// See `world_id_core::Authenticator::onchain_address` for more details.
    #[must_use]
    pub fn onchain_address(&self) -> String {
        self.inner.onchain_address().to_string()
    }

    /// Returns the packed account data for the holder's World ID fetching it from the on-chain registry.
    ///
    /// # Errors
    /// Will error if the provided RPC URL is not valid or if there are RPC call failures.
    pub async fn get_packed_account_data_remote(
        &self,
    ) -> Result<U256Wrapper, WalletKitError> {
        let client = reqwest::Client::new(); // TODO: reuse client
        let packed_account_data = CoreAuthenticator::get_packed_account_data(
            self.inner.onchain_address(),
            self.inner.registry().as_deref(),
            &self.inner.config,
            &client,
        )
        .await?;
        Ok(packed_account_data.into())
    }
}

#[cfg(not(feature = "storage"))]
#[uniffi::export]
impl Authenticator {
    /// Initializes a new Authenticator from a seed and with SDK defaults.
    ///
    /// The user's World ID must already be registered in the `WorldIDRegistry`,
    /// otherwise a [`WalletKitError::AccountDoesNotExist`] error will be returned.
    ///
    /// # Errors
    /// See `CoreAuthenticator::init` for potential errors.
    #[uniffi::constructor]
    pub async fn init_with_defaults(
        seed: &[u8],
        rpc_url: Option<String>,
        environment: &Environment,
    ) -> Result<Self, WalletKitError> {
        let config = Config::from_environment(environment, rpc_url)?;
        let authenticator = CoreAuthenticator::init(seed, config).await?;
        Ok(Self {
            inner: authenticator,
        })
    }

    /// Initializes a new Authenticator from a seed and config.
    ///
    /// The user's World ID must already be registered in the `WorldIDRegistry`,
    /// otherwise a [`WalletKitError::AccountDoesNotExist`] error will be returned.
    ///
    /// # Errors
    /// Will error if the provided seed is not valid or if the config is not valid.
    #[uniffi::constructor]
    pub async fn init(seed: &[u8], config: &str) -> Result<Self, WalletKitError> {
        let config =
            Config::from_json(config).map_err(|_| WalletKitError::InvalidInput {
                attribute: "config".to_string(),
                reason: "Invalid config".to_string(),
            })?;
        let authenticator = CoreAuthenticator::init(seed, config).await?;
        Ok(Self {
            inner: authenticator,
        })
    }
}

#[cfg(feature = "storage")]
#[uniffi::export]
impl Authenticator {
    /// Initializes a new Authenticator from a seed and with SDK defaults.
    ///
    /// The user's World ID must already be registered in the `WorldIDRegistry`,
    /// otherwise a [`WalletKitError::AccountDoesNotExist`] error will be returned.
    ///
    /// # Errors
    /// See `CoreAuthenticator::init` for potential errors.
    #[uniffi::constructor]
    pub async fn init_with_defaults(
        seed: &[u8],
        rpc_url: Option<String>,
        environment: &Environment,
        store: Arc<CredentialStore>,
    ) -> Result<Self, WalletKitError> {
        let config = Config::from_environment(environment, rpc_url)?;
        let authenticator = CoreAuthenticator::init(seed, config).await?;
        Ok(Self {
            inner: authenticator,
            store,
        })
    }

    /// Initializes a new Authenticator from a seed and config.
    ///
    /// The user's World ID must already be registered in the `WorldIDRegistry`,
    /// otherwise a [`WalletKitError::AccountDoesNotExist`] error will be returned.
    ///
    /// # Errors
    /// Will error if the provided seed is not valid or if the config is not valid.
    #[uniffi::constructor]
    pub async fn init(
        seed: &[u8],
        config: &str,
        store: Arc<CredentialStore>,
    ) -> Result<Self, WalletKitError> {
        let config =
            Config::from_json(config).map_err(|_| WalletKitError::InvalidInput {
                attribute: "config".to_string(),
                reason: "Invalid config".to_string(),
            })?;
        let authenticator = CoreAuthenticator::init(seed, config).await?;
        Ok(Self {
            inner: authenticator,
            store,
        })
    }

    /// Generates a proof for the given proof request.
    ///
    /// # Errors
    /// Returns an error if proof generation fails.
    pub async fn generate_proof(
        &self,
        proof_request: &ProofRequest,
        now: Option<u64>,
    ) -> Result<ProofResponse, WalletKitError> {
        let now = if let Some(n) = now {
            n
        } else {
            let start = std::time::SystemTime::now();
            start
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|e| WalletKitError::Generic {
                    error: format!("Critical. Unable to determine SystemTime: {e}"),
                })?
                .as_secs()
        };

        // First check if the request can be fulfilled and which credentials should be used
        let credential_list = self.store.list_credentials(None, now)?;
        let credential_list = credential_list
            .into_iter()
            .map(|cred| cred.issuer_schema_id.clone().to_string())
            .collect::<std::collections::HashSet<_>>();
        let credentials_to_prove = proof_request
            .0
            .credentials_to_prove(&credential_list)
            .ok_or(WalletKitError::UnfulfillableRequest)?;

        // Next, generate the nullifier and check the replay guard
        let nullifier = self.inner.generate_nullifier(&proof_request.0).await?;

        if self
            .store
            .is_nullifier_replay(nullifier.verifiable_oprf_output.output.into(), now)?
        {
            return Err(WalletKitError::NullifierReplay);
        }

        let mut responses: Vec<ResponseItem> = vec![];

        for request_item in credentials_to_prove {
            let (credential, blinding_factor) = self
                .store
                .get_credential(request_item.issuer_schema_id, now)?
                .ok_or(WalletKitError::CredentialNotIssued)?;

            let session_id_r_seed = FieldElement::random(&mut OsRng); // TODO: Properly fetch session seed from cache

            let response_item = self.inner.generate_single_proof(
                nullifier.clone(),
                request_item,
                &credential,
                blinding_factor,
                session_id_r_seed,
                proof_request.0.session_id,
                proof_request.0.created_at,
            )?;
            responses.push(response_item);
        }

        let response = CoreProofResponse {
            id: proof_request.0.id.clone(),
            version: world_id_core::requests::RequestVersion::V1,
            responses,
            error: None,
            session_id: None, // TODO: This needs to be computed to be shareable
        };

        self.store
            .replay_guard_set(nullifier.verifiable_oprf_output.output.into(), now)?;
        Ok(response.into())
    }
}

/// Registration status for a World ID being created through the gateway.
#[derive(Debug, Clone, uniffi::Enum)]
pub enum RegistrationStatus {
    /// Request queued but not yet batched.
    Queued,
    /// Request currently being batched.
    Batching,
    /// Request submitted on-chain.
    Submitted,
    /// Request finalized on-chain. The World ID is now registered.
    Finalized,
    /// Request failed during processing.
    Failed {
        /// Error message returned by the gateway.
        error: String,
        /// Specific error code, if available.
        error_code: Option<String>,
    },
}

impl From<GatewayRequestState> for RegistrationStatus {
    fn from(state: GatewayRequestState) -> Self {
        match state {
            GatewayRequestState::Queued => Self::Queued,
            GatewayRequestState::Batching => Self::Batching,
            GatewayRequestState::Submitted { .. } => Self::Submitted,
            GatewayRequestState::Finalized { .. } => Self::Finalized,
            GatewayRequestState::Failed { error, error_code } => Self::Failed {
                error,
                error_code: error_code.map(|c| c.to_string()),
            },
        }
    }
}

/// Represents an Authenticator in the process of being initialized.
///
/// The account is not yet registered in the `WorldIDRegistry` contract.
/// Use this for non-blocking registration flows where you want to poll the status yourself.
#[derive(uniffi::Object)]
pub struct InitializingAuthenticator(CoreInitializingAuthenticator);

#[uniffi::export(async_runtime = "tokio")]
impl InitializingAuthenticator {
    /// Registers a new World ID with SDK defaults.
    ///
    /// This returns immediately and does not wait for registration to complete.
    /// The returned `InitializingAuthenticator` can be used to poll the registration status.
    ///
    /// # Errors
    /// See `CoreAuthenticator::register` for potential errors.
    #[uniffi::constructor]
    pub async fn register_with_defaults(
        seed: &[u8],
        rpc_url: Option<String>,
        environment: &Environment,
        recovery_address: Option<String>,
    ) -> Result<Self, WalletKitError> {
        let recovery_address =
            Address::parse_from_ffi_optional(recovery_address, "recovery_address")?;

        let config = Config::from_environment(environment, rpc_url)?;

        let initializing_authenticator =
            CoreAuthenticator::register(seed, config, recovery_address).await?;

        Ok(Self(initializing_authenticator))
    }

    /// Registers a new World ID.
    ///
    /// This returns immediately and does not wait for registration to complete.
    /// The returned `InitializingAuthenticator` can be used to poll the registration status.
    ///
    /// # Errors
    /// See `CoreAuthenticator::register` for potential errors.
    #[uniffi::constructor]
    pub async fn register(
        seed: &[u8],
        config: &str,
        recovery_address: Option<String>,
    ) -> Result<Self, WalletKitError> {
        let recovery_address =
            Address::parse_from_ffi_optional(recovery_address, "recovery_address")?;

        let config =
            Config::from_json(config).map_err(|_| WalletKitError::InvalidInput {
                attribute: "config".to_string(),
                reason: "Invalid config".to_string(),
            })?;

        let initializing_authenticator =
            CoreAuthenticator::register(seed, config, recovery_address).await?;

        Ok(Self(initializing_authenticator))
    }

    /// Polls the registration status from the gateway.
    ///
    /// # Errors
    /// Will error if the network request fails or the gateway returns an error.
    pub async fn poll_status(&self) -> Result<RegistrationStatus, WalletKitError> {
        let status = self.0.poll_status().await?;
        Ok(status.into())
    }
}

#[cfg(all(test, feature = "storage"))]
mod tests {
    use super::*;
    use crate::storage::tests_utils::{
        cleanup_test_storage, temp_root_path, InMemoryStorageProvider,
    };
    use alloy::primitives::address;

    #[tokio::test]
    async fn test_init_with_config_and_storage() {
        // Install default crypto provider for rustls
        let _ = rustls::crypto::ring::default_provider().install_default();

        let mut mock_server = mockito::Server::new_async().await;

        // Mock eth_call to return account data indicating account exists
        mock_server
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

        let seed = [2u8; 32];
        let config = Config::new(
            Some(mock_server.url()),
            480,
            address!("0x969947cFED008bFb5e3F32a25A1A2CDdf64d46fe"),
            "https://world-id-indexer.stage-crypto.worldcoin.org".to_string(),
            "https://world-id-gateway.stage-crypto.worldcoin.org".to_string(),
            vec![],
            2,
        )
        .unwrap();
        let config = serde_json::to_string(&config).unwrap();

        let root = temp_root_path();
        let provider = InMemoryStorageProvider::new(&root);
        let store = CredentialStore::from_provider(&provider).expect("store");
        store.init(42, 100).expect("init storage");

        Authenticator::init(&seed, &config, Arc::new(store))
            .await
            .unwrap();
        drop(mock_server);
        cleanup_test_storage(&root);
    }
}
