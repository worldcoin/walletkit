//! The Authenticator is the main component with which users interact with the World ID Protocol.

use alloy_primitives::Address;
use world_id_core::{
    primitives::Config, types::GatewayRequestState, Authenticator as CoreAuthenticator,
    InitializingAuthenticator as CoreInitializingAuthenticator,
};

use crate::{
    defaults::DefaultConfig, error::WalletKitError,
    primitives::ParseFromForeignBinding, Environment, U256Wrapper,
};

mod storage;
mod utils;

/// The Authenticator is the main component with which users interact with the World ID Protocol.
#[derive(Debug, uniffi::Object)]
pub struct Authenticator(CoreAuthenticator);

#[uniffi::export(async_runtime = "tokio")]
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
        Ok(Self(authenticator))
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
        Ok(Self(authenticator))
    }

    /// Initializes (if the World ID already exists) or registers a new World ID with SDK defaults.
    ///
    /// This method will block until the registration is in a final state (success or terminal error).
    /// See `CoreAuthenticator::init_or_register` for more details.
    ///
    /// # Errors
    /// See `CoreAuthenticator::init_or_register` for potential errors.
    #[uniffi::constructor]
    pub async fn init_or_register_with_defaults(
        seed: &[u8],
        rpc_url: Option<String>,
        environment: &Environment,
        recovery_address: Option<String>,
    ) -> Result<Self, WalletKitError> {
        let recovery_address =
            Address::parse_from_ffi_optional(recovery_address, "recovery_address")?;

        let config = Config::from_environment(environment, rpc_url)?;

        let authenticator =
            CoreAuthenticator::init_or_register(seed, config, recovery_address).await?;

        Ok(Self(authenticator))
    }

    /// Initializes (if the World ID already exists) or registers a new World ID.
    ///
    /// This method will block until the registration is in a final state (success or terminal error).
    /// See `CoreAuthenticator::init_or_register` for more details.
    ///
    /// # Errors
    /// See `CoreAuthenticator::init_or_register` for potential errors.
    #[uniffi::constructor]
    pub async fn init_or_register(
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

        let authenticator =
            CoreAuthenticator::init_or_register(seed, config, recovery_address).await?;

        Ok(Self(authenticator))
    }

    /// Returns the packed account data for the holder's World ID.
    ///
    /// The packed account data is a 256 bit integer which includes the user's leaf index, their recovery counter,
    /// and their pubkey id/commitment.
    #[must_use]
    pub fn packed_account_data(&self) -> U256Wrapper {
        self.0.packed_account_data.into()
    }

    /// Returns the leaf index for the holder's World ID.
    ///
    /// This is the index in the Merkle tree where the holder's World ID account is registered. It
    /// should only be used inside the authenticator and never shared.
    #[must_use]
    pub fn leaf_index(&self) -> U256Wrapper {
        self.0.leaf_index().into()
    }

    /// Returns the Authenticator's `onchain_address`.
    ///
    /// See `world_id_core::Authenticator::onchain_address` for more details.
    #[must_use]
    pub fn onchain_address(&self) -> String {
        self.0.onchain_address().to_string()
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
            self.0.onchain_address(),
            self.0.registry().as_deref(),
            &self.0.config,
            &client,
        )
        .await?;
        Ok(packed_account_data.into())
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

#[cfg(test)]
mod tests {
    use alloy::primitives::address;

    use super::*;

    #[tokio::test]
    async fn test_init_with_config() {
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
        Authenticator::init(&seed, &config).await.unwrap();
        drop(mock_server);
    }
}
