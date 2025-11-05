//! The Authenticator is the main component with which users interact with the World ID Protocol.

use alloy_primitives::Address;
use world_id_core::{primitives::Config, Authenticator as CoreAuthenticator};

use crate::{
    defaults::DefaultConfig, error::WalletKitError,
    primitives::ParseFromForeignBinding, Environment, U256Wrapper,
};

/// The Authenticator is the main component with which users interact with the World ID Protocol.
#[derive(Debug, uniffi::Object)]
pub struct Authenticator(CoreAuthenticator);

#[uniffi::export]
impl Authenticator {
    /// Initializes a new Authenticator from a seed and with SDK defaults.
    ///
    /// # Errors
    /// See `CoreAuthenticator::init` for potential errors.
    #[uniffi::constructor]
    pub async fn init_with_defaults(
        seed: &[u8],
        rpc_url: String,
        environment: &Environment,
    ) -> Result<Self, WalletKitError> {
        let config = Config::from_environment(environment, rpc_url);
        let authenticator = CoreAuthenticator::init(seed, config).await?;
        Ok(Self(authenticator))
    }

    /// Initializes a new Authenticator from a seed and config.
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

    /// Initializes a new Authenticator from a seed and with SDK defaults.
    ///
    /// It will create a new account if it doesn't exist. See `CoreAuthenticator::init_or_create_blocking` for more details.
    ///
    /// # Errors
    /// See `CoreAuthenticator::init_or_create_blocking` for potential errors.
    #[uniffi::constructor]
    pub async fn init_or_create_blocking_with_defaults(
        seed: &[u8],
        rpc_url: String,
        environment: &Environment,
        recovery_address: Option<String>,
    ) -> Result<Self, WalletKitError> {
        let recovery_address =
            Address::parse_from_ffi_optional(recovery_address, "recovery_address")?;

        let config = Config::from_environment(environment, rpc_url);

        let authenticator =
            CoreAuthenticator::init_or_create_blocking(seed, config, recovery_address)
                .await?;

        Ok(Self(authenticator))
    }

    /// Initializes a new Authenticator from a seed and config and creates a new account with the specified recovery address.
    ///
    /// It will create a new account if it doesn't exist. See `CoreAuthenticator::init_or_create_blocking` for more details.
    ///
    /// # Errors
    /// See `CoreAuthenticator::init_or_create_blocking` for potential errors.
    #[uniffi::constructor]
    pub async fn init_or_create_blocking(
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
            CoreAuthenticator::init_or_create_blocking(seed, config, recovery_address)
                .await?;

        Ok(Self(authenticator))
    }

    /// Returns the full account index for the holder's World ID.
    ///
    /// The packed account index is a 256 bit integer which includes the user's account index, their recovery counter,
    /// and their pubkey id/commitment.
    ///
    /// # Errors
    /// Will error if the provided RPC URL is not valid or if there are RPC call failures.
    #[must_use]
    pub fn account_id(&self) -> U256Wrapper {
        self.0.account_id().into()
    }

    /// Returns the Authenticator's `onchain_address`.
    ///
    /// See `world_id_core::Authenticator::onchain_address` for more details.
    #[must_use]
    pub fn onchain_address(&self) -> String {
        self.0.onchain_address().to_string()
    }
}

#[cfg(test)]
mod tests {
    use alloy::primitives::address;

    use super::*;

    #[tokio::test]
    async fn test_init_with_config() {
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
            mock_server.url(),
            address!("0xd66aFbf92d684B4404B1ed3e9aDA85353c178dE2"),
            "https://world-id-indexer.stage-crypto.worldcoin.org".to_string(),
            "https://world-id-gateway.stage-crypto.worldcoin.org".to_string(),
            vec![],
        );
        let config = serde_json::to_string(&config).unwrap();
        Authenticator::init(&seed, &config).await.unwrap();
        drop(mock_server);
    }
}
