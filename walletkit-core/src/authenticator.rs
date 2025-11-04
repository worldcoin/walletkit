//! The Authenticator is the main component with which users interact with the World ID Protocol.

use alloy_primitives::Address;
use tokio::sync::Mutex;
use world_id_core::{primitives::Config, Authenticator as CoreAuthenticator};

use crate::{defaults::DefaultConfig, error::WalletKitError, Environment, U256Wrapper};

/// The Authenticator is the main component with which users interact with the World ID Protocol.
#[derive(Debug, uniffi::Object)]
pub struct Authenticator(Mutex<CoreAuthenticator>);

#[uniffi::export(async_runtime = "tokio")]
impl Authenticator {
    #[uniffi::constructor]
    /// Initializes a new Authenticator from a seed and with SDK defaults.
    ///
    /// # Errors
    /// Will error if the provided seed is not valid.
    pub fn from_seed_with_defaults(
        seed: &[u8],
        rpc_url: String,
        environment: &Environment,
    ) -> Result<Self, WalletKitError> {
        let config = Config::from_environment(environment, rpc_url);
        let authenticator = CoreAuthenticator::new(seed, config)
            .map_err(|_| WalletKitError::InvalidInput)?;
        Ok(Self(Mutex::new(authenticator)))
    }

    #[uniffi::constructor]
    /// Initializes a new Authenticator from a seed and config.
    ///
    /// # Errors
    /// Will error if the provided seed is not valid.
    pub fn from_seed(seed: &[u8], config: &str) -> Result<Self, WalletKitError> {
        let config =
            Config::from_json(config).map_err(|_| WalletKitError::InvalidInput)?;
        let authenticator = CoreAuthenticator::new(seed, config)
            .map_err(|_| WalletKitError::InvalidInput)?;
        Ok(Self(Mutex::new(authenticator)))
    }

    /// Checks if the World ID Account has already been registered in the `AccountRegistry`.
    ///
    /// # Errors
    /// Will error if the account information cannot be retrieved.
    pub async fn is_registered(&self) -> Result<bool, WalletKitError> {
        if let Err(e) = self.0.lock().await.account_index().await {
            if let Some(e) = e.downcast_ref::<world_id_core::AuthenticatorError>() {
                if e == &world_id_core::AuthenticatorError::AccountDoesNotExist {
                    return Ok(false);
                }
            }
            return Err(WalletKitError::AuthenticatorError {
                error: (e.to_string()),
            });
        }
        Ok(true)
    }

    /// Creates a new account with the specified recovery address.
    ///
    /// # Errors
    /// Will error if the recovery address is invalid or if the account creation fails.
    pub async fn create_account(
        &self,
        recovery_address: Option<String>,
    ) -> Result<(), WalletKitError> {
        let recovery_address = recovery_address
            .map(|address| {
                address
                    .parse::<Address>()
                    .map_err(|_| WalletKitError::InvalidInput)
            })
            .transpose()?;

        self.0
            .lock()
            .await
            .create_account(recovery_address)
            .await
            .map_err(|e| {
                let err = e.downcast_ref::<world_id_core::AuthenticatorError>();
                err.map_or_else(
                    || WalletKitError::AuthenticatorError {
                        error: (e.to_string()),
                    },
                    WalletKitError::from,
                )
            })?;

        Ok(())
    }

    /// Returns the full account index for the holder's World ID.
    ///
    /// The packed account index is a 256 bit integer which includes the user's account index, their recovery counter,
    /// and their pubkey id/commitment.
    ///
    /// # Errors
    /// Will error if the provided RPC URL is not valid or if there are RPC call failures.
    pub async fn account_id(&self) -> Result<U256Wrapper, WalletKitError> {
        let index = self
            .0
            .lock()
            .await
            .account_index()
            .await
            .map_err(|e| {
                let err = e.downcast_ref::<world_id_core::AuthenticatorError>();
                err.map_or_else(
                    || WalletKitError::AuthenticatorError {
                        error: (e.to_string()),
                    },
                    WalletKitError::from,
                )
            })?
            .into();
        Ok(index)
    }

    /// Returns the Authenticator `onchain_address`.
    ///
    /// See `world_id_core::Authenticator::onchain_address` for more details.
    #[must_use]
    pub async fn onchain_address(&self) -> String {
        self.0.lock().await.onchain_address().to_string()
    }
}

#[cfg(test)]
mod tests {
    use alloy::primitives::address;

    use super::*;

    #[tokio::test]
    async fn test_from_seed() {
        let seed = [2u8; 32];
        let config = Config::new(
            "ws://localhost:8545".to_string(),
            address!("0xd66aFbf92d684B4404B1ed3e9aDA85353c178dE2"),
            "https://world-id-indexer.stage-crypto.worldcoin.org".to_string(),
            "https://world-id-gateway.stage-crypto.worldcoin.org".to_string(),
            vec![],
        );
        let config = serde_json::to_string(&config).unwrap();
        Authenticator::from_seed(&seed, &config).unwrap();
    }
}
