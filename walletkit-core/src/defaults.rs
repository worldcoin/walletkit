use alloy_primitives::{address, Address};
use world_id_core::primitives::{Config, PrimitiveError};

use crate::{error::WalletKitError, Environment};

pub static ACCOUNT_REGISTRY: Address =
    address!("0xd66aFbf92d684B4404B1ed3e9aDA85353c178dE2");

pub trait DefaultConfig {
    fn from_environment(
        environment: &Environment,
        rpc_url: Option<String>,
    ) -> Result<Self, WalletKitError>
    where
        Self: Sized;
}

fn map_config_error(e: PrimitiveError) -> WalletKitError {
    if let PrimitiveError::InvalidInput { attribute, reason } = e {
        return WalletKitError::InvalidInput { attribute, reason };
    }
    WalletKitError::Generic {
        error: format!("Config initialization error: {e}"),
    }
}

impl DefaultConfig for Config {
    fn from_environment(
        environment: &Environment,
        rpc_url: Option<String>,
    ) -> Result<Self, WalletKitError> {
        // TODO: Add all correct values
        match environment {
            Environment::Staging => Self::new(
                rpc_url,
                480, // Staging also runs on World Chain Mainnet by default
                ACCOUNT_REGISTRY,
                "https://world-id-indexer.stage-crypto.worldcoin.org".to_string(),
                "https://world-id-gateway.stage-crypto.worldcoin.org".to_string(),
                vec![],
                2,
            )
            .map_err(map_config_error),

            Environment::Production => Self::new(
                rpc_url,
                480,
                ACCOUNT_REGISTRY,
                "https://world-id-indexer.crypto.worldcoin.org".to_string(),
                "https://world-id-gateway.crypto.worldcoin.org".to_string(),
                vec![],
                2,
            )
            .map_err(map_config_error),
        }
    }
}
