use alloy_primitives::{address, Address};
use world_id_core::primitives::Config;

use crate::Environment;

pub static ACCOUNT_REGISTRY: Address =
    address!("0xd66aFbf92d684B4404B1ed3e9aDA85353c178dE2");

pub trait DefaultConfig {
    fn from_environment(environment: &Environment, rpc_url: String) -> Self;
}

impl DefaultConfig for Config {
    fn from_environment(environment: &Environment, rpc_url: String) -> Self {
        // TODO: Add all correct values
        match environment {
            Environment::Staging => Self::new(
                // This always needs to be provided. There is no default.
                rpc_url,
                ACCOUNT_REGISTRY,
                "https://world-id-indexer.stage-crypto.worldcoin.org".to_string(),
                "https://world-id-gateway.stage-crypto.worldcoin.org".to_string(),
                vec![],
            ),

            Environment::Production => Self::new(
                // This always needs to be provided. There is no default.
                rpc_url,
                ACCOUNT_REGISTRY,
                "https://world-id-indexer.crypto.worldcoin.org".to_string(),
                "https://world-id-gateway.crypto.worldcoin.org".to_string(),
                vec![],
            ),
        }
    }
}
