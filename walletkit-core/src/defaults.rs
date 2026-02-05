use alloy_primitives::{address, Address};
use world_id_core::primitives::Config;

use crate::{error::WalletKitError, Environment};

pub static WORLD_ID_REGISTRY: Address =
    address!("0x969947cFED008bFb5e3F32a25A1A2CDdf64d46fe");

pub trait DefaultConfig {
    fn from_environment(
        environment: &Environment,
        rpc_url: Option<String>,
    ) -> Result<Self, WalletKitError>
    where
        Self: Sized;
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
                WORLD_ID_REGISTRY,
                "https://world-id-indexer.stage-crypto.worldcoin.org".to_string(),
                "https://world-id-gateway.stage-crypto.worldcoin.org".to_string(),
                vec![],
                2,
            )
            .map_err(WalletKitError::from),

            Environment::Production => todo!("There is no production environment yet"),
        }
    }
}
