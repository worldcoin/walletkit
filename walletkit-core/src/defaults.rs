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
                vec![
                    "https://node0.us.staging.world.oprf.taceo.network".to_string(),
                    "https://node1.us.staging.world.oprf.taceo.network".to_string(),
                    "https://node2.us.staging.world.oprf.taceo.network".to_string(),
                    "https://node3.us.staging.world.oprf.taceo.network".to_string(),
                    "https://node4.us.staging.world.oprf.taceo.network".to_string(),
                    "https://node0.eu.staging.world.oprf.taceo.network".to_string(),
                    "https://node1.eu.staging.world.oprf.taceo.network".to_string(),
                    "https://node2.eu.staging.world.oprf.taceo.network".to_string(),
                    "https://node3.eu.staging.world.oprf.taceo.network".to_string(),
                    "https://node4.eu.staging.world.oprf.taceo.network".to_string(),
                    "https://node0.ap.staging.world.oprf.taceo.network".to_string(),
                    "https://node1.ap.staging.world.oprf.taceo.network".to_string(),
                    "https://node2.ap.staging.world.oprf.taceo.network".to_string(),
                    "https://node3.ap.staging.world.oprf.taceo.network".to_string(),
                    "https://node4.ap.staging.world.oprf.taceo.network".to_string(),
                ],
                2,
            )
            .map_err(WalletKitError::from),

            Environment::Production => todo!("There is no production environment yet"),
        }
    }
}
