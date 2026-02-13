use alloy_primitives::{address, Address};
use world_id_core::primitives::Config;

use crate::{error::WalletKitError, Environment};

/// The World ID Registry contract address on World Chain Mainnet.
pub static WORLD_ID_REGISTRY: Address =
    address!("0x7215Be2f5521985e2169f376B36a57473eaaAe6f");

/// Build a [`Config`] from well-known defaults for a given [`Environment`].
pub trait DefaultConfig {
    /// Returns a config populated with the default URLs and addresses for the given environment.
    ///
    /// # Errors
    ///
    /// Returns [`WalletKitError`] if the configuration cannot be constructed (e.g. invalid RPC URL).
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
                // TODO: Add a mechanism for selecting nodes by region
                // https://github.com/worldcoin/walletkit/issues/194
                // NOTE: That node0.us.. and node0.eu.. are the same node, so we can't just samle
                // from the full list
                vec![
                    // "https://node0.us.staging.world.oprf.taceo.network".to_string(),
                    // "https://node1.us.staging.world.oprf.taceo.network".to_string(),
                    // "https://node2.us.staging.world.oprf.taceo.network".to_string(),
                    // "https://node3.us.staging.world.oprf.taceo.network".to_string(),
                    // "https://node4.us.staging.world.oprf.taceo.network".to_string(),
                    "https://node0.eu.staging.world.oprf.taceo.network".to_string(),
                    "https://node1.eu.staging.world.oprf.taceo.network".to_string(),
                    "https://node2.eu.staging.world.oprf.taceo.network".to_string(),
                    "https://node3.eu.staging.world.oprf.taceo.network".to_string(),
                    "https://node4.eu.staging.world.oprf.taceo.network".to_string(),
                    // "https://node0.ap.staging.world.oprf.taceo.network".to_string(),
                    // "https://node1.ap.staging.world.oprf.taceo.network".to_string(),
                    // "https://node2.ap.staging.world.oprf.taceo.network".to_string(),
                    // "https://node3.ap.staging.world.oprf.taceo.network".to_string(),
                    // "https://node4.ap.staging.world.oprf.taceo.network".to_string(),
                ],
                3,
            )
            .map_err(WalletKitError::from),

            Environment::Production => todo!("There is no production environment yet"),
        }
    }
}
