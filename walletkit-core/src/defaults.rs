use alloy_primitives::{address, Address};
use world_id_core::primitives::Config;

use crate::{error::WalletKitError, Environment, OprfRegion};

/// The World ID Registry contract address on World Chain Mainnet.
pub static WORLD_ID_REGISTRY: Address =
    address!("0x7215Be2f5521985e2169f376B36a57473eaaAe6f");

const OPRF_NODE_COUNT: usize = 5;

/// Generates the list of OPRF node URLs for a given region and environment.
fn oprf_node_urls(region: OprfRegion, environment: &Environment) -> Vec<String> {
    let region_code = match region {
        OprfRegion::Us => "us",
        OprfRegion::Eu => "eu",
        OprfRegion::Ap => "ap",
    };

    let env_segment = match environment {
        Environment::Staging => "staging",
        Environment::Production => todo!("Production OPRF URLs not yet defined"),
    };

    (0..OPRF_NODE_COUNT)
        .map(|i| {
            format!(
                "https://node{i}.{region_code}.{env_segment}.world.oprf.taceo.network"
            )
        })
        .collect()
}

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
        oprf_region: Option<OprfRegion>,
    ) -> Result<Self, WalletKitError>
    where
        Self: Sized;
}

impl DefaultConfig for Config {
    fn from_environment(
        environment: &Environment,
        rpc_url: Option<String>,
        oprf_region: Option<OprfRegion>,
    ) -> Result<Self, WalletKitError> {
        let region = oprf_region.unwrap_or_default();

        match environment {
            Environment::Staging => Self::new(
                rpc_url,
                480, // Staging also runs on World Chain Mainnet by default
                WORLD_ID_REGISTRY,
                "https://world-id-indexer.stage-crypto.worldcoin.org".to_string(),
                "https://world-id-gateway.stage-crypto.worldcoin.org".to_string(),
                oprf_node_urls(region, environment),
                3,
            )
            .map_err(WalletKitError::from),

            Environment::Production => todo!("There is no production environment yet"),
        }
    }
}
