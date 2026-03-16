use alloy_primitives::{address, Address};
use world_id_core::primitives::Config;

use crate::{error::WalletKitError, Environment, Region};

/// The World ID Registry contract address on World Chain Mainnet.
pub static WORLD_ID_REGISTRY: Address =
    address!("0x8556d07D75025f286fe757C7EeEceC40D54FA16D");

/// The TFH (Tools for Humanity) Recovery Agent contract address on the **staging** environment.
///
/// This is the default recovery agent address for World IDs created in the staging
/// environment. See [`tfh_recovery_agent_address`] for a helper that selects the
/// appropriate address by [`Environment`].
pub static TFH_RECOVERY_AGENT_ADDRESS_STAGING: Address =
    address!("0xE2946556E4Bc67E687f202F032b56f5d63c76f83");

/// The TFH (Tools for Humanity) Recovery Agent contract address on the **production** environment.
///
/// This is the default recovery agent address for World IDs created in the production
/// environment. See [`tfh_recovery_agent_address`] for a helper that selects the
/// appropriate address by [`Environment`].
pub static TFH_RECOVERY_AGENT_ADDRESS_PRODUCTION: Address =
    address!("0x1312C524D85717dfAB70a6D25de7b30CC68B4d9d");

/// Returns the TFH Recovery Agent address for the given [`Environment`].
///
/// The recovery agent is a smart contract operated by Tools for Humanity that users
/// can optionally designate when registering a World ID. If a user loses access to all
/// of their authenticators, the recovery agent can sign a recovery transaction on their
/// behalf, restoring access to the same World ID account.
///
/// Designating a recovery agent is optional — pass the returned address as the
/// `recovery_address` argument to [`crate::InitializingAuthenticator::register_with_defaults`]
/// (or the equivalent `register` constructors) to opt in to TFH-assisted recovery.
///
/// # Examples
///
/// ```rust
/// use walletkit_core::{defaults::tfh_recovery_agent_address, Environment};
///
/// let staging = tfh_recovery_agent_address(&Environment::Staging);
/// assert_eq!(staging.to_string(), "0xE2946556E4Bc67E687f202F032b56f5d63c76f83");
///
/// let production = tfh_recovery_agent_address(&Environment::Production);
/// assert_eq!(production.to_string(), "0x1312C524D85717dfAB70a6D25de7b30CC68B4d9d");
/// ```
#[must_use]
pub fn tfh_recovery_agent_address(environment: &Environment) -> Address {
    match environment {
        Environment::Staging => TFH_RECOVERY_AGENT_ADDRESS_STAGING,
        Environment::Production => TFH_RECOVERY_AGENT_ADDRESS_PRODUCTION,
    }
}

const OPRF_NODE_COUNT: usize = 5;

/// Generates the list of OPRF node URLs for a given region and environment.
fn oprf_node_urls(region: Region, environment: &Environment) -> Vec<String> {
    let env_segment = match environment {
        Environment::Staging => ".staging",
        Environment::Production => "",
    };

    (0..OPRF_NODE_COUNT)
        .map(|i| {
            format!("https://node{i}.{region}{env_segment}.world.oprf.taceo.network")
        })
        .collect()
}

fn indexer_url(region: Region, environment: &Environment) -> String {
    let domain = match environment {
        Environment::Staging => "worldcoin.dev",
        Environment::Production => "world.org",
    };
    format!("https://indexer.{region}.id-infra.{domain}")
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
        region: Option<Region>,
    ) -> Result<Self, WalletKitError>
    where
        Self: Sized;
}

impl DefaultConfig for Config {
    fn from_environment(
        environment: &Environment,
        rpc_url: Option<String>,
        region: Option<Region>,
    ) -> Result<Self, WalletKitError> {
        let region = region.unwrap_or_default();

        match environment {
            Environment::Staging => Self::new(
                rpc_url,
                480, // Staging also runs on World Chain Mainnet by default
                WORLD_ID_REGISTRY,
                indexer_url(region, environment),
                "https://gateway.id-infra.worldcoin.dev".to_string(),
                oprf_node_urls(region, environment),
                3,
            )
            .map_err(WalletKitError::from),

            Environment::Production => todo!("There is no production environment yet"),
        }
    }
}
