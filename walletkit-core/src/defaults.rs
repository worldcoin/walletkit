use alloy_primitives::{address, Address};
use world_id_core::{primitives::Config, AuthenticatorConfig, OhttpClientConfig};

use crate::{error::WalletKitError, Environment, Region};

/// The World ID Registry contract address on World Chain Mainnet.
pub static WORLD_ID_REGISTRY: Address =
    address!("0x0000000000aE079eB8a274cD51c0f44a9E4d67d4");

/// The **Staging** World ID Registry contract address also on World Chain Mainnet.
pub static STAGING_WORLD_ID_REGISTRY: Address =
    address!("0x8556d07D75025f286fe757C7EeEceC40D54FA16D");

/// The `PoH` Recovery Agent contract address on the staging environment.
pub static POH_RECOVERY_AGENT_ADDRESS_STAGING: Address =
    address!("0x8df366ed8ef894f0d1d25dc21b7e36e2d97a7140");

/// The `PoH` Recovery Agent contract address on the production environment.
pub static POH_RECOVERY_AGENT_ADDRESS_PRODUCTION: Address =
    address!("0x00000000CBBA8Cb46C8CD414B62213F1B334fC59");

pub(crate) fn poh_recovery_agent_address(environment: &Environment) -> Address {
    match environment {
        Environment::Staging => POH_RECOVERY_AGENT_ADDRESS_STAGING,
        Environment::Production => POH_RECOVERY_AGENT_ADDRESS_PRODUCTION,
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

fn ohttp_relay_url(region: Region, environment: &Environment) -> String {
    let path = match environment {
        Environment::Staging => format!("{region}-world-id-stage"),
        Environment::Production => format!("{region}-world-id"),
    };
    let host = match environment {
        Environment::Staging => "staging.privacy-relay.cloudflare.com",
        Environment::Production => "privacy-relay.cloudflare.com",
    };
    format!("https://{host}/{path}")
}

// Base64-encoded `application/ohttp-keys` payloads fetched from /ohttp-keys endpoints.
// Each region has an independent HPKE key derived from its own seed secret.
// To refresh, run the `refresh-ohttp-keys` GitHub Action workflow.
const OHTTP_KEY_CONFIG_STAGING_US: &str = include_str!("ohttp_keys/staging_us.b64");
const OHTTP_KEY_CONFIG_STAGING_EU: &str = include_str!("ohttp_keys/staging_eu.b64");
const OHTTP_KEY_CONFIG_STAGING_AP: &str = include_str!("ohttp_keys/staging_ap.b64");
const OHTTP_KEY_CONFIG_PRODUCTION_US: &str = include_str!("ohttp_keys/production_us.b64");
const OHTTP_KEY_CONFIG_PRODUCTION_EU: &str = include_str!("ohttp_keys/production_eu.b64");
const OHTTP_KEY_CONFIG_PRODUCTION_AP: &str = include_str!("ohttp_keys/production_ap.b64");

const fn ohttp_key_config(region: Region, environment: &Environment) -> &'static str {
    match (environment, region) {
        (Environment::Staging, Region::Us) => OHTTP_KEY_CONFIG_STAGING_US,
        (Environment::Staging, Region::Eu) => OHTTP_KEY_CONFIG_STAGING_EU,
        (Environment::Staging, Region::Ap) => OHTTP_KEY_CONFIG_STAGING_AP,
        (Environment::Production, Region::Us) => OHTTP_KEY_CONFIG_PRODUCTION_US,
        (Environment::Production, Region::Eu) => OHTTP_KEY_CONFIG_PRODUCTION_EU,
        (Environment::Production, Region::Ap) => OHTTP_KEY_CONFIG_PRODUCTION_AP,
    }
}

impl DefaultConfig for AuthenticatorConfig {
    fn from_environment(
        environment: &Environment,
        rpc_url: Option<String>,
        region: Option<Region>,
    ) -> Result<Self, WalletKitError> {
        let region = region.unwrap_or_default();
        let config = Config::from_environment(environment, rpc_url, Some(region))?;

        let key_config_base64 = ohttp_key_config(region, environment);
        let relay_url = ohttp_relay_url(region, environment);
        let ohttp = Some(OhttpClientConfig::new(
            relay_url,
            key_config_base64.to_string(),
        ));

        Ok(Self {
            config,
            ohttp_indexer: ohttp.clone(),
            ohttp_gateway: ohttp,
        })
    }
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
                480, // Staging also runs on World Chain Mainnet
                STAGING_WORLD_ID_REGISTRY,
                indexer_url(region, environment),
                "https://gateway.id-infra.worldcoin.dev".to_string(),
                oprf_node_urls(region, environment),
                3,
            )
            .map_err(WalletKitError::from),

            Environment::Production => Self::new(
                rpc_url,
                480,
                WORLD_ID_REGISTRY,
                indexer_url(region, environment),
                "https://gateway.id-infra.world.org".to_string(),
                oprf_node_urls(region, environment),
                3,
            )
            .map_err(WalletKitError::from),
        }
    }
}
