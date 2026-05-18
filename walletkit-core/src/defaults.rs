use alloy_core::primitives::{address, Address};
use world_id_core::primitives::{Config, ServiceEndpoint};

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

fn gateway_url(environment: &Environment) -> String {
    match environment {
        Environment::Staging => "https://gateway.id-infra.worldcoin.dev".to_string(),
        Environment::Production => "https://gateway.id-infra.world.org".to_string(),
    }
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
const OHTTP_KEY_CONFIG_PRODUCTION_US: &str =
    include_str!("ohttp_keys/production_us.b64");
const OHTTP_KEY_CONFIG_PRODUCTION_EU: &str =
    include_str!("ohttp_keys/production_eu.b64");
const OHTTP_KEY_CONFIG_PRODUCTION_AP: &str =
    include_str!("ohttp_keys/production_ap.b64");

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

fn ohttp_endpoint(
    url: String,
    region: Region,
    environment: &Environment,
) -> ServiceEndpoint {
    ServiceEndpoint::ohttp(
        url,
        ohttp_relay_url(region, environment),
        ohttp_key_config(region, environment).to_string(),
    )
}

fn build_config(
    environment: &Environment,
    rpc_url: Option<String>,
    region: Region,
    indexer: ServiceEndpoint,
    gateway: ServiceEndpoint,
) -> Result<Config, WalletKitError> {
    let (chain_id, registry_address) = match environment {
        // Staging also runs on World Chain Mainnet.
        Environment::Staging => (480, STAGING_WORLD_ID_REGISTRY),
        Environment::Production => (480, WORLD_ID_REGISTRY),
    };

    Config::new(
        rpc_url,
        chain_id,
        registry_address,
        indexer,
        gateway,
        oprf_node_urls(region, environment),
        3,
    )
    .map_err(WalletKitError::from)
}

/// Builds a [`Config`] for the given [`Environment`] using direct (non-OHTTP)
/// service endpoints — the default for SDK consumers.
///
/// # Errors
///
/// Returns [`WalletKitError`] if the configuration cannot be constructed
/// (e.g. invalid RPC URL).
pub fn default_config(
    environment: &Environment,
    rpc_url: Option<String>,
    region: Option<Region>,
) -> Result<Config, WalletKitError> {
    let region = region.unwrap_or_default();
    let indexer = ServiceEndpoint::direct(indexer_url(region, environment));
    let gateway = ServiceEndpoint::direct(gateway_url(environment));
    build_config(environment, rpc_url, region, indexer, gateway)
}

/// Builds a [`Config`] for the given [`Environment`] using OHTTP service
/// endpoints. Opt-in alternative to [`default_config`] for consumers that
/// want their indexer/gateway traffic to flow through the Cloudflare OHTTP
/// relay.
///
/// The indexer endpoint follows the caller's region; the gateway endpoint is
/// always pinned to the US OHTTP relay because the `world-id-gateway` is
/// centralised in the US cluster.
///
/// # Errors
///
/// Returns [`WalletKitError`] if the configuration cannot be constructed
/// (e.g. invalid RPC URL).
pub fn default_config_with_ohttp(
    environment: &Environment,
    rpc_url: Option<String>,
    region: Option<Region>,
) -> Result<Config, WalletKitError> {
    let region = region.unwrap_or_default();
    let indexer =
        ohttp_endpoint(indexer_url(region, environment), region, environment);
    let gateway = ohttp_endpoint(gateway_url(environment), Region::Us, environment);
    build_config(environment, rpc_url, region, indexer, gateway)
}
