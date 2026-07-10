//! Test environment configuration.
use alloy::primitives::{hex, Address};
use walletkit_core::{defaults::world_id_verifier_address, Environment, Region};
use world_id_core::primitives::Config;

/// Staging RP ID registered on the `RpRegistry` contract.
pub const STAGING_RP_ID: u64 = 46;

/// ECDSA private key (secp256k1) for the staging RP.
///
/// WARNING: intentionally public and only authorized for the pre-registered
/// *staging* RP. Never reuse against non-staging environments — non-staging
/// setups must supply their own `rp_signing_key`.
pub const STAGING_RP_SIGNING_KEY: [u8; 32] =
    hex!("1111111111111111111111111111111111111111111111111111111111111111");

/// Default RPC URL for World Chain Mainnet (chain 480).
pub const DEFAULT_WORLDCHAIN_RPC_URL: &str =
    "https://worldchain-mainnet.g.alchemy.com/public";

/// Hosted faux-issuer endpoint (staging).
pub const FAUX_ISSUER_URL: &str = "https://faux-issuer.us.id-infra.worldcoin.dev/issue";

/// Issuer schema ID served by the hosted faux issuer.
pub const FAUX_ISSUER_SCHEMA_ID: u64 = 128;

/// Issuer schema ID registered for the local `EdDSA` issuer on staging.
pub const LOCAL_ISSUER_SCHEMA_ID: u64 = 47;

/// `EdDSA` private key (32 bytes) for the registered local issuer.
///
/// WARNING: intentionally public and only authorized for the issuer schema
/// registered on *staging*. Never reuse against non-staging environments —
/// non-staging setups must supply their own `local_issuer_eddsa_key`.
pub const LOCAL_ISSUER_EDDSA_KEY: [u8; 32] =
    hex!("1111111111111111111111111111111111111111111111111111111111111111");

/// Configuration for the test helpers, centralizing all staging fixtures.
///
/// Construct with [`TestEnv::default_staging`] (also the [`Default`]) and override any
/// field as needed. Every helper in this crate takes a `&TestEnv` so callers can
/// point the same flow at a different RP, verifier, RPC, or issuer.
///
/// All defaults are *staging* fixtures: the embedded private keys are
/// intentionally public and authorized on staging only. When targeting any
/// other environment, supply your own `rp_signing_key` and
/// `local_issuer_eddsa_key` — never reuse the staging defaults.
#[derive(Debug, Clone)]
pub struct TestEnv {
    /// RP ID registered on the `RpRegistry` contract.
    pub rp_id: u64,
    /// ECDSA private key (secp256k1) used to sign proof requests as the RP.
    pub rp_signing_key: [u8; 32],
    /// On-chain `WorldIDVerifier` contract address.
    pub world_id_verifier: Address,
    /// Hosted faux-issuer endpoint.
    pub faux_issuer_url: String,
    /// Issuer schema ID served by the hosted faux issuer.
    pub faux_issuer_schema_id: u64,
    /// Issuer schema ID registered for the local `EdDSA` issuer.
    pub local_issuer_schema_id: u64,
    /// `EdDSA` private key for the local issuer.
    pub local_issuer_eddsa_key: [u8; 32],
    /// World Chain RPC URL for the test environment.
    pub rpc_url: String,
    /// World ID configuration for the test environment.
    pub world_id_config: Config,
}

impl TestEnv {
    /// Returns the staging configuration with all pre-registered fixtures.
    #[expect(
        clippy::missing_panics_doc,
        reason = "unreachable: default_config only fails parsing a caller-supplied rpc_url"
    )]
    #[must_use]
    pub fn default_staging() -> Self {
        let world_id_config = walletkit_core::defaults::default_config(
            &Environment::Staging,
            None,
            Some(Region::Us),
        )
        .expect("infallible: default_config only fails parsing a caller-supplied rpc_url, and none is passed");
        Self {
            rp_id: STAGING_RP_ID,
            rp_signing_key: STAGING_RP_SIGNING_KEY,
            world_id_verifier: world_id_verifier_address(&Environment::Staging),
            faux_issuer_url: FAUX_ISSUER_URL.to_string(),
            faux_issuer_schema_id: FAUX_ISSUER_SCHEMA_ID,
            local_issuer_schema_id: LOCAL_ISSUER_SCHEMA_ID,
            local_issuer_eddsa_key: LOCAL_ISSUER_EDDSA_KEY,
            rpc_url: DEFAULT_WORLDCHAIN_RPC_URL.to_string(),
            world_id_config,
        }
    }

    /// Returns the staging configuration with the given World ID `config` and
    /// verifier address, keeping all other pre-registered staging fixtures.
    #[must_use]
    pub fn default_with_config_and_verifier(config: Config, verifier: Address) -> Self {
        Self {
            rp_id: STAGING_RP_ID,
            rp_signing_key: STAGING_RP_SIGNING_KEY,
            world_id_verifier: verifier,
            faux_issuer_url: FAUX_ISSUER_URL.to_string(),
            faux_issuer_schema_id: FAUX_ISSUER_SCHEMA_ID,
            local_issuer_schema_id: LOCAL_ISSUER_SCHEMA_ID,
            local_issuer_eddsa_key: LOCAL_ISSUER_EDDSA_KEY,
            rpc_url: DEFAULT_WORLDCHAIN_RPC_URL.to_string(),
            world_id_config: config,
        }
    }
}

impl Default for TestEnv {
    fn default() -> Self {
        Self::default_staging()
    }
}
