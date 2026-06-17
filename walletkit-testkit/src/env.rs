//! Test environment configuration.
//!
//! [`TestEnv`] centralizes every staging-registered constant that the test
//! helpers need — RP id/signing key, on-chain verifier address, World Chain RPC,
//! and the two issuer fixtures (hosted faux-issuer and local `EdDSA`). The
//! [`Default`] impl returns [`TestEnv::staging`]; individual fields can be
//! overridden for pointing helpers at other environments or fixtures.
//!
//! All fixtures are pre-registered on staging: the RP on the `RpRegistry`
//! contract and both issuers on the `CredentialSchemaIssuerRegistry`. Proofs
//! verify on-chain because the `WorldIDVerifier` resolves the issuer public key
//! from the on-chain registry by schema id.

use alloy::primitives::{address, hex, Address};
use walletkit_core::Environment;

/// Staging RP ID registered on the `RpRegistry` contract.
pub const STAGING_RP_ID: u64 = 46;

/// ECDSA private key (secp256k1) for the staging RP.
pub const STAGING_RP_SIGNING_KEY: [u8; 32] = hex!(
    "1111111111111111111111111111111111111111111111111111111111111111"
);

/// `WorldIDVerifier` proxy contract address on staging (World Chain Mainnet 480).
pub const STAGING_WORLD_ID_VERIFIER: Address =
    address!("0x703a6316c975DEabF30b637c155edD53e24657DB");

/// Default RPC URL for World Chain Mainnet (chain 480).
pub const DEFAULT_WORLDCHAIN_RPC_URL: &str =
    "https://worldchain-mainnet.g.alchemy.com/public";

/// Hosted faux-issuer endpoint (staging).
pub const FAUX_ISSUER_URL: &str =
    "https://faux-issuer.us.id-infra.worldcoin.dev/issue";

/// Issuer schema ID served by the hosted faux issuer.
pub const FAUX_ISSUER_SCHEMA_ID: u64 = 128;

/// Issuer schema ID registered for the local `EdDSA` issuer on staging.
pub const LOCAL_ISSUER_SCHEMA_ID: u64 = 47;

/// `EdDSA` private key (32 bytes) for the registered local issuer.
pub const LOCAL_ISSUER_EDDSA_KEY: [u8; 32] = hex!(
    "1111111111111111111111111111111111111111111111111111111111111111"
);

/// Configuration for the test helpers, centralizing all staging fixtures.
///
/// Construct with [`TestEnv::staging`] (also the [`Default`]) and override any
/// field as needed. Every helper in this crate takes a `&TestEnv` so callers can
/// point the same flow at a different RP, verifier, RPC, or issuer.
#[derive(Debug, Clone)]
pub struct TestEnv {
    /// RP ID registered on the `RpRegistry` contract.
    pub rp_id: u64,
    /// ECDSA private key (secp256k1) used to sign proof requests as the RP.
    pub rp_signing_key: [u8; 32],
    /// On-chain `WorldIDVerifier` contract address.
    pub world_id_verifier: Address,
    /// World Chain RPC URL used for on-chain verification.
    pub worldchain_rpc_url: String,
    /// Hosted faux-issuer endpoint.
    pub faux_issuer_url: String,
    /// Issuer schema ID served by the hosted faux issuer.
    pub faux_issuer_schema_id: u64,
    /// Issuer schema ID registered for the local `EdDSA` issuer.
    pub local_issuer_schema_id: u64,
    /// `EdDSA` private key for the local issuer.
    pub local_issuer_eddsa_key: [u8; 32],
    /// World ID environment these fixtures belong to.
    pub environment: Environment,
}

impl TestEnv {
    /// Returns the staging configuration with all pre-registered fixtures.
    #[must_use]
    pub fn staging() -> Self {
        Self {
            rp_id: STAGING_RP_ID,
            rp_signing_key: STAGING_RP_SIGNING_KEY,
            world_id_verifier: STAGING_WORLD_ID_VERIFIER,
            worldchain_rpc_url: DEFAULT_WORLDCHAIN_RPC_URL.to_string(),
            faux_issuer_url: FAUX_ISSUER_URL.to_string(),
            faux_issuer_schema_id: FAUX_ISSUER_SCHEMA_ID,
            local_issuer_schema_id: LOCAL_ISSUER_SCHEMA_ID,
            local_issuer_eddsa_key: LOCAL_ISSUER_EDDSA_KEY,
            environment: Environment::Staging,
        }
    }

    /// Overrides the World Chain RPC URL, returning the modified config.
    #[must_use]
    pub fn with_rpc_url(mut self, rpc_url: impl Into<String>) -> Self {
        self.worldchain_rpc_url = rpc_url.into();
        self
    }
}

impl Default for TestEnv {
    fn default() -> Self {
        Self::staging()
    }
}
