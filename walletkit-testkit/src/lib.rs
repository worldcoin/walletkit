//! `walletkit-testkit` — reusable end-to-end test helpers for World ID v4.
//!
//! This crate consolidates the e2e/test-support logic that was previously
//! duplicated across `walletkit-core`'s integration tests, the `walletkit-cli`
//! binary, and external consumers (e.g. orb-tools). It is **test-support only**
//! and is never published to crates.io: it ships staging URLs and pre-registered
//! test-RP / test-issuer private keys, and is consumed by git revision.
//!
//! # What it provides
//!
//! - [`TestEnv`] — a config struct centralizing all staging constants (RP id/key,
//!   on-chain verifier address, World Chain RPC, faux-issuer URL + schema, local
//!   issuer key + schema). [`TestEnv::default`] is staging; every field is
//!   overridable.
//! - Storage providers usable with the `walletkit-core` storage traits:
//!   an in-memory provider for ephemeral tests and a filesystem-backed provider
//!   for CLI-style local state.
//! - Credential issuance via two interchangeable strategies: the hosted
//!   faux-issuer (HTTP, schema 128) and a local `EdDSA` issuer (schema 47,
//!   deterministic, no service dependency).
//! - Proof-request construction signed by the staging RP key, and on-chain
//!   verification against the staging `WorldIDVerifier` contract.
//! - A high-level `generate_and_verify_test_proof` convenience that wires the
//!   whole flow together for either issuance strategy.

pub mod env;
pub mod storage;

pub use env::TestEnv;
