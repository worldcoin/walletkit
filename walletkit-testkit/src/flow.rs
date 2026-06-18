//! High-level end-to-end convenience flow.
//!
//! [`generate_and_verify_test_proof`] wires the whole pipeline together — account
//! registration, authenticator init, credential issuance, proof-request signing,
//! proof generation, and on-chain verification — for either issuance strategy.
//! It mirrors the CLI's `proof test` subcommand.

use std::path::Path;

use alloy::primitives::Address;
use eyre::WrapErr as _;
use world_id_core::requests::ProofType;

use crate::authenticator::{init_authenticator, register_account};
use crate::env::TestEnv;
use crate::issuer::{
    issue_faux_credential, issue_local_credential, IssuedTestCredential,
};
use crate::proof::{build_test_request, verify_proof_onchain, VerifyItemResult};

/// Credential issuance strategy for [`generate_and_verify_test_proof`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssuanceStrategy {
    /// Hosted faux issuer over HTTP (schema 128).
    Faux,
    /// Local `EdDSA` issuer (schema 47), deterministic and service-independent.
    LocalEdDSA,
}

/// Outcome of an end-to-end test proof run.
#[derive(Debug, Clone)]
pub struct TestProofOutcome {
    /// The credential that was issued and stored.
    pub issued: IssuedTestCredential,
    /// On-chain verification results, one per response item.
    pub results: Vec<VerifyItemResult>,
}

impl TestProofOutcome {
    /// Returns `true` if every response item verified on-chain.
    #[must_use]
    pub fn all_verified(&self) -> bool {
        self.results.iter().all(|r| r.verified)
    }
}

/// How far in the future issued credentials and proof requests expire.
const CREDENTIAL_TTL_SECS: u64 = 3600;
const REQUEST_TTL_SECS: u64 = 300;

/// Runs the full issue → prove → verify flow for the given issuance strategy.
///
/// Registers (or initializes) the account, initializes a filesystem-backed
/// authenticator rooted at `root`, issues a uniqueness credential via `strategy`,
/// builds and signs a proof request for `signal`, generates the proof, and
/// verifies it on-chain. `now` (unix seconds) is used consistently throughout.
///
/// # Errors
///
/// Returns an error if any stage (registration, init, issuance, proof
/// generation, or verification setup) fails.
pub async fn generate_and_verify_test_proof(
    env: &TestEnv,
    seed: &[u8],
    root: &Path,
    strategy: IssuanceStrategy,
    signal: &str,
    now: u64,
) -> eyre::Result<TestProofOutcome> {
    let leaf_index = register_account(env, seed, Some(Address::ZERO))
        .await
        .wrap_err("account registration failed")?;

    let (authenticator, store) = init_authenticator(env, seed, root, now).await?;

    let issued = match strategy {
        IssuanceStrategy::Faux => {
            issue_faux_credential(env, &authenticator, &store, now).await?
        }
        IssuanceStrategy::LocalEdDSA => {
            issue_local_credential(
                env,
                &authenticator,
                &store,
                leaf_index,
                now,
                now,
                now + CREDENTIAL_TTL_SECS,
            )
            .await?
        }
    };

    let core_request = build_test_request(
        env,
        issued.issuer_schema_id,
        signal,
        now,
        REQUEST_TTL_SECS,
        ProofType::Uniqueness,
        None,
    )?;

    let walletkit_request: walletkit_core::requests::ProofRequest =
        core_request.clone().into();
    let proof_response = authenticator
        .generate_proof(&walletkit_request, Some(now))
        .await
        .wrap_err("proof generation failed")?;
    let response = proof_response.into_inner();

    let results = verify_proof_onchain(env, &core_request, &response).await?;

    Ok(TestProofOutcome { issued, results })
}
