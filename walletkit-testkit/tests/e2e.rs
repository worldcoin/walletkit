//! End-to-end staging integration tests for `walletkit-testkit`.
//!
//! These tests drive the full [`generate_and_verify_test_proof`] flow against
//! **live staging infrastructure** (OPRF nodes, indexer, gateway, faux issuer,
//! and the on-chain `WorldIDVerifier`). They are `#[ignore]`d by default and run
//! only on demand:
//!
//! ```text
//! cargo test -p walletkit-testkit --test e2e -- --ignored --nocapture
//! ```

#![allow(
    clippy::missing_panics_doc,
    clippy::missing_errors_doc,
    reason = "integration tests"
)]

use tempfile::TempDir;
use walletkit_testkit::utils::now_secs;
use walletkit_testkit::{generate_and_verify_test_proof, CredentialType, TestEnv};

// Distinct seeds so the parallel tests drive independent staging identities.
const FAUX_TEST_SEED: [u8; 32] = [7u8; 32];
const LOCAL_TEST_SEED: [u8; 32] = [8u8; 32];
const SIGNAL: &str = "test_signal";
const CREDENTIAL_TTL_SECS: u64 = 3600;

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .try_init();
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires staging infrastructure"]
async fn e2e_faux_issuer_proof() {
    init_tracing();
    let env = TestEnv::default_staging();
    let root = TempDir::new().expect("failed to create temp storage dir");

    let outcome = generate_and_verify_test_proof(
        CredentialType::Faux,
        &env,
        &FAUX_TEST_SEED,
        root.path(),
        SIGNAL,
    )
    .await
    .expect("faux-issuer flow should succeed");

    assert!(
        outcome.verified(),
        "faux-issued proof should verify on-chain: {:?}",
        outcome.verification
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires staging infrastructure"]
async fn e2e_local_eddsa_proof() {
    init_tracing();
    let env = TestEnv::default_staging();
    let root = TempDir::new().expect("failed to create temp storage dir");

    let now = now_secs();
    let credential_type = CredentialType::Local {
        genesis_issued_at: now,
        expires_at: now + CREDENTIAL_TTL_SECS,
    };

    let outcome = generate_and_verify_test_proof(
        credential_type,
        &env,
        &LOCAL_TEST_SEED,
        root.path(),
        SIGNAL,
    )
    .await
    .expect("local-EdDSA flow should succeed");

    assert!(
        outcome.verified(),
        "local-EdDSA-issued proof should verify on-chain: {:?}",
        outcome.verification
    );
}
