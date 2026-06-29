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

use walletkit_testkit::storage::{cleanup_storage, temp_root};
use walletkit_testkit::utils::now_secs;
use walletkit_testkit::{generate_and_verify_test_proof, CredentialType, TestEnv};

const TEST_SEED: [u8; 32] = [7u8; 32];
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
    let root = temp_root();

    let outcome = generate_and_verify_test_proof(
        CredentialType::Faux,
        &env,
        &TEST_SEED,
        &root,
        SIGNAL,
    )
    .await
    .expect("faux-issuer flow should succeed");

    cleanup_storage(&root);
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
    let root = temp_root();

    let now = now_secs();
    let credential_type = CredentialType::Local {
        genesis_issued_at: now,
        expires_at: now + CREDENTIAL_TTL_SECS,
    };

    let outcome = generate_and_verify_test_proof(
        credential_type,
        &env,
        &TEST_SEED,
        &root,
        SIGNAL,
    )
    .await
    .expect("local-EdDSA flow should succeed");

    cleanup_storage(&root);
    assert!(
        outcome.verified(),
        "local-EdDSA-issued proof should verify on-chain: {:?}",
        outcome.verification
    );
}
