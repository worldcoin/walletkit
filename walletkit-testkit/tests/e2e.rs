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

use std::time::{SystemTime, UNIX_EPOCH};

use walletkit_testkit::flow::{generate_and_verify_test_proof, IssuanceStrategy};
use walletkit_testkit::storage::{cleanup_storage, temp_root};
use walletkit_testkit::TestEnv;

/// Shared test seed (matches the existing core integration tests).
const TEST_SEED: [u8; 32] = [7u8; 32];

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time after epoch")
        .as_secs()
}

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
    let env = TestEnv::staging();
    let root = temp_root();

    let outcome = generate_and_verify_test_proof(
        &env,
        &TEST_SEED,
        &root,
        IssuanceStrategy::Faux,
        "test_signal",
        now_secs(),
    )
    .await
    .expect("faux-issuer flow should succeed");

    cleanup_storage(&root);
    assert!(
        outcome.all_verified(),
        "faux-issued proof should verify on-chain: {:?}",
        outcome.results
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires staging infrastructure"]
async fn e2e_local_eddsa_proof() {
    init_tracing();
    let env = TestEnv::staging();
    let root = temp_root();

    let outcome = generate_and_verify_test_proof(
        &env,
        &TEST_SEED,
        &root,
        IssuanceStrategy::LocalEdDSA,
        "test_signal",
        now_secs(),
    )
    .await
    .expect("local-EdDSA flow should succeed");

    cleanup_storage(&root);
    assert!(
        outcome.all_verified(),
        "local-EdDSA-issued proof should verify on-chain: {:?}",
        outcome.results
    );
}
