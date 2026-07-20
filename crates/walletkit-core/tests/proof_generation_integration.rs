#![allow(
    missing_docs,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::similar_names,
    clippy::too_many_lines,
    reason = "integration tests"
)]

//! End-to-end integration tests for `walletkit_core::Authenticator::generate_proof`
//! (World ID v4) against **staging infrastructure** (real OPRF nodes, indexer,
//! gateway, faux/local issuer, and the on-chain `WorldIDVerifier`).
//!
//! These build on [`walletkit_testkit`] so the staging fixtures (RP, issuer
//! schemas, keys, verifier, RPC) live in a single [`TestEnv`] instead of being
//! duplicated here.
//!
//! Run with:
//!   `cargo test --test proof_generation_integration --features embed-zkeys`

use alloy::primitives::Address;
use rand::rngs::OsRng;
use tempfile::TempDir;
use walletkit_testkit::issuer::issue_local_credential;
use walletkit_testkit::proof::build_test_request;
use walletkit_testkit::utils::now_secs;
use walletkit_testkit::{
    generate_and_verify_test_proof, init_and_register_account, CredentialType,
    ProofType, TestEnv,
};
use world_id_core::primitives::FieldElement;

use eyre::{Result, WrapErr as _};

// Distinct seeds so these tests drive independent staging identities, both from
// each other and from the `walletkit-testkit` e2e suite (which uses [7], [8], [9]).
const UNIQUENESS_TEST_SEED: [u8; 32] = [17u8; 32];
const SESSION_TEST_SEED: [u8; 32] = [19u8; 32];
const SIGNAL: &str = "my_signal";
const CREDENTIAL_TTL_SECS: u64 = 3600;
const REQUEST_TTL_SECS: u64 = 300;

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .try_init();
}

/// Full end-to-end uniqueness proof through `walletkit_core::Authenticator`
/// against staging infrastructure: account registration, local-EdDSA credential
/// issuance, proof generation, and on-chain verification.
#[tokio::test(flavor = "multi_thread")]
async fn e2e_authenticator_generate_proof() -> Result<()> {
    init_tracing();

    let env = TestEnv::default_staging();
    let root = TempDir::new().wrap_err("failed to create temp storage dir")?;

    let now = now_secs();
    let credential_type = CredentialType::Local {
        genesis_issued_at: now,
        expires_at: now + CREDENTIAL_TTL_SECS,
    };

    let outcome = generate_and_verify_test_proof(
        credential_type,
        &env,
        &UNIQUENESS_TEST_SEED,
        root.path(),
        SIGNAL,
        ProofType::Uniqueness,
        None,
    )
    .await
    .wrap_err("uniqueness flow should succeed")?;

    assert!(
        outcome.verified(),
        "uniqueness proof should verify on-chain: {:?}",
        outcome.verification
    );

    Ok(())
}

/// End-to-end session flow through `walletkit_core::Authenticator` against
/// staging infrastructure: creates a session, generates a follow-up session
/// proof reusing the session, and asserts that an independently generated
/// WIP-103 ownership proof shares the session proof's Merkle root (i.e. both
/// prove inclusion of the same on-chain account).
#[tokio::test(flavor = "multi_thread")]
async fn e2e_session_proof() -> Result<()> {
    init_tracing();

    let env = TestEnv::default_staging();
    let root = TempDir::new().wrap_err("failed to create temp storage dir")?;
    let schema_id = env.local_issuer_schema_id;

    // Phase 1: register the account and initialize a filesystem-backed authenticator.
    let (authenticator, store) = init_and_register_account(
        &env,
        &SESSION_TEST_SEED,
        root.path(),
        Some(Address::ZERO),
    )
    .await
    .wrap_err("account setup failed")?;

    // Phase 2: issue a local-EdDSA credential to prove over.
    let now = now_secs();
    issue_local_credential(
        &env,
        &authenticator,
        &store,
        now,
        now + CREDENTIAL_TTL_SECS,
    )
    .await
    .wrap_err("credential issuance failed")?;

    // Phase 3: create a session and confirm the session seed is cached.
    let create_request = build_test_request(
        &env,
        schema_id,
        SIGNAL,
        REQUEST_TTL_SECS,
        ProofType::CreateSession,
        None,
    )
    .wrap_err("failed to build create-session request")?;
    let create_response = authenticator
        .generate_proof(&create_request.clone().into(), Some(now_secs()))
        .await
        .wrap_err("generate_proof (create session) failed")?
        .into_inner();
    assert!(create_response.error.is_none(), "create-session error");
    assert_eq!(create_response.responses.len(), 1);
    let create_item = &create_response.responses[0];
    assert!(
        create_item.is_session(),
        "create-session response should contain a session proof"
    );
    assert!(
        create_item.session_nullifier.is_some(),
        "create-session response should have a session_nullifier"
    );
    assert!(
        create_item.nullifier.is_none(),
        "create-session response should not have a uniqueness nullifier"
    );
    let session_id = create_response
        .session_id
        .expect("create-session response should include session_id");
    let cached_seed = store
        .get_session_seed(session_id.oprf_seed, now)
        .wrap_err("get_session_seed failed")?;
    assert!(
        cached_seed.is_some(),
        "create-session should cache session_id_r_seed"
    );

    // Phase 4: generate a follow-up session proof reusing the session.
    let session_request = build_test_request(
        &env,
        schema_id,
        SIGNAL,
        REQUEST_TTL_SECS,
        ProofType::Session,
        Some(session_id),
    )
    .wrap_err("failed to build session request")?;
    let session_response = authenticator
        .generate_proof(&session_request.clone().into(), Some(now_secs()))
        .await
        .wrap_err("generate_proof (session) failed")?
        .into_inner();
    assert!(session_response.error.is_none(), "session proof error");
    assert_eq!(session_response.responses.len(), 1);

    let session_item = &session_response.responses[0];
    assert!(
        session_item.is_session(),
        "response should be a session proof"
    );
    assert!(
        session_item.session_nullifier.is_some(),
        "session proof should have a session_nullifier"
    );
    assert!(
        session_item.nullifier.is_none(),
        "session proof should not have a uniqueness nullifier"
    );

    // Phase 5: an independent ownership proof must share the session proof's
    // Merkle root — both prove inclusion of the same on-chain account.
    let (credential, blinding_factor) = store
        .get_credential(schema_id, now)
        .wrap_err("failed to retrieve issued credential")?
        .ok_or_else(|| eyre::eyre!("issued credential missing from store"))?;
    let sub = credential.sub();
    let nonce = FieldElement::random(&mut OsRng).into();
    let ownership_proof = authenticator
        .prove_credential_sub(&nonce, &blinding_factor, &sub)
        .await
        .wrap_err("ownership proof generation failed")?;
    assert_eq!(
        ownership_proof.merkle_root().to_u256(),
        session_item.proof.as_ethereum_representation()[4],
        "ownership proof Merkle root should match the session proof"
    );

    Ok(())
}
