#![cfg(feature = "storage")]

//! End-to-end integration test for `Authenticator::generate_proof` (World ID v4)
//! using **staging infrastructure** (real OPRF nodes, indexer, gateway, on-chain registries).
//!
//! Prerequisites:
//! - A registered RP on the staging `RpRegistry` contract (hardcoded below)
//! - A registered issuer on the staging `CredentialSchemaIssuerRegistry` (hardcoded below)
//! - Staging OPRF key-gen must have picked up both registrations
//!
//! Run with:
//!   cargo test --test proof_generation_integration --features default -- --ignored

mod common;

use std::time::{SystemTime, UNIX_EPOCH};

use alloy::providers::ProviderBuilder;
use alloy::signers::{local::PrivateKeySigner, SignerSync};
use alloy::sol;
use eyre::{Context as _, Result};
use walletkit_core::{defaults::DefaultConfig, Authenticator, Environment};
use world_id_core::{
    requests::{ProofRequest, RequestItem, RequestVersion},
    Authenticator as CoreAuthenticator, EdDSAPrivateKey,
};
use world_id_primitives::{rp::RpId, FieldElement};

// ---------------------------------------------------------------------------
// Staging-registered constants (TODO: fill in after on-chain registration)
// ---------------------------------------------------------------------------

/// RP ID registered on the staging `RpRegistry` contract.
const RP_ID: u64 = 0; // TODO: replace with actual staging RP ID

/// ECDSA private key for the registered RP (secp256k1).
const RP_SIGNING_KEY: [u8; 32] =
    alloy::primitives::hex!("81ee18b54602db350e0575685ab35ce07840b89121a98d325623fc9b02db4f63");

/// Issuer schema ID registered on the staging `CredentialSchemaIssuerRegistry`.
const ISSUER_SCHEMA_ID: u64 = 0; // TODO: replace with actual staging issuer schema ID

/// EdDSA private key (32 bytes) for the registered issuer.
const ISSUER_EDDSA_KEY: [u8; 32] =
    alloy::primitives::hex!("4670065be71c9035d4f43b28eab2dc364a1af46bfc31eac24dc01ff47a26ccbc");

/// WorldIDVerifier proxy contract address on staging (World Chain Mainnet 480).
const WORLD_ID_VERIFIER: alloy::primitives::Address =
    alloy::primitives::address!("0xC1BF296fdf56Eec522eFCcb7655F158F3D108560");

/// Default RPC URL for World Chain Mainnet (chain 480).
const DEFAULT_RPC_URL: &str = "https://worldchain-mainnet.g.alchemy.com/public";

// ---------------------------------------------------------------------------
// On-chain WorldIDVerifier binding (only the `verify` function)
// ---------------------------------------------------------------------------
sol!(
    #[allow(clippy::too_many_arguments)]
    #[sol(rpc)]
    interface IWorldIDVerifier {
        function verify(
            uint256 nullifier,
            uint256 action,
            uint64 rpId,
            uint256 nonce,
            uint256 signalHash,
            uint64 expiresAtMin,
            uint64 issuerSchemaId,
            uint256 credentialGenesisIssuedAtMin,
            uint256[5] calldata zeroKnowledgeProof
        ) external view;
    }
);

/// Full end-to-end proof generation through `walletkit_core::Authenticator::generate_proof`
/// against staging infrastructure.
///
/// This test exercises:
/// 1. Account registration (or init if already registered) via the staging gateway
/// 2. Credential issuance (signed by a pre-registered staging issuer)
/// 3. Proof generation with real staging OPRF nodes
/// 4. On-chain proof verification via the staging `WorldIDVerifier`
#[ignore] // requires staging services + pre-registered RP/issuer
#[tokio::test(flavor = "multi_thread")]
async fn e2e_authenticator_generate_proof() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .try_init();

    let rpc_url = std::env::var("WORLDCHAIN_RPC_URL")
        .unwrap_or_else(|_| DEFAULT_RPC_URL.to_string());

    // ----------------------------------------------------------------
    // Phase 1: Account registration
    // ----------------------------------------------------------------
    let seed = [7u8; 32];
    let recovery_address = alloy::primitives::Address::ZERO;

    let config = world_id_primitives::Config::from_environment(
        &Environment::Staging,
        Some(rpc_url.clone()),
    )
    .wrap_err("failed to build staging config")?;

    let core_authenticator =
        CoreAuthenticator::init_or_register(&seed, config, Some(recovery_address))
            .await
            .wrap_err("account creation/init failed")?;

    let leaf_index = core_authenticator.leaf_index();
    eprintln!("Phase 1 complete: account ready (leaf_index={leaf_index})");

    // ----------------------------------------------------------------
    // Phase 2: Authenticator init with walletkit wrapper
    // ----------------------------------------------------------------
    // Set working directory to workspace root so embedded zkeys can be found
    let workspace_root =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..");
    std::env::set_current_dir(&workspace_root)
        .wrap_err("failed to set working directory to workspace root")?;

    let store = common::create_test_credential_store();

    let authenticator = Authenticator::init_with_defaults(
        &seed,
        Some(rpc_url.clone()),
        &Environment::Staging,
        store.clone(),
    )
    .await
    .wrap_err("failed to init walletkit Authenticator")?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time after epoch")
        .as_secs();

    authenticator
        .init_storage(now)
        .wrap_err("init_storage failed")?;

    eprintln!("Phase 2 complete: authenticator initialized");

    // ----------------------------------------------------------------
    // Phase 3: Credential issuance
    // ----------------------------------------------------------------
    let issuer_sk = EdDSAPrivateKey::from_bytes(ISSUER_EDDSA_KEY);
    let issuer_pk = issuer_sk.public();

    let blinding_factor = authenticator
        .generate_credential_blinding_factor_remote(ISSUER_SCHEMA_ID)
        .await
        .wrap_err("blinding factor generation failed")?;

    let _credential_sub = authenticator.compute_credential_sub(&blinding_factor);

    let mut credential = world_id_test_utils::fixtures::build_base_credential(
        ISSUER_SCHEMA_ID,
        leaf_index,
        now,
        now + 3600, // expires in 1 hour
        blinding_factor.0,
    );
    credential.issuer = issuer_pk;
    let credential_hash = credential.hash().wrap_err("failed to hash credential")?;
    credential.signature = Some(issuer_sk.sign(*credential_hash));

    let walletkit_credential: walletkit_core::Credential = credential.clone().into();
    store
        .store_credential(
            &walletkit_credential,
            &blinding_factor,
            now + 3600,
            None,
            now,
        )
        .wrap_err("store_credential failed")?;

    eprintln!("Phase 3 complete: credential issued and stored");

    // ----------------------------------------------------------------
    // Phase 4: Proof generation
    // ----------------------------------------------------------------
    let rp_signer = PrivateKeySigner::from_bytes(&RP_SIGNING_KEY.into())
        .expect("invalid RP ECDSA key");

    let nonce = FieldElement::from(42u64);
    let created_at = now;
    let expires_at = now + 300;
    let action = FieldElement::from(1u64);

    let rp_msg = world_id_primitives::rp::compute_rp_signature_msg(
        *nonce, created_at, expires_at,
    );
    let signature = rp_signer
        .sign_message_sync(&rp_msg)
        .wrap_err("failed to sign RP message")?;

    let rp_id = RpId::new(RP_ID);

    let proof_request_core = ProofRequest {
        id: "staging_test_request".to_string(),
        version: RequestVersion::V1,
        created_at,
        expires_at,
        rp_id,
        oprf_key_id: taceo_oprf::types::OprfKeyId::new(alloy::primitives::U160::from(
            RP_ID,
        )),
        session_id: None,
        action: Some(action),
        signature,
        nonce,
        requests: vec![RequestItem {
            identifier: "identifier".to_string(),
            issuer_schema_id: ISSUER_SCHEMA_ID,
            signal: Some("my_signal".to_string()),
            genesis_issued_at_min: None,
            expires_at_min: None,
        }],
        constraints: None,
    };

    let proof_request_json = serde_json::to_string(&proof_request_core).unwrap();
    let proof_request =
        walletkit_core::requests::ProofRequest::from_json(&proof_request_json)
            .wrap_err("failed to parse proof request")?;

    let proof_response = authenticator
        .generate_proof(&proof_request, Some(now))
        .await
        .wrap_err("generate_proof failed")?;

    let response_json = proof_response
        .to_json()
        .wrap_err("failed to serialize proof response")?;
    let response: world_id_core::requests::ProofResponse =
        serde_json::from_str(&response_json)
            .wrap_err("failed to parse proof response JSON")?;
    assert!(response.error.is_none(), "proof response contains error");
    assert_eq!(response.responses.len(), 1);

    let response_item = &response.responses[0];
    let nullifier = response_item
        .nullifier
        .expect("uniqueness proof should have nullifier");
    assert_ne!(nullifier, FieldElement::ZERO);

    eprintln!("Phase 4 complete: proof generated (nullifier={nullifier:?})");

    // ----------------------------------------------------------------
    // Phase 5: On-chain verification
    // ----------------------------------------------------------------
    let provider = ProviderBuilder::new().connect_http(rpc_url.parse().unwrap());

    let verifier = IWorldIDVerifier::new(WORLD_ID_VERIFIER, &provider);

    let request_item = proof_request_core
        .find_request_by_issuer_schema_id(ISSUER_SCHEMA_ID)
        .unwrap();

    verifier
        .verify(
            nullifier.into(),
            action.into(),
            RP_ID,
            nonce.into(),
            request_item.signal_hash().into(),
            response_item.expires_at_min,
            ISSUER_SCHEMA_ID,
            request_item
                .genesis_issued_at_min
                .unwrap_or_default()
                .try_into()
                .expect("u64 fits into U256"),
            response_item.proof.as_ethereum_representation(),
        )
        .call()
        .await
        .wrap_err("on-chain proof verification failed")?;

    eprintln!("Phase 5 complete: on-chain verification passed");

    Ok(())
}
