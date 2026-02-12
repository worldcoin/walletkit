#![cfg(feature = "storage")]

//! End-to-end integration test for `Authenticator::generate_proof` (World ID v4).
//!
//! Requires Docker for Postgres + LocalStack containers.
//! Run with: `cargo test --test proof_generation_integration --features default`

mod common;

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use alloy::signers::local::LocalSigner;
use eyre::{Context as _, Result};
use taceo_oprf::types::{OprfKeyId, ShareEpoch};
use taceo_oprf_test_utils::health_checks;
use walletkit_core::Authenticator;
use world_id_core::{
    requests::{ProofRequest, RequestItem, RequestVersion},
    Authenticator as CoreAuthenticator, EdDSAPrivateKey,
};
use world_id_gateway::{spawn_gateway_for_tests, GatewayConfig, SignerArgs};
use world_id_primitives::{
    merkle::AccountInclusionProof, Config, FieldElement, TREE_DEPTH,
};
use world_id_test_utils::{
    anvil::WorldIDVerifier,
    fixtures::{
        build_base_credential, generate_rp_fixture, single_leaf_merkle_fixture,
        MerkleFixture, RegistryTestContext,
    },
    stubs::spawn_indexer_stub,
};

/// Full end-to-end proof generation through `walletkit_core::Authenticator::generate_proof`.
///
/// This test exercises:
/// 1. Account creation via the gateway
/// 2. Credential issuance (signed by a test issuer)
/// 3. Proof generation with real OPRF nodes (ZK circuit requires real OPRF output)
/// 4. On-chain proof verification via `WorldIDVerifier`
#[tokio::test(flavor = "multi_thread")]
async fn e2e_authenticator_generate_proof() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .try_init();

    // ----------------------------------------------------------------
    // Phase 1: Infrastructure — containers, contracts, gateway
    // ----------------------------------------------------------------
    let containers = tokio::join!(
        taceo_oprf_test_utils::localstack_testcontainer(),
        taceo_oprf_test_utils::postgres_testcontainer(),
        taceo_oprf_test_utils::postgres_testcontainer(),
        taceo_oprf_test_utils::postgres_testcontainer(),
        taceo_oprf_test_utils::postgres_testcontainer(),
        taceo_oprf_test_utils::postgres_testcontainer(),
    );
    let (_localstack_container, localstack_url) = containers.0?;
    let (_pg0, pg_url_0) = containers.1?;
    let (_pg1, pg_url_1) = containers.2?;
    let (_pg2, pg_url_2) = containers.3?;
    let (_pg3, pg_url_3) = containers.4?;
    let (_pg4, pg_url_4) = containers.5?;
    let postgres_urls = [pg_url_0, pg_url_1, pg_url_2, pg_url_3, pg_url_4];

    let RegistryTestContext {
        anvil,
        world_id_registry,
        rp_registry,
        oprf_key_registry,
        world_id_verifier,
        credential_registry,
    } = RegistryTestContext::new().await?;

    let deployer = anvil
        .signer(0)
        .wrap_err("failed to fetch deployer signer")?;

    let signer_args = SignerArgs::from_wallet(hex::encode(deployer.to_bytes()));
    let gateway_config = GatewayConfig {
        registry_addr: world_id_registry,
        provider: world_id_gateway::ProviderArgs {
            http: Some(vec![anvil.endpoint().parse().unwrap()]),
            signer: Some(signer_args),
            ..Default::default()
        },
        batch_ms: 200,
        listen_addr: (std::net::Ipv4Addr::LOCALHOST, 0u16).into(),
        max_create_batch_size: 10,
        max_ops_batch_size: 10,
        redis_url: None,
    };
    let gateway = spawn_gateway_for_tests(gateway_config)
        .await
        .wrap_err("failed to spawn gateway")?;
    let gateway_url = format!("http://{}", gateway.listen_addr);

    // ----------------------------------------------------------------
    // Phase 2: Account creation via CoreAuthenticator
    // ----------------------------------------------------------------
    let seed = [7u8; 32];
    let recovery_address = anvil
        .signer(1)
        .wrap_err("failed to fetch recovery signer")?
        .address();

    let creation_config = Config::new(
        Some(anvil.endpoint().to_string()),
        anvil.instance.chain_id(),
        world_id_registry,
        "http://127.0.0.1:0".to_string(), // placeholder indexer
        gateway_url.clone(),
        Vec::new(),
        3,
    )
    .unwrap();

    let core_authenticator = CoreAuthenticator::init_or_register(
        &seed,
        creation_config.clone(),
        Some(recovery_address),
    )
    .await
    .wrap_err("account creation failed")?;
    assert_eq!(core_authenticator.leaf_index(), 1);

    let leaf_index = core_authenticator.leaf_index();
    let MerkleFixture {
        key_set,
        inclusion_proof: merkle_inclusion_proof,
        ..
    } = single_leaf_merkle_fixture(
        vec![core_authenticator.offchain_pubkey()],
        leaf_index,
    )
    .wrap_err("failed to construct merkle fixture")?;

    let inclusion_proof =
        AccountInclusionProof::<{ TREE_DEPTH }>::new(merkle_inclusion_proof, key_set)
            .wrap_err("failed to build inclusion proof")?;

    let (indexer_url, indexer_handle) = spawn_indexer_stub(leaf_index, inclusion_proof)
        .await
        .wrap_err("failed to start indexer stub")?;

    // ----------------------------------------------------------------
    // Phase 3: OPRF nodes + on-chain registrations
    // ----------------------------------------------------------------
    let rp_fixture = generate_rp_fixture();
    let mut rng = rand::thread_rng();

    let oprf_key_gens = world_id_test_utils::stubs::spawn_key_gens(
        anvil.ws_endpoint(),
        &localstack_url,
        &postgres_urls,
        oprf_key_registry,
    )
    .await;

    let nodes = world_id_test_utils::stubs::spawn_oprf_nodes(
        anvil.ws_endpoint(),
        &postgres_urls,
        oprf_key_registry,
        world_id_registry,
        rp_registry,
        credential_registry,
    )
    .await;

    health_checks::services_health_check(&nodes, Duration::from_secs(60)).await?;
    health_checks::services_health_check(&oprf_key_gens, Duration::from_secs(60))
        .await?;

    // Register issuer on-chain (triggers OPRF key-gen for issuer)
    let issuer_schema_id = 1u64;
    let issuer_sk = EdDSAPrivateKey::random(&mut rng);
    let issuer_pk = issuer_sk.public();
    anvil
        .register_issuer(
            credential_registry,
            deployer.clone(),
            issuer_schema_id,
            issuer_pk.clone(),
        )
        .await?;

    // Register RP on-chain (triggers OPRF key-gen for RP)
    let rp_signer = LocalSigner::from_signing_key(rp_fixture.signing_key.clone());
    anvil
        .register_rp(
            rp_registry,
            deployer.clone(),
            rp_fixture.world_rp_id,
            rp_signer.address(),
            rp_signer.address(),
            "taceo.oprf".to_string(),
        )
        .await?;

    // Wait for OPRF public keys to be available
    let _rp_oprf_pk = health_checks::oprf_public_key_from_services(
        rp_fixture.oprf_key_id,
        ShareEpoch::default(),
        &nodes,
        Duration::from_secs(120),
    )
    .await?;

    let _issuer_oprf_pk = health_checks::oprf_public_key_from_services(
        OprfKeyId::new(alloy::primitives::U160::from(issuer_schema_id)),
        ShareEpoch::default(),
        &nodes,
        Duration::from_secs(120),
    )
    .await?;

    // ----------------------------------------------------------------
    // Phase 4: Reinitialize walletkit Authenticator with full config
    // ----------------------------------------------------------------
    // Set working directory to workspace root so embedded zkeys can be found
    let workspace_root =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..");
    std::env::set_current_dir(&workspace_root)
        .wrap_err("failed to set working directory to workspace root")?;

    let proof_config = Config::new(
        Some(anvil.endpoint().to_string()),
        anvil.instance.chain_id(),
        world_id_registry,
        indexer_url.clone(),
        gateway_url.clone(),
        nodes.to_vec(),
        3,
    )
    .unwrap();
    let config_json = serde_json::to_string(&proof_config).unwrap();

    let store = common::create_test_credential_store();

    let authenticator = Authenticator::init(&seed, &config_json, store.clone())
        .await
        .wrap_err("failed to init walletkit Authenticator with proof config")?;
    assert_eq!(authenticator.leaf_index(), 1);

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time after epoch")
        .as_secs();

    authenticator
        .init_storage(now)
        .wrap_err("init_storage failed")?;

    // ----------------------------------------------------------------
    // Phase 5: Credential issuance
    // ----------------------------------------------------------------
    let blinding_factor = authenticator
        .generate_credential_blinding_factor_remote(issuer_schema_id)
        .await
        .wrap_err("blinding factor generation failed")?;

    let _credential_sub = authenticator.compute_credential_sub(&blinding_factor);

    // Build and sign credential (inline, equivalent to faux-issuer)
    let mut credential = build_base_credential(
        issuer_schema_id,
        leaf_index,
        now,
        now + 3600, // expires in 1 hour
        blinding_factor.0,
    );
    credential.issuer = issuer_pk;
    let credential_hash = credential.hash().wrap_err("failed to hash credential")?;
    credential.signature = Some(issuer_sk.sign(*credential_hash));

    // Store credential in the CredentialStore
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

    // ----------------------------------------------------------------
    // Phase 6: Proof generation via walletkit Authenticator
    // ----------------------------------------------------------------
    let proof_request_core = ProofRequest {
        id: "test_request".to_string(),
        version: RequestVersion::V1,
        created_at: rp_fixture.current_timestamp,
        expires_at: rp_fixture.expiration_timestamp,
        rp_id: rp_fixture.world_rp_id,
        oprf_key_id: rp_fixture.oprf_key_id,
        session_id: None,
        action: Some(rp_fixture.action.into()),
        signature: rp_fixture.signature,
        nonce: rp_fixture.nonce.into(),
        requests: vec![RequestItem {
            identifier: "identifier".to_string(),
            issuer_schema_id,
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

    // ----------------------------------------------------------------
    // Phase 7: On-chain verification
    // ----------------------------------------------------------------
    let request_item = proof_request_core
        .find_request_by_issuer_schema_id(issuer_schema_id)
        .unwrap();

    let verifier: WorldIDVerifier::WorldIDVerifierInstance<
        alloy::providers::DynProvider,
    > = WorldIDVerifier::new(world_id_verifier, anvil.provider()?);
    verifier
        .verify(
            nullifier.into(),
            rp_fixture.action.into(),
            rp_fixture.world_rp_id.into_inner(),
            rp_fixture.nonce.into(),
            request_item.signal_hash().into(),
            response_item.expires_at_min,
            issuer_schema_id,
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

    // Cleanup
    indexer_handle.abort();

    panic!();

    Ok(())
}
