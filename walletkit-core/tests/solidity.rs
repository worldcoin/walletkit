use alloy::{
    node_bindings::AnvilInstance,
    primitives::{address, U256},
    providers::{ext::AnvilApi, ProviderBuilder, WalletProvider},
    signers::local::PrivateKeySigner,
    sol,
    sol_types::SolValue,
};
use walletkit_core::{
    proof::ProofContext, world_id::WorldId, CredentialType, Environment,
};

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    ExternalNullifier,
    "tests/out/external_nullifier.sol/ExternalNullifier.json"
);

#[tokio::test]
async fn test_advanced_external_nullifier_generation_on_chain() {
    let provider = ProviderBuilder::new().connect_anvil_with_wallet();

    let app_id = "app_10eb12bd96d8f7202892ff25f094c803".to_string();

    let addr = provider.default_signer_address();

    let contract = ExternalNullifier::deploy(&provider, app_id.clone())
        .await
        .unwrap();

    let contract = contract.clone();

    let custom_action =
        [addr.abi_encode_packed(), "test_text".abi_encode_packed()].concat();

    let context = ProofContext::new_from_bytes(
        &app_id,
        Some(custom_action),
        None,
        CredentialType::Orb,
    );

    let nullifier = contract
        .generateExternalNullifier("test_text".to_string())
        .from(addr)
        .call()
        .await
        .unwrap();

    assert_eq!(nullifier, *context.external_nullifier);
}

fn setup_anvil() -> AnvilInstance {
    dotenvy::dotenv().ok();
    let rpc_url = std::env::var("WORLDCHAIN_SEPOLIA_RPC_URL").expect(
        "WORLDCHAIN_SEPOLIA_RPC_URL not set. Copy .env.example to .env and add your RPC URL",
    );

    let anvil = alloy::node_bindings::Anvil::new().fork(rpc_url).spawn();
    println!("✓ Anvil started at: {}", anvil.endpoint());
    anvil
}

sol!(
    /// The World ID Address Book allows verifying wallet addresses using a World ID for a period of time.
    ///
    /// Reference: <https://github.com/worldcoin/world-id-contracts/blob/main/src/WorldIDRouterImplV1.sol#L342>
    ///
    /// Reference: <https://github.com/worldcoin/world-id-contracts/blob/main/src/interfaces/IWorldID.sol#L9>
    #[sol(rpc)]
    #[sol(rename_all = "camelcase")]
    interface IWorldIDRouter {
        function verifyProof(
            uint256 root,
            uint256 groupId,
            uint256 signal_hash,
            uint256 nullifier_hash,
            uint256 external_nullifier_hash,
            uint256[8] calldata proof
        ) external view;
    }
);

#[tokio::test]
async fn test_verify_simple_world_id_proof_on_chain() {
    // set up a World Chain Sepolia fork with the `WorldIDRouter` contract (proxy for `IWorldID`).
    let anvil = setup_anvil();
    let owner_signer = PrivateKeySigner::random();
    let owner = owner_signer.address();
    let provider = ProviderBuilder::new()
        .wallet(owner_signer)
        .connect_http(anvil.endpoint_url());
    provider
        .anvil_set_balance(owner, U256::from(1e19))
        .await
        .unwrap();

    // The World Chain Sepolia (4801) World ID Router contract
    // Reference: <https://docs.world.org/world-id/reference/contract-deployments>
    let contract_address = address!("0x57f928158C3EE7CDad1e4D8642503c4D0201f611");
    let world_id_contract = IWorldIDRouter::new(contract_address, &provider);

    // initialize a World ID and generate the relevant proof context
    let world_id = WorldId::new(b"not_a_real_secret", &Environment::Staging);

    let proof_context = ProofContext::new(
        "app_staging_509648994ab005fe79c4ddd0449606ca",
        None,
        Some("my_signal".to_string()),
        CredentialType::Orb,
    );

    let proof = world_id.generate_proof(&proof_context).await.unwrap();

    world_id_contract
        .verifyProof(
            proof.merkle_root.into(),
            U256::from(1), // 1 is the `groupId` for the Orb verification group
            proof_context.signal_hash.into(),
            proof.nullifier_hash.into(),
            proof_context.external_nullifier.into(),
            proof.raw_proof.flatten(),
        )
        .from(owner)
        .call()
        .await
        .unwrap();
}
