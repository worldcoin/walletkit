use std::time::SystemTime;

use alloy::{
    node_bindings::AnvilInstance,
    primitives::{address, Address, U256},
    providers::{ProviderBuilder, WalletProvider},
    sol,
    sol_types::SolValue,
};
use walletkit_core::{
    common_apps::AddressBook, proof::ProofContext, world_id::WorldId, CredentialType,
    Environment,
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
    /// Reference: <https://github.com/worldcoin/worldcoin-vault/blob/main/src/interfaces/IAddressBook.sol>
    #[sol(rpc)]
    #[sol(rename_all = "camelcase")]
    interface IAddressBook {
        function verify(
            address account,
            uint256 root,
            uint256 nullifier_hash,
            uint256[8] calldata proof,
            uint256 proof_time
        ) external payable virtual;
    }
);

#[tokio::test]
async fn test_address_book_proof_verification_on_chain() {
    // set up a World Chain Sepolia fork with the `WorldIdAddressBook` contract.
    let anvil = setup_anvil();
    let provider = ProviderBuilder::new().connect_http(anvil.endpoint_url());
    let contract_address = address!("0xb02Cafb1656043F7ae3b1BCc2f5B0d8086d5Df0e");
    let address_book = IAddressBook::new(contract_address, &provider);

    // initialize a World ID and generate the relevant proof context
    let world_id = WorldId::new(b"not_a_real_secret", &Environment::Staging);
    let address_to_verify = Address::random();
    let proof_time: u64 = chrono::Utc::now().timestamp() as u64;

    let proof_context = AddressBook::new()
        .generate_proof_context(address_to_verify.to_string().as_str(), proof_time)
        .unwrap();

    let proof = world_id.generate_proof(&proof_context).await.unwrap();

    let result = address_book
        .verify(
            address_to_verify,
            proof.merkle_root.into(),
            proof.nullifier_hash.into(),
            proof.raw_proof.flatten(),
            U256::from(proof_time),
        )
        .call()
        .await
        .unwrap();
}
