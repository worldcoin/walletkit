use alloy::node_bindings::AnvilInstance;
use alloy::primitives::{address, U256};
use alloy::providers::ProviderBuilder;
use alloy::signers::local::PrivateKeySigner;
use walletkit_core::error::WalletKitError;
use walletkit_core::{Authenticator, Environment};
use world_id_core::account_registry::AccountRegistry;

const ACCOUNT_REGISTRY: alloy::primitives::Address =
    address!("0xd66aFbf92d684B4404B1ed3e9aDA85353c178dE2");

fn setup_anvil() -> AnvilInstance {
    dotenvy::dotenv().ok();
    let rpc_url = std::env::var("WORLDCHAIN_RPC_URL").expect(
        "WORLDCHAIN_RPC_URL not set. Copy .env.example to .env and add your RPC URL",
    );

    let anvil = alloy::node_bindings::Anvil::new().fork(rpc_url).spawn();
    println!(
        "✓ Anvil started for World Chain Mainnet at: {}",
        anvil.endpoint()
    );
    anvil
}

#[tokio::test]
async fn test_authenticator_integration() {
    let anvil = setup_anvil();

    let authenticator_seeder = PrivateKeySigner::random();

    // When account doesn't exist, this should fail
    let authenticator = Authenticator::init_with_defaults(
        authenticator_seeder.to_bytes().as_slice(),
        Some(anvil.endpoint()),
        &Environment::Staging,
    )
    .await
    .unwrap_err();
    assert!(matches!(authenticator, WalletKitError::AccountDoesNotExist));

    // We don't create the account with the internal to avoid having to mock the gateway,
    // we simply call the createAccount function directly on the AccountRegistry

    let signer: PrivateKeySigner = anvil.keys()[0].clone().into();
    let provider = ProviderBuilder::new()
        .wallet(signer)
        .connect_http(anvil.endpoint_url());

    let registry = AccountRegistry::new(ACCOUNT_REGISTRY, &provider);

    let tx = registry
        .createAccount(
            address!("0x0000000000000000000000000000000000000001"), // recovery address
            vec![authenticator_seeder.address()],
            vec![U256::from(1)], // pubkeys
            U256::from(1),       // commitment
        )
        .send()
        .await
        .unwrap();

    tx.get_receipt().await.unwrap();

    // now the authenticator exists
    let authenticator = Authenticator::init_with_defaults(
        authenticator_seeder.to_bytes().as_slice(),
        Some(anvil.endpoint()),
        &Environment::Staging,
    )
    .await
    .unwrap();
    let packed_account_data = authenticator.packed_account_data();
    println!("Created World ID with packed account data: {packed_account_data:?}",);
}
