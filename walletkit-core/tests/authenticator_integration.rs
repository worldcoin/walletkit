use alloy::node_bindings::AnvilInstance;
use alloy::primitives::{address, U256};
use alloy::providers::ProviderBuilder;
use alloy::signers::local::PrivateKeySigner;
use alloy_primitives::Address;
use rand::Rng;
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

    let mut rng = rand::thread_rng();

    // Create authenticator with custom config that points to our mock gateway
    let authenticator = Authenticator::from_seed_with_defaults(
        &rng.gen::<[u8; 32]>(),
        anvil.endpoint(),
        &Environment::Staging,
    )
    .unwrap();

    // We don't create the account with `authenticator.create_account` because it uses the gateway,
    // instead for this test we create the account directly on the Anvil fork

    let signer: PrivateKeySigner = anvil.keys()[0].clone().into();
    let provider = ProviderBuilder::new()
        .wallet(signer)
        .connect_http(anvil.endpoint_url());

    let registry = AccountRegistry::new(ACCOUNT_REGISTRY, &provider);

    let tx = registry
        .createAccount(
            address!("0x0000000000000000000000000000000000000001"), // recovery address
            // authenticator addresses
            vec![authenticator
                .onchain_address()
                .await
                .parse::<Address>()
                .unwrap()],
            vec![U256::from(1)], // pubkeys
            U256::from(1),       // commitment
        )
        .send()
        .await
        .unwrap();

    tx.get_receipt().await.unwrap();

    assert!(authenticator.is_registered().await.unwrap());

    let account_id = authenticator.account_id().await.unwrap();
    println!("Created World ID with account ID: {account_id:?}",);
}
