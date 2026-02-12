#![cfg(feature = "storage")]

mod common;

use alloy::node_bindings::AnvilInstance;
use alloy::primitives::{address, U256};
use alloy::providers::ProviderBuilder;
use alloy::signers::local::PrivateKeySigner;
use walletkit_core::error::WalletKitError;
use walletkit_core::{Authenticator, Environment};
use world_id_core::world_id_registry::WorldIdRegistry;

const WORLD_ID_REGISTRY: alloy::primitives::Address =
    address!("0x969947cFED008bFb5e3F32a25A1A2CDdf64d46fe");

fn setup_anvil() -> AnvilInstance {
    dotenvy::dotenv().ok();
    let rpc_url = std::env::var("WORLDCHAIN_RPC_URL")
        .unwrap_or_else(|_| "https://worldchain-mainnet.g.alchemy.com/public".to_string());

    let anvil = alloy::node_bindings::Anvil::new().fork(rpc_url).spawn();
    println!(
        "✓ Anvil started for World Chain Mainnet at: {}",
        anvil.endpoint()
    );
    anvil
}

#[tokio::test]
async fn test_authenticator_integration() {
    // Install default crypto provider for rustls
    let _ = rustls::crypto::ring::default_provider().install_default();

    let anvil = setup_anvil();

    let authenticator_seeder = PrivateKeySigner::random();
    let store = common::create_test_credential_store();

    // When account doesn't exist, this should fail
    let authenticator = Authenticator::init_with_defaults(
        authenticator_seeder.to_bytes().as_slice(),
        Some(anvil.endpoint()),
        &Environment::Staging,
        store.clone(),
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

    let registry = WorldIdRegistry::new(WORLD_ID_REGISTRY, &provider);

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
        store,
    )
    .await
    .unwrap();
    let packed_account_data = authenticator.packed_account_data();
    println!("Created World ID with packed account data: {packed_account_data:?}",);
}
