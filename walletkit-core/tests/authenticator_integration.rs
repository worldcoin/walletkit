use std::time::Duration;

use alloy::node_bindings::AnvilInstance;
use walletkit_core::{Authenticator, Environment};

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

    let seed = [2u8; 32];
    let authenticator = Authenticator::from_seed_with_defaults(
        &seed,
        anvil.endpoint(),
        &Environment::Staging,
    )
    .unwrap();

    authenticator
        .create_account(Some(
            "0x0000000000000000000000000000000000000001".to_string(),
        ))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_secs(5)).await;
    dbg!(authenticator.account_id().await.unwrap());
}
