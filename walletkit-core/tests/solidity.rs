use std::sync::Arc;

use alloy::{
    providers::{ProviderBuilder, WalletProvider},
    sol,
    sol_types::SolValue,
};
use walletkit_core::{credential_type::CredentialType, proof::Context};

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    ExternalNullifier,
    "tests/out/external_nullifier.sol/ExternalNullifier.json"
);

#[tokio::test]
async fn test_advanced_external_nullifier_generation_on_chain() {
    let provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .on_anvil_with_wallet();

    let app_id = "app_10eb12bd96d8f7202892ff25f094c803".to_string();

    let addr = provider.default_signer_address();

    let contract = ExternalNullifier::deploy(&provider, app_id.clone())
        .await
        .unwrap();

    let contract = contract.clone();

    let custom_action =
        [addr.abi_encode_packed(), "test_text".abi_encode_packed()].concat();

    let context = Context::new_from_bytes(
        &app_id,
        Some(custom_action),
        None,
        Arc::new(CredentialType::Orb),
    );

    let nullifier = contract
        .generateExternalNullifier("test_text".to_string())
        .from(addr)
        .call()
        .await
        .unwrap()
        ._0;

    assert_eq!(nullifier, *context.external_nullifier);
}
