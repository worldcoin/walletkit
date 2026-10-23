//! End-to-end WIP-109 authenticator registration test against staging infrastructure.
//!
//! A Requesting and an Approving Authenticator pair through the staging message-bridge
//! (`staging-bridge.worldcoin.org`), the approver inserts the new authenticator through the
//! staging gateway into the staging `WorldIDRegistry` on World Chain, and the requester verifies
//! the registration against the staging indexer and restarts by leaf index.

#![allow(
    missing_docs,
    clippy::missing_docs_in_private_items,
    reason = "integration tests"
)]

mod common;

use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use alloy::primitives::Address;
use tempfile::TempDir;
use tokio::sync::oneshot;
use walletkit_core::{
    registration::{
        ApprovalOutcome, ApprovalResult, BridgeClient, KnownAuthenticator,
        PendingRegistration, RegistrationPlan, RegistrationRequester, RequestedClass,
        RequesterStatus,
    },
    Authenticator, Environment, Region,
};
use walletkit_testkit::{init_and_register_account, TestEnv};
use world_id_core::artifacts::dummy::DummyZkArtifactSource;

/// Staging message-bridge deployment.
const STAGING_BRIDGE_DOMAIN: &str = "staging-bridge.worldcoin.org";

#[tokio::test(flavor = "multi_thread")]
async fn a_proving_authenticator_registers_through_an_admin_authenticator() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let env = TestEnv::default_staging();
    let root = TempDir::new().expect("failed to create temp storage dir");
    let approver_seed: [u8; 32] = rand::random();
    let requester_seed: [u8; 32] = rand::random();

    let (approver, approver_store) = init_and_register_account(
        &env,
        &approver_seed,
        root.path(),
        Some(Address::ZERO),
    )
    .await
    .expect("staging account registration should succeed");
    let vault = approver_store.export_vault_for_backup().unwrap();
    let leaf_index = approver.leaf_index();

    let bridge = Arc::new(BridgeClient::new(STAGING_BRIDGE_DOMAIN).unwrap());

    // The two devices meet only through the QR code and the pairing code the user types.
    let (uri_tx, uri_rx) = oneshot::channel();
    let (code_tx, code_rx) = oneshot::channel();
    let approving = tokio::spawn(approving_device(
        approver,
        vault,
        bridge.clone(),
        uri_rx,
        code_rx,
    ));
    let requesting = tokio::spawn(requesting_device(
        requester_seed,
        env.rpc_url.clone(),
        bridge,
        uri_tx,
        code_tx,
    ));

    let (approval, registered) = tokio::time::timeout(Duration::from_mins(3), async {
        tokio::join!(approving, requesting)
    })
    .await
    .expect("the registration timed out");
    let approval = approval.unwrap();
    let registered = registered.unwrap();
    assert!(approval.delivered);
    assert!(!approval.vault_omitted);
    assert_eq!(
        approval.result,
        ApprovalResult::Registered {
            leaf_index,
            pubkey_id: 1
        }
    );
    assert_eq!(registered.leaf_index(), leaf_index);

    let restarted = Authenticator::init_with_leaf_index_and_defaults(
        requester_seed.to_vec(),
        leaf_index,
        Some(env.rpc_url),
        &Environment::Staging,
        Some(Region::Us),
        Arc::new(DummyZkArtifactSource),
        common::create_test_credential_store(),
    )
    .await
    .unwrap();
    assert_eq!(restarted.leaf_index(), leaf_index);
}

/// Takes the request from the scanned QR code, checks it with the code the user typed, and
/// approves it with the vault.
async fn approving_device(
    approver: Authenticator,
    vault: Vec<u8>,
    bridge: Arc<BridgeClient>,
    uri: oneshot::Receiver<String>,
    code: oneshot::Receiver<String>,
) -> ApprovalOutcome {
    let pending = PendingRegistration::receive(&uri.await.unwrap(), vec![bridge])
        .await
        .unwrap();
    let incoming = pending.authenticate(&code.await.unwrap()).await.unwrap();
    assert_eq!(incoming.class(), RequestedClass::Proving);
    assert_eq!(incoming.name().as_deref(), Some("Chrome on MacBook"));
    let checked = incoming.check(&approver).await.unwrap();
    assert_eq!(checked.plan(), RegistrationPlan::Insert { pubkey_id: 1 });
    let others = vec![KnownAuthenticator {
        pubkey_id: 0,
        name: "iPhone".to_string(),
    }];
    checked
        .approve(&approver, Some(vault), others)
        .await
        .unwrap()
}

/// Shows the QR code, then the pairing code, verifies the result and imports the vault.
async fn requesting_device(
    seed: [u8; 32],
    rpc_url: String,
    bridge: Arc<BridgeClient>,
    uri: oneshot::Sender<String>,
    code: oneshot::Sender<String>,
) -> Arc<Authenticator> {
    let requester = RegistrationRequester::start(
        seed.to_vec(),
        RequestedClass::Proving,
        Some("Chrome on MacBook".to_string()),
        bridge,
    )
    .await
    .unwrap();
    uri.send(requester.pairing_uri().unwrap()).unwrap();
    assert_eq!(
        poll_past(&requester, &RequesterStatus::Waiting).await,
        RequesterStatus::Retrieved
    );
    assert_eq!(requester.pairing_uri(), None);
    code.send(requester.pairing_code().unwrap()).unwrap();
    let RequesterStatus::Approved { result } =
        poll_past(&requester, &RequesterStatus::Retrieved).await
    else {
        panic!("the registration did not succeed");
    };
    assert_eq!(result.authenticators()[0].name, "iPhone");
    assert!(result.has_vault());
    let store = common::create_test_credential_store();
    let registered = requester
        .verify_with_defaults(
            seed.to_vec(),
            &result,
            Some(rpc_url),
            &Environment::Staging,
            Some(Region::Us),
            Arc::new(DummyZkArtifactSource),
            store.clone(),
        )
        .await
        .unwrap();
    registered.authenticator.init_storage(now()).unwrap();
    store
        .merge_vault_from_backup(&registered.vault_backup.unwrap())
        .unwrap();
    registered.authenticator
}

/// Polls until the status is no longer `current`.
async fn poll_past(
    requester: &RegistrationRequester,
    current: &RequesterStatus,
) -> RequesterStatus {
    loop {
        let status = requester.poll().await.unwrap();
        if status != *current {
            return status;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
