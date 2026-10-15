//! An end-to-end WIP-109 registration. A Requesting and an Approving Authenticator, each in its
//! own task, pair through a message-bridge stub, and the approver inserts the new authenticator
//! into the staging `WorldIDRegistry` on a fork of World Chain. The gateway stub submits the
//! insertion to the fork, and the indexer stub serves the account it built.

#![allow(
    missing_docs,
    clippy::missing_docs_in_private_items,
    clippy::significant_drop_tightening,
    reason = "each stub handler holds its lock for one short request"
)]

mod common;

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use alloy::{
    node_bindings::{Anvil, AnvilInstance},
    primitives::{Address, U256},
    providers::{DynProvider, Provider as _, ProviderBuilder},
    signers::local::PrivateKeySigner,
};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde_json::{json, Value};
use tokio::{net::TcpListener, sync::oneshot};
use walletkit_core::{
    defaults::STAGING_WORLD_ID_REGISTRY,
    registration::{
        ApprovalOutcome, BridgeClient, KnownAuthenticator, PairingCode, PairingUri,
        PendingRegistration, RegistrationPlan, RegistrationRequester, RequestedClass,
        RequesterStatus,
    },
    Authenticator,
};
use world_id_core::{
    api_types::{
        GatewayRequestId, GatewayRequestKind, GatewayRequestState,
        GatewayStatusResponse, IndexerAuthenticatorsResponse,
        InsertAuthenticatorRequest,
    },
    artifacts::dummy::DummyZkArtifactSource,
    primitives::{AuthenticatorPublicKeySet, Config, ServiceEndpoint},
    world_id_registry::WorldIdRegistry::{self, WorldIdRegistryInstance},
    OnchainKeyRepresentable as _, Signer,
};

#[tokio::test(flavor = "multi_thread")]
async fn a_proving_authenticator_registers_through_an_admin_authenticator() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    // Fresh seeds: the fork carries every account ever registered on staging.
    let approver_seed: [u8; 32] = rand::random();
    let requester_seed: [u8; 32] = rand::random();
    let anvil = fork_world_chain();
    let registry = registry(&anvil);
    let account = Arc::new(Mutex::new(create_account(&registry, &approver_seed).await));
    let config = Config::new(
        Some(anvil.endpoint()),
        480,
        STAGING_WORLD_ID_REGISTRY,
        ServiceEndpoint::direct(serve(indexer(account.clone())).await),
        ServiceEndpoint::direct(serve(gateway(registry, account)).await),
        Vec::new(),
        0,
    )
    .unwrap();
    let bridge = BridgeClient::with_base_url(
        "bridge.example".parse().unwrap(),
        serve(bridge()).await.parse().unwrap(),
    )
    .unwrap();

    let approver_store = common::create_test_credential_store();
    let approver = Authenticator::init_with_config(
        &approver_seed,
        config.clone(),
        Arc::new(DummyZkArtifactSource),
        approver_store.clone(),
    )
    .await
    .unwrap();
    approver.init_storage(now()).unwrap();
    let vault = approver_store.export_vault_for_backup().unwrap();
    let leaf_index = approver.leaf_index();

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
        config.clone(),
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
    let result = approval.result.unwrap();
    assert_eq!((result.leaf_index, result.pubkey_id), (leaf_index, 1));
    assert_eq!(registered.leaf_index(), leaf_index);

    let restarted = Authenticator::init_with_leaf_index(
        &requester_seed,
        leaf_index,
        config,
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
    bridge: BridgeClient,
    uri: oneshot::Receiver<String>,
    code: oneshot::Receiver<String>,
) -> ApprovalOutcome {
    let uri: PairingUri = uri.await.unwrap().parse().unwrap();
    let mut pending = PendingRegistration::receive(&uri, &[bridge]).await.unwrap();
    let code: PairingCode = code.await.unwrap().parse().unwrap();
    let incoming = pending.authenticate(&code).await.unwrap();
    assert_eq!(
        incoming.request().name.as_ref().unwrap().as_str(),
        "Chrome on MacBook"
    );
    let checked = incoming.check(&approver).await.unwrap();
    assert_eq!(checked.plan(), RegistrationPlan::Insert { pubkey_id: 1 });
    let others = vec![KnownAuthenticator {
        pubkey_id: 0,
        name: "iPhone".to_string(),
    }];
    checked.approve(&approver, Some(vault.into()), others).await
}

/// Shows the QR code, then the pairing code, verifies the result and imports the vault.
async fn requesting_device(
    seed: [u8; 32],
    config: Config,
    bridge: BridgeClient,
    uri: oneshot::Sender<String>,
    code: oneshot::Sender<String>,
) -> Authenticator {
    let mut requester = RegistrationRequester::start(
        &seed,
        RequestedClass::Proving,
        Some("Chrome on MacBook".to_string().try_into().unwrap()),
        bridge,
    )
    .await
    .unwrap();
    uri.send(requester.pairing_uri().unwrap().to_string())
        .unwrap();
    assert_eq!(
        poll_past(&mut requester, &RequesterStatus::Waiting).await,
        RequesterStatus::Retrieved
    );
    code.send(requester.pairing_code().unwrap().as_str().to_string())
        .unwrap();
    let RequesterStatus::Completed(Ok(result)) =
        poll_past(&mut requester, &RequesterStatus::Retrieved).await
    else {
        panic!("the registration did not succeed");
    };
    assert_eq!(result.authenticators[0].name, "iPhone");
    let store = common::create_test_credential_store();
    let registered = requester
        .verify(
            &seed,
            result,
            config,
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
    requester: &mut RegistrationRequester,
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

fn fork_world_chain() -> AnvilInstance {
    dotenvy::dotenv().ok();
    let rpc_url = std::env::var("WORLDCHAIN_RPC_URL")
        .unwrap_or_else(|_| "https://rpc.worldchain.worldcoin.org".to_string());
    Anvil::new().fork(rpc_url).spawn()
}

fn registry(anvil: &AnvilInstance) -> WorldIdRegistryInstance<DynProvider> {
    let signer: PrivateKeySigner = anvil.keys()[0].clone().into();
    let provider = ProviderBuilder::new()
        .wallet(signer)
        .connect_http(anvil.endpoint_url())
        .erased();
    WorldIdRegistry::new(STAGING_WORLD_ID_REGISTRY, provider)
}

/// Creates the approver's account directly on the registry, with the approver as its only
/// authenticator, and returns the account as the indexer serves it.
async fn create_account(
    registry: &WorldIdRegistryInstance<DynProvider>,
    seed: &[u8],
) -> IndexerAuthenticatorsResponse {
    let signer = Signer::from_seed_bytes(seed).unwrap();
    let pubkey = signer.offchain_signer_pubkey();
    let commitment: U256 = AuthenticatorPublicKeySet::new(vec![pubkey.clone()])
        .unwrap()
        .leaf_hash()
        .into();
    let encoded = pubkey.to_ethereum_representation().unwrap();
    registry
        .createAccount(
            Address::with_last_byte(1),
            vec![signer.onchain_signer_address()],
            vec![encoded],
            commitment,
        )
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();
    IndexerAuthenticatorsResponse {
        authenticator_pubkeys: vec![Some(encoded)],
        authenticator_addresses: vec![Some(signer.onchain_signer_address())],
        offchain_signer_commitment: commitment,
        recovery_counter: 0,
    }
}

/// Serves `app` on a random local port and returns its URL.
async fn serve(app: Router) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    url
}

type Account = Arc<Mutex<IndexerAuthenticatorsResponse>>;

/// Serves the one account's authenticators, whatever leaf index is asked for.
fn indexer(account: Account) -> Router {
    Router::new()
        .route(
            "/authenticators",
            post(|State(account): State<Account>| async move {
                let account = account.lock().unwrap();
                Json(IndexerAuthenticatorsResponse {
                    authenticator_pubkeys: account.authenticator_pubkeys.clone(),
                    authenticator_addresses: account.authenticator_addresses.clone(),
                    ..*account
                })
            }),
        )
        .with_state(account)
}

/// Submits insertions to the registry and records them in the account, as the gateway and the
/// indexer would once the transaction is final.
fn gateway(registry: WorldIdRegistryInstance<DynProvider>, account: Account) -> Router {
    let insert = |State((registry, account)): State<(
        WorldIdRegistryInstance<DynProvider>,
        Account,
    )>,
                  Json(request): Json<InsertAuthenticatorRequest>| async move {
        let receipt = registry
            .insertAuthenticator(
                request.leaf_index,
                request.new_authenticator_address,
                request.pubkey_id,
                request.new_authenticator_pubkey,
                request.old_offchain_signer_commitment,
                request.new_offchain_signer_commitment,
                request.signature.as_bytes().to_vec().into(),
                request.nonce,
            )
            .send()
            .await
            .map_err(|error| (StatusCode::BAD_REQUEST, error.to_string()))?
            .get_receipt()
            .await
            .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;
        let mut account = account.lock().unwrap();
        let slot = request.pubkey_id as usize;
        account.authenticator_pubkeys.resize(slot + 1, None);
        account.authenticator_addresses.resize(slot + 1, None);
        account.authenticator_pubkeys[slot] = Some(request.new_authenticator_pubkey);
        account.authenticator_addresses[slot] = Some(request.new_authenticator_address);
        account.offchain_signer_commitment = request.new_offchain_signer_commitment;
        Ok::<_, (StatusCode, String)>(Json(status(
            receipt.transaction_hash.to_string(),
        )))
    };
    Router::new()
        .route("/insert-authenticator", post(insert))
        .route(
            "/status/{id}",
            get(|Path(id): Path<String>| async move { Json(status(id)) }),
        )
        .with_state((registry, account))
}

/// A finalized insertion, identified by its transaction hash.
fn status(tx_hash: String) -> GatewayStatusResponse {
    GatewayStatusResponse {
        request_id: GatewayRequestId::new(tx_hash.clone()),
        kind: GatewayRequestKind::InsertAuthenticator,
        status: GatewayRequestState::Finalized { tx_hash },
    }
}

/// A session on the bridge stub, keyed by its request id.
enum Session {
    Initialized(Value),
    Retrieved,
    Completed(Value),
}

type Sessions = Arc<Mutex<HashMap<String, Session>>>;

/// The message-bridge routes, with single-use reads and a session that ends once its response
/// is read.
fn bridge() -> Router {
    Router::new()
        .route("/request", post(publish_request))
        .route("/request/{id}", get(take_request))
        .route("/response/{id}", get(fetch_response).put(put_response))
        .with_state(Sessions::default())
}

async fn publish_request(
    State(sessions): State<Sessions>,
    Json(mut body): Json<Value>,
) -> StatusCode {
    let id = body["request_id"].as_str().unwrap().to_string();
    body.as_object_mut().unwrap().remove("request_id");
    sessions
        .lock()
        .unwrap()
        .insert(id, Session::Initialized(body));
    StatusCode::OK
}

async fn take_request(
    State(sessions): State<Sessions>,
    Path(id): Path<String>,
) -> Result<Json<Value>, StatusCode> {
    let mut sessions = sessions.lock().unwrap();
    match sessions.remove(&id) {
        Some(Session::Initialized(request)) => {
            sessions.insert(id, Session::Retrieved);
            Ok(Json(request))
        }
        _ => Err(StatusCode::NOT_FOUND),
    }
}

async fn fetch_response(
    State(sessions): State<Sessions>,
    Path(id): Path<String>,
) -> Result<Json<Value>, StatusCode> {
    let mut sessions = sessions.lock().unwrap();
    let body = match sessions.get(&id).ok_or(StatusCode::NOT_FOUND)? {
        Session::Initialized(_) => json!({ "status": "initialized", "response": null }),
        Session::Retrieved => json!({ "status": "retrieved", "response": null }),
        Session::Completed(response) => {
            let body = json!({ "status": "completed", "response": response });
            sessions.remove(&id);
            body
        }
    };
    Ok(Json(body))
}

async fn put_response(
    State(sessions): State<Sessions>,
    Path(id): Path<String>,
    Json(response): Json<Value>,
) -> StatusCode {
    let mut sessions = sessions.lock().unwrap();
    match sessions.get(&id) {
        Some(Session::Initialized(_) | Session::Retrieved) => {
            sessions.insert(id, Session::Completed(response));
            StatusCode::CREATED
        }
        Some(Session::Completed(_)) => StatusCode::CONFLICT,
        None => StatusCode::BAD_REQUEST,
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
