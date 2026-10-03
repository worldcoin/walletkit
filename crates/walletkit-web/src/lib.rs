//! Browser facade over `WalletKit`, exported with `wasm-bindgen`.
//!
//! The `walletkit-web` npm package runs this module inside a dedicated Web Worker.
//! Rust objects never cross into JavaScript: [`WalletKit`] owns the credential store,
//! the pending registration and the authenticator, and every method returns plain
//! structured-clone data that the worker can post back to the page.

#![cfg(all(target_arch = "wasm32", target_os = "unknown"))]

mod error;
mod js;

use std::{cell::RefCell, rc::Rc, str::FromStr, sync::Arc};

use js_sys::Promise;
use walletkit_core::{
    authenticator::{
        artifacts::embedded::EmbeddedZkArtifacts, recovery_data_from_seed,
    },
    requests::ProofRequest,
    storage::{
        initialize_persistent_storage, CredentialStore, StorageKeys, StoragePaths,
    },
    Authenticator, Credential, Environment, FieldElement, InitializingAuthenticator,
    Region, RegistrationStatus,
};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;

use crate::error::{invalid_state, to_js};

#[wasm_bindgen(typescript_custom_section)]
const TS_TYPES: &str = r#"
export interface RecoveryData {
  authenticatorAddress: string;
  authenticatorPubkey: string;
  offchainSignerCommitment: string;
}

export type RegistrationStatus =
  | { state: "queued" | "batching" | "submitted" | "finalized" }
  | { state: "failed"; error: string; errorCode?: string };

export interface PreparedCredential {
  blindingFactor: string;
  sub: string;
}

export interface StoredCredential {
  credentialId: bigint;
  issuerSchemaId: bigint;
}
"#;

/// Forwards Rust panics to the console before the module traps.
///
/// A panic leaves the instance unusable; the worker reports the resulting
/// `WebAssembly.RuntimeError` and refuses further calls.
#[wasm_bindgen(start)]
fn start() {
    std::panic::set_hook(Box::new(|info| js::console_error(&info.to_string())));
}

/// Derives the recovery identity material for a 32-byte seed.
///
/// # Errors
/// Throws a `WalletKitError` when the seed is invalid.
#[wasm_bindgen(js_name = recoveryDataFromSeed, unchecked_return_type = "RecoveryData")]
pub fn recovery_data_from_seed_js(seed: Vec<u8>) -> Result<JsValue, JsValue> {
    let data = recovery_data_from_seed(seed).map_err(to_js)?;
    js::object(&[
        ("authenticatorAddress", data.authenticator_address.into()),
        ("authenticatorPubkey", data.authenticator_pubkey.into()),
        (
            "offchainSignerCommitment",
            data.offchain_signer_commitment.into(),
        ),
    ])
}

/// A `WalletKit` account opened in this worker.
#[wasm_bindgen]
pub struct WalletKit {
    state: Rc<RefCell<State>>,
}

struct State {
    environment: Environment,
    region: Region,
    rpc_url: Option<String>,
    store: Option<Arc<CredentialStore>>,
    registration: Option<Arc<InitializingAuthenticator>>,
    authenticator: Option<Arc<Authenticator>>,
}

impl State {
    fn store(&self) -> Result<Arc<CredentialStore>, JsValue> {
        self.store
            .clone()
            .ok_or_else(|| invalid_state("WalletKit is closed"))
    }

    fn authenticator(&self) -> Result<Arc<Authenticator>, JsValue> {
        self.authenticator
            .clone()
            .ok_or_else(|| invalid_state("Initialize the authenticator first"))
    }
}

#[wasm_bindgen]
impl WalletKit {
    /// Acquires the OPFS storage pool and opens the encrypted credential store.
    ///
    /// `storage_id` selects the account namespace and `database_key` is the
    /// resolved 32-byte database key. `environment` is `"production"` or
    /// `"staging"`, and `region` is `"eu"`, `"us"` or `"ap"`.
    ///
    /// # Errors
    /// Rejects when an argument is invalid, outside a dedicated worker, when another
    /// context owns the storage pool, or when the store cannot be opened.
    #[wasm_bindgen(unchecked_return_type = "Promise<WalletKit>")]
    pub fn open(
        storage_id: String,
        database_key: Vec<u8>,
        environment: &str,
        region: &str,
        rpc_url: Option<String>,
    ) -> Promise {
        let config = parse_config(&storage_id, environment, region);
        future_to_promise(async move {
            let (environment, region) = config?;
            let keys = StorageKeys::from_bytes(database_key).map_err(to_js)?;
            initialize_persistent_storage().await.map_err(to_js)?;
            let paths = StoragePaths::from_root(format!("/walletkit/{storage_id}"));
            let store =
                CredentialStore::new(Arc::new(paths), Arc::new(keys)).map_err(to_js)?;

            Ok(Self {
                state: Rc::new(RefCell::new(State {
                    environment,
                    region,
                    rpc_url,
                    store: Some(Arc::new(store)),
                    registration: None,
                    authenticator: None,
                })),
            }
            .into())
        })
    }

    /// Submits a new World ID registration for `seed`.
    ///
    /// # Errors
    /// Rejects when a registration is already pending or the gateway call fails.
    #[wasm_bindgen(unchecked_return_type = "Promise<void>")]
    pub fn register(&self, seed: Vec<u8>) -> Promise {
        let state = Rc::clone(&self.state);
        future_to_promise(async move {
            let (environment, region, rpc_url) = {
                let s = state.borrow();
                s.store()?;
                if s.registration.is_some() {
                    return Err(invalid_state("Registration already started"));
                }
                (s.environment.clone(), s.region, s.rpc_url.clone())
            };

            let registration = InitializingAuthenticator::register_with_defaults(
                seed,
                rpc_url,
                &environment,
                Some(region),
                None,
            )
            .await
            .map_err(to_js)?;

            state.borrow_mut().registration = Some(Arc::new(registration));
            Ok(JsValue::UNDEFINED)
        })
    }

    /// Polls the status of the pending registration.
    ///
    /// # Errors
    /// Rejects when no registration was started or the gateway call fails.
    #[wasm_bindgen(js_name = pollRegistration, unchecked_return_type = "Promise<RegistrationStatus>")]
    pub fn poll_registration(&self) -> Promise {
        let state = Rc::clone(&self.state);
        future_to_promise(async move {
            let registration = state
                .borrow()
                .registration
                .clone()
                .ok_or_else(|| invalid_state("Start registration first"))?;

            let status = match registration.poll_status().await.map_err(to_js)? {
                RegistrationStatus::Queued => js::object(&[("state", "queued".into())]),
                RegistrationStatus::Batching => {
                    js::object(&[("state", "batching".into())])
                }
                RegistrationStatus::Submitted => {
                    js::object(&[("state", "submitted".into())])
                }
                RegistrationStatus::Finalized => {
                    js::object(&[("state", "finalized".into())])
                }
                RegistrationStatus::Failed { error, error_code } => js::object(&[
                    ("state", "failed".into()),
                    ("error", error.into()),
                    (
                        "errorCode",
                        error_code.map_or(JsValue::UNDEFINED, Into::into),
                    ),
                ]),
            }?;
            Ok(status)
        })
    }

    /// Opens the authenticator for an already registered `seed`.
    ///
    /// `now` is the current unix time in seconds.
    ///
    /// # Errors
    /// Rejects when the authenticator is already open, the account does not exist,
    /// or storage initialization fails.
    #[wasm_bindgen(js_name = initializeAuthenticator, unchecked_return_type = "Promise<void>")]
    pub fn initialize_authenticator(&self, seed: Vec<u8>, now: u64) -> Promise {
        let state = Rc::clone(&self.state);
        future_to_promise(async move {
            let (environment, region, rpc_url, store) = {
                let s = state.borrow();
                if s.authenticator.is_some() {
                    return Err(invalid_state("Authenticator is already initialized"));
                }
                (
                    s.environment.clone(),
                    s.region,
                    s.rpc_url.clone(),
                    s.store()?,
                )
            };

            let artifacts =
                Arc::new(EmbeddedZkArtifacts::new()).as_zk_artifact_source();
            let authenticator = Authenticator::init_with_defaults(
                seed,
                rpc_url,
                &environment,
                Some(region),
                artifacts,
                store,
            )
            .await
            .map_err(to_js)?;
            authenticator.init_storage(now).map_err(to_js)?;

            let mut s = state.borrow_mut();
            // `close()` may have run while the network call was pending.
            s.store()?;
            s.authenticator = Some(Arc::new(authenticator));
            Ok(JsValue::UNDEFINED)
        })
    }

    /// Obtains a credential blinding factor and the matching `sub` for an issuer.
    ///
    /// # Errors
    /// Rejects when the authenticator is not initialized or the OPRF call fails.
    #[wasm_bindgen(js_name = prepareCredential, unchecked_return_type = "Promise<PreparedCredential>")]
    pub fn prepare_credential(&self, issuer_schema_id: u64) -> Promise {
        let state = Rc::clone(&self.state);
        future_to_promise(async move {
            let authenticator = state.borrow().authenticator()?;
            let factor = authenticator
                .generate_credential_blinding_factor_remote(issuer_schema_id)
                .await
                .map_err(to_js)?;
            let sub = authenticator.compute_credential_sub(&factor);

            js::object(&[
                ("blindingFactor", factor.to_hex_string().into()),
                ("sub", sub.to_hex_string().into()),
            ])
        })
    }

    /// Stores serialized credential bytes with the blinding factor from
    /// [`WalletKit::prepare_credential`].
    ///
    /// # Errors
    /// Throws when the authenticator is not initialized, the inputs are malformed,
    /// or the credential cannot be stored.
    #[wasm_bindgen(js_name = storeCredential, unchecked_return_type = "StoredCredential")]
    pub fn store_credential(
        &self,
        credential: Vec<u8>,
        blinding_factor: &str,
        now: u64,
    ) -> Result<JsValue, JsValue> {
        let store = {
            let s = self.state.borrow();
            s.authenticator()?;
            s.store()?
        };

        let credential = Credential::from_bytes(credential).map_err(to_js)?;
        let blinding_factor =
            FieldElement::try_from_hex_string(blinding_factor).map_err(to_js)?;
        let credential_id = store
            .store_credential(
                &credential,
                &blinding_factor,
                credential.expires_at(),
                None,
                now,
            )
            .map_err(to_js)?;

        js::object(&[
            ("credentialId", credential_id.into()),
            ("issuerSchemaId", credential.issuer_schema_id().into()),
        ])
    }

    /// Generates a proof for a JSON proof request and returns the JSON response.
    ///
    /// # Errors
    /// Rejects when the authenticator is not initialized, the request is malformed,
    /// or proof generation fails.
    #[wasm_bindgen(js_name = generateProof, unchecked_return_type = "Promise<string>")]
    pub fn generate_proof(&self, request: String, now: u64) -> Promise {
        let state = Rc::clone(&self.state);
        future_to_promise(async move {
            let authenticator = state.borrow().authenticator()?;
            let request = ProofRequest::from_json(&request).map_err(to_js)?;
            let response = authenticator
                .generate_proof(&request, Some(now))
                .await
                .map_err(to_js)?;
            Ok(response.to_json().map_err(to_js)?.into())
        })
    }

    /// Releases the authenticator, registration and credential store.
    ///
    /// Further calls fail. The OPFS pool stays owned until the worker terminates.
    pub fn close(&self) {
        let mut s = self.state.borrow_mut();
        s.authenticator = None;
        s.registration = None;
        s.store = None;
    }
}

fn parse_config(
    storage_id: &str,
    environment: &str,
    region: &str,
) -> Result<(Environment, Region), JsValue> {
    let valid_id = (1..=128).contains(&storage_id.len())
        && storage_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
    if !valid_id {
        return Err(error::invalid_argument(
            "Invalid storageId: use 1–128 letters, digits, underscores or hyphens",
        ));
    }

    let environment = Environment::from_str(environment).map_err(|_| {
        error::invalid_argument(&format!("Unknown environment: {environment}"))
    })?;
    let region = Region::from_str(region)
        .map_err(|_| error::invalid_argument(&format!("Unknown region: {region}")))?;
    Ok((environment, region))
}

/// Hooks for the browser storage tests, which run without network registration.
#[cfg(feature = "test-hooks")]
#[wasm_bindgen]
impl WalletKit {
    /// Binds the credential store to `leaf_index`, as authenticator initialization does.
    ///
    /// # Errors
    /// Throws when the store is closed or cannot be initialized.
    #[wasm_bindgen(js_name = testInitStorage)]
    pub fn test_init_storage(&self, leaf_index: u64, now: u64) -> Result<(), JsValue> {
        self.state
            .borrow()
            .store()?
            .init(leaf_index, now)
            .map_err(to_js)
    }
}
