//! The World ID authenticator and its registration flow.

use std::{str::FromStr, sync::Arc};

use js_sys::{Promise, Reflect};
use walletkit_core::{
    authenticator::{
        artifacts::embedded::EmbeddedZkArtifacts, validate_authenticator_pubkey,
        GatewayRequestStatus,
    },
    Authenticator, Environment, InitializingAuthenticator, Region, RegistrationStatus,
};
use wasm_bindgen::prelude::*;

use crate::{
    error::{invalid_argument, to_js},
    js,
    storage::JsCredentialStore,
    values::{JsFieldElement, JsProofRequest, JsProofResponse},
};

fn parse_environment(environment: &str) -> Result<Environment, JsValue> {
    Environment::from_str(environment)
        .map_err(|_| invalid_argument(&format!("Unknown environment: {environment}")))
}

fn parse_region(region: Option<String>) -> Result<Option<Region>, JsValue> {
    region
        .map(|region| {
            Region::from_str(&region)
                .map_err(|_| invalid_argument(&format!("Unknown region: {region}")))
        })
        .transpose()
}

/// The recovery agent address contract for `environment`.
///
/// # Errors
/// Throws a `TypeError` for an unknown environment.
#[wasm_bindgen(js_name = pohRecoveryAgentAddress)]
pub fn poh_recovery_agent_address(
    #[wasm_bindgen(unchecked_param_type = "Environment")] environment: &str,
) -> Result<String, JsValue> {
    Ok(parse_environment(environment)?.poh_recovery_agent_address())
}

/// The World ID verifier contract address for `environment`.
///
/// # Errors
/// Throws a `TypeError` for an unknown environment.
#[wasm_bindgen(js_name = worldIdVerifierAddress)]
pub fn world_id_verifier_address(
    #[wasm_bindgen(unchecked_param_type = "Environment")] environment: &str,
) -> Result<String, JsValue> {
    Ok(parse_environment(environment)?.world_id_verifier_address())
}

/// Checks that `authenticator_pubkey` is a valid key and returns its canonical encoding.
///
/// # Errors
/// Throws a `WalletKitError` when the key is invalid.
#[wasm_bindgen(js_name = validateAuthenticatorPubkey)]
pub fn validate_authenticator_pubkey_js(
    authenticator_pubkey: &str,
) -> Result<String, JsValue> {
    validate_authenticator_pubkey(authenticator_pubkey).map_err(to_js)
}

/// Proving material compiled into the module.
#[wasm_bindgen(js_name = EmbeddedZkArtifacts)]
pub struct JsEmbeddedZkArtifacts(Arc<EmbeddedZkArtifacts>);

#[wasm_bindgen(js_class = EmbeddedZkArtifacts)]
impl JsEmbeddedZkArtifacts {
    #[wasm_bindgen(constructor)]
    #[must_use]
    pub fn new() -> Self {
        Self(Arc::new(EmbeddedZkArtifacts::new()))
    }
}

impl Default for JsEmbeddedZkArtifacts {
    fn default() -> Self {
        Self::new()
    }
}

/// The main component with which users interact with the World ID Protocol.
#[wasm_bindgen(js_name = Authenticator)]
pub struct JsAuthenticator(Arc<Authenticator>);

#[wasm_bindgen(js_class = Authenticator)]
impl JsAuthenticator {
    /// Opens the authenticator for a registered `seed` using the environment defaults.
    ///
    /// `environment` is `"production"` or `"staging"`, and `region` is `"eu"`, `"us"` or `"ap"`.
    ///
    /// # Errors
    /// Rejects when an argument is invalid, the account does not exist, or the network call fails.
    #[wasm_bindgen(js_name = initWithDefaults, unchecked_return_type = "Promise<Authenticator>")]
    pub fn init_with_defaults(
        seed: Vec<u8>,
        rpc_url: Option<String>,
        #[wasm_bindgen(unchecked_param_type = "Environment")] environment: &str,
        #[wasm_bindgen(unchecked_param_type = "Region | undefined")] region: Option<
            String,
        >,
        artifacts: &JsEmbeddedZkArtifacts,
        store: &JsCredentialStore,
    ) -> Promise {
        let environment = parse_environment(environment);
        let region = parse_region(region);
        let artifacts = Arc::clone(&artifacts.0).as_zk_artifact_source();
        let store = Arc::clone(&store.0);
        js::promise(async move {
            let authenticator = Authenticator::init_with_defaults(
                seed,
                rpc_url,
                &environment?,
                region?,
                artifacts,
                store,
            )
            .await
            .map_err(to_js)?;
            Ok(Self(Arc::new(authenticator)).into())
        })
    }

    /// Like [`Self::init_with_defaults`], routing gateway traffic through OHTTP.
    ///
    /// # Errors
    /// Rejects when an argument is invalid, the account does not exist, or the network call fails.
    #[wasm_bindgen(js_name = initWithOhttpDefaults, unchecked_return_type = "Promise<Authenticator>")]
    pub fn init_with_ohttp_defaults(
        seed: Vec<u8>,
        rpc_url: Option<String>,
        #[wasm_bindgen(unchecked_param_type = "Environment")] environment: &str,
        #[wasm_bindgen(unchecked_param_type = "Region | undefined")] region: Option<
            String,
        >,
        artifacts: &JsEmbeddedZkArtifacts,
        store: &JsCredentialStore,
    ) -> Promise {
        let environment = parse_environment(environment);
        let region = parse_region(region);
        let artifacts = Arc::clone(&artifacts.0).as_zk_artifact_source();
        let store = Arc::clone(&store.0);
        js::promise(async move {
            let authenticator = Authenticator::init_with_ohttp_defaults(
                seed,
                rpc_url,
                &environment?,
                region?,
                artifacts,
                store,
            )
            .await
            .map_err(to_js)?;
            Ok(Self(Arc::new(authenticator)).into())
        })
    }

    /// Opens the authenticator for a registered `seed` with an explicit JSON `config`.
    ///
    /// # Errors
    /// Rejects when the config is invalid, the account does not exist, or the network call fails.
    #[wasm_bindgen(js_name = init, unchecked_return_type = "Promise<Authenticator>")]
    pub fn init(
        seed: Vec<u8>,
        config: String,
        artifacts: &JsEmbeddedZkArtifacts,
        store: &JsCredentialStore,
    ) -> Promise {
        let artifacts = Arc::clone(&artifacts.0).as_zk_artifact_source();
        let store = Arc::clone(&store.0);
        js::promise(async move {
            let authenticator = Authenticator::init(seed, &config, artifacts, store)
                .await
                .map_err(to_js)?;
            Ok(Self(Arc::new(authenticator)).into())
        })
    }

    /// Binds the credential store to this account.
    ///
    /// # Errors
    /// Throws a `WalletKitError` when the store belongs to a different account.
    #[wasm_bindgen(js_name = initStorage)]
    pub fn init_storage(&self, now: u64) -> Result<(), JsValue> {
        self.0.init_storage(now).map_err(to_js)
    }

    /// Deletes the credential store.
    ///
    /// # Errors
    /// Throws a `WalletKitError` when a file cannot be deleted.
    #[wasm_bindgen(js_name = destroyStorage)]
    pub fn destroy_storage(&self) -> Result<(), JsValue> {
        self.0.destroy_storage().map_err(to_js)
    }

    /// The packed account data as a 0x-prefixed, zero-padded 256-bit hex string.
    #[wasm_bindgen(js_name = packedAccountData)]
    #[must_use]
    pub fn packed_account_data(&self) -> String {
        self.0.packed_account_data().to_padded_hex_string()
    }

    #[wasm_bindgen(js_name = leafIndex)]
    #[must_use]
    pub fn leaf_index(&self) -> u64 {
        self.0.leaf_index()
    }

    #[wasm_bindgen(js_name = onchainAddress)]
    #[must_use]
    pub fn onchain_address(&self) -> String {
        self.0.onchain_address()
    }

    /// Fetches the packed account data from the on-chain registry.
    ///
    /// # Errors
    /// Rejects when the RPC call fails.
    #[wasm_bindgen(js_name = getPackedAccountDataRemote, unchecked_return_type = "Promise<string>")]
    pub fn get_packed_account_data_remote(&self) -> Promise {
        let authenticator = Arc::clone(&self.0);
        js::promise(async move {
            let data = authenticator
                .get_packed_account_data_remote()
                .await
                .map_err(to_js)?;
            Ok(data.to_padded_hex_string().into())
        })
    }

    /// Generates a credential blinding factor through the OPRF nodes.
    ///
    /// # Errors
    /// Rejects when the OPRF call fails.
    #[wasm_bindgen(js_name = generateCredentialBlindingFactorRemote, unchecked_return_type = "Promise<FieldElement>")]
    pub fn generate_credential_blinding_factor_remote(
        &self,
        issuer_schema_id: u64,
    ) -> Promise {
        let authenticator = Arc::clone(&self.0);
        js::promise(async move {
            let factor = authenticator
                .generate_credential_blinding_factor_remote(issuer_schema_id)
                .await
                .map_err(to_js)?;
            Ok(JsFieldElement(factor).into())
        })
    }

    /// Computes the credential `sub` from the leaf index and a blinding factor.
    #[wasm_bindgen(js_name = computeCredentialSub)]
    #[must_use]
    pub fn compute_credential_sub(
        &self,
        blinding_factor: &JsFieldElement,
    ) -> JsFieldElement {
        JsFieldElement(self.0.compute_credential_sub(&blinding_factor.0))
    }

    /// Signs `challenge` with the on-chain key. Reveals the leaf index to the verifier.
    ///
    /// # Errors
    /// Throws a `WalletKitError` when signing fails.
    #[wasm_bindgen(js_name = dangerSignChallenge)]
    pub fn danger_sign_challenge(
        &self,
        challenge: Vec<u8>,
    ) -> Result<Vec<u8>, JsValue> {
        self.0.danger_sign_challenge(challenge).map_err(to_js)
    }

    /// # Errors
    /// Rejects when the address is invalid or the signing request fails.
    #[wasm_bindgen(js_name = dangerSignInitiateRecoveryAgentUpdate, unchecked_return_type = "Promise<RecoveryUpdateSignature>")]
    pub fn danger_sign_initiate_recovery_agent_update(
        &self,
        new_recovery_agent: String,
    ) -> Promise {
        let authenticator = Arc::clone(&self.0);
        js::promise(async move {
            let update = authenticator
                .danger_sign_initiate_recovery_agent_update(new_recovery_agent)
                .await
                .map_err(to_js)?;
            js::object(&[
                (
                    "signature",
                    js_sys::Uint8Array::from(update.signature.as_slice()).into(),
                ),
                ("nonce", update.nonce.to_padded_hex_string().into()),
            ])
        })
    }

    /// Submits a recovery agent update and returns the gateway request ID.
    ///
    /// # Errors
    /// Rejects when the address is invalid or the gateway call fails.
    #[wasm_bindgen(js_name = updateRecoveryAgent, unchecked_return_type = "Promise<string>")]
    pub fn update_recovery_agent(&self, new_recovery_agent: String) -> Promise {
        let authenticator = Arc::clone(&self.0);
        js::promise(async move {
            let request_id = authenticator
                .update_recovery_agent(new_recovery_agent)
                .await
                .map_err(to_js)?;
            Ok(request_id.into())
        })
    }

    /// Cancels a pending recovery agent update and returns the gateway request ID.
    ///
    /// # Errors
    /// Rejects when the gateway call fails.
    #[wasm_bindgen(js_name = revertRecoveryAgentUpdate, unchecked_return_type = "Promise<string>")]
    pub fn revert_recovery_agent_update(&self) -> Promise {
        let authenticator = Arc::clone(&self.0);
        js::promise(async move {
            let request_id = authenticator
                .revert_recovery_agent_update()
                .await
                .map_err(to_js)?;
            Ok(request_id.into())
        })
    }

    /// Adds an authenticator key and returns the gateway request ID.
    ///
    /// # Errors
    /// Rejects when an argument is invalid or the gateway call fails.
    #[wasm_bindgen(js_name = insertAuthenticator, unchecked_return_type = "Promise<string>")]
    pub fn insert_authenticator(
        &self,
        new_authenticator_pubkey: String,
        new_authenticator_address: String,
    ) -> Promise {
        let authenticator = Arc::clone(&self.0);
        js::promise(async move {
            let request_id = authenticator
                .insert_authenticator(
                    new_authenticator_pubkey,
                    new_authenticator_address,
                )
                .await
                .map_err(to_js)?;
            Ok(request_id.into())
        })
    }

    /// # Errors
    /// Rejects when the key is invalid or the key set cannot be fetched.
    #[wasm_bindgen(js_name = hasAuthenticatorPubkey, unchecked_return_type = "Promise<boolean>")]
    pub fn has_authenticator_pubkey(&self, authenticator_pubkey: String) -> Promise {
        let authenticator = Arc::clone(&self.0);
        js::promise(async move {
            let found = authenticator
                .has_authenticator_pubkey(authenticator_pubkey)
                .await
                .map_err(to_js)?;
            Ok(found.into())
        })
    }

    /// Fetches the on-chain key set. Empty slots are `undefined`.
    ///
    /// # Errors
    /// Rejects when the key set cannot be fetched.
    #[wasm_bindgen(js_name = getAuthenticatorPubkeys, unchecked_return_type = "Promise<(string | undefined)[]>")]
    pub fn get_authenticator_pubkeys(&self) -> Promise {
        let authenticator = Arc::clone(&self.0);
        js::promise(async move {
            let pubkeys = authenticator
                .get_authenticator_pubkeys()
                .await
                .map_err(to_js)?;
            Ok(js::array(pubkeys.into_iter().map(JsValue::from)))
        })
    }

    /// Removes an authenticator key and returns the gateway request ID.
    ///
    /// # Errors
    /// Rejects when an argument is invalid, the slot holds a different key, or the gateway call fails.
    #[wasm_bindgen(js_name = removeAuthenticator, unchecked_return_type = "Promise<string>")]
    pub fn remove_authenticator(
        &self,
        authenticator_address: String,
        #[wasm_bindgen(unchecked_param_type = "number")] pubkey_id: f64,
        expected_authenticator_pubkey: String,
    ) -> Promise {
        let authenticator = Arc::clone(&self.0);
        js::promise(async move {
            let pubkey_id = js::u32_arg("pubkeyId", pubkey_id)?;
            let request_id = authenticator
                .remove_authenticator(
                    authenticator_address,
                    pubkey_id,
                    expected_authenticator_pubkey,
                )
                .await
                .map_err(to_js)?;
            Ok(request_id.into())
        })
    }

    /// Polls the status of a gateway request returned by a mutation above.
    ///
    /// # Errors
    /// Rejects when the gateway call fails.
    #[wasm_bindgen(js_name = pollStatus, unchecked_return_type = "Promise<GatewayRequestStatus>")]
    pub fn poll_status(&self, request_id: String) -> Promise {
        let authenticator = Arc::clone(&self.0);
        js::promise(async move {
            let status = authenticator.poll_status(request_id).await.map_err(to_js)?;
            gateway_request_status(status)
        })
    }

    /// Generates a proof for `proof_request` from the stored credentials.
    ///
    /// `now` is the current unix time in seconds; the browser has no clock core can use.
    ///
    /// # Errors
    /// Rejects when no credential satisfies the request, the request is a replay, or proving fails.
    #[wasm_bindgen(js_name = generateProof, unchecked_return_type = "Promise<ProofResponse>")]
    pub fn generate_proof(&self, proof_request: &JsProofRequest, now: u64) -> Promise {
        let authenticator = Arc::clone(&self.0);
        let proof_request = proof_request.0.clone();
        js::promise(async move {
            let response = authenticator
                .generate_proof(&proof_request, Some(now))
                .await
                .map_err(to_js)?;
            Ok(JsProofResponse(response).into())
        })
    }
}

/// A World ID registration that has been submitted but not yet finalized.
#[wasm_bindgen(js_name = InitializingAuthenticator)]
pub struct JsInitializingAuthenticator(Arc<InitializingAuthenticator>);

#[wasm_bindgen(js_class = InitializingAuthenticator)]
impl JsInitializingAuthenticator {
    /// Submits a registration for `seed` using the environment defaults.
    ///
    /// # Errors
    /// Rejects when an argument is invalid or the gateway call fails.
    #[wasm_bindgen(js_name = registerWithDefaults, unchecked_return_type = "Promise<InitializingAuthenticator>")]
    pub fn register_with_defaults(
        seed: Vec<u8>,
        rpc_url: Option<String>,
        #[wasm_bindgen(unchecked_param_type = "Environment")] environment: &str,
        #[wasm_bindgen(unchecked_param_type = "Region | undefined")] region: Option<
            String,
        >,
        recovery_address: Option<String>,
    ) -> Promise {
        let environment = parse_environment(environment);
        let region = parse_region(region);
        js::promise(async move {
            let registration = InitializingAuthenticator::register_with_defaults(
                seed,
                rpc_url,
                &environment?,
                region?,
                recovery_address,
            )
            .await
            .map_err(to_js)?;
            Ok(Self(Arc::new(registration)).into())
        })
    }

    /// Like [`Self::register_with_defaults`], routing gateway traffic through OHTTP.
    ///
    /// # Errors
    /// Rejects when an argument is invalid or the gateway call fails.
    #[wasm_bindgen(js_name = registerWithOhttpDefaults, unchecked_return_type = "Promise<InitializingAuthenticator>")]
    pub fn register_with_ohttp_defaults(
        seed: Vec<u8>,
        rpc_url: Option<String>,
        #[wasm_bindgen(unchecked_param_type = "Environment")] environment: &str,
        #[wasm_bindgen(unchecked_param_type = "Region | undefined")] region: Option<
            String,
        >,
        recovery_address: Option<String>,
    ) -> Promise {
        let environment = parse_environment(environment);
        let region = parse_region(region);
        js::promise(async move {
            let registration = InitializingAuthenticator::register_with_ohttp_defaults(
                seed,
                rpc_url,
                &environment?,
                region?,
                recovery_address,
            )
            .await
            .map_err(to_js)?;
            Ok(Self(Arc::new(registration)).into())
        })
    }

    /// Submits a registration for `seed` with an explicit JSON `config`.
    ///
    /// # Errors
    /// Rejects when the config is invalid or the gateway call fails.
    #[wasm_bindgen(js_name = register, unchecked_return_type = "Promise<InitializingAuthenticator>")]
    pub fn register(
        seed: Vec<u8>,
        config: String,
        recovery_address: Option<String>,
    ) -> Promise {
        js::promise(async move {
            let registration =
                InitializingAuthenticator::register(seed, &config, recovery_address)
                    .await
                    .map_err(to_js)?;
            Ok(Self(Arc::new(registration)).into())
        })
    }

    /// Polls the registration status.
    ///
    /// # Errors
    /// Rejects when the gateway call fails.
    #[wasm_bindgen(js_name = pollStatus, unchecked_return_type = "Promise<RegistrationStatus>")]
    pub fn poll_status(&self) -> Promise {
        let registration = Arc::clone(&self.0);
        js::promise(async move {
            registration_status(registration.poll_status().await.map_err(to_js)?)
        })
    }
}

fn status(state: &str, fields: &[(&str, JsValue)]) -> Result<JsValue, JsValue> {
    let object = js::object(&[("state", state.into())])?;
    for (key, value) in fields {
        Reflect::set(&object, &JsValue::from_str(key), value)?;
    }
    Ok(object)
}

fn registration_status(status_: RegistrationStatus) -> Result<JsValue, JsValue> {
    match status_ {
        RegistrationStatus::Queued => status("queued", &[]),
        RegistrationStatus::Batching => status("batching", &[]),
        RegistrationStatus::Submitted => status("submitted", &[]),
        RegistrationStatus::Finalized => status("finalized", &[]),
        RegistrationStatus::Failed { error, error_code } => status(
            "failed",
            &[("error", error.into()), ("errorCode", error_code.into())],
        ),
    }
}

fn gateway_request_status(status_: GatewayRequestStatus) -> Result<JsValue, JsValue> {
    match status_ {
        GatewayRequestStatus::Queued => status("queued", &[]),
        GatewayRequestStatus::Batching => status("batching", &[]),
        GatewayRequestStatus::Submitted { tx_hash } => {
            status("submitted", &[("txHash", tx_hash.into())])
        }
        GatewayRequestStatus::Finalized { tx_hash } => {
            status("finalized", &[("txHash", tx_hash.into())])
        }
        GatewayRequestStatus::Failed { error, error_code } => status(
            "failed",
            &[("error", error.into()), ("errorCode", error_code.into())],
        ),
    }
}
