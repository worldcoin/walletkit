//! Registering a new authenticator through an existing Admin Authenticator (WIP-109).
//!
//! Both sides derive the transport key with Argon2id (64 MiB) synchronously, in
//! `RegistrationRequester.start` and `PendingRegistration.authenticate`. The package runs
//! the module in a Web Worker, so this never blocks the page.

use std::sync::Arc;

use js_sys::{Array, Promise, Uint8Array};
use walletkit_core::registration::{
    ApprovalOutcome, ApprovalResult, BridgeClient, CheckedRegistration,
    IncomingRegistration, KnownAuthenticator, PendingRegistration, Registered,
    RegistrationErrorReason, RegistrationPlan, RegistrationRequester,
    RegistrationResult, RequestedClass, RequesterStatus,
};
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

use crate::{
    authenticator::{
        parse_environment, parse_region, JsAuthenticator, JsEmbeddedZkArtifacts,
    },
    error::{invalid_argument, to_js},
    js,
    storage::JsCredentialStore,
};

/// A client for one message-bridge deployment.
#[wasm_bindgen(js_name = BridgeClient)]
pub struct JsBridgeClient(Arc<BridgeClient>);

#[wasm_bindgen(js_class = BridgeClient)]
impl JsBridgeClient {
    /// Creates a client for the bridge at `https://{domain}`.
    ///
    /// # Errors
    /// Throws a `BridgeError` when `domain` is not a valid bridge domain.
    #[wasm_bindgen(js_name = new)]
    pub fn new(domain: &str) -> Result<Self, JsValue> {
        BridgeClient::new(domain)
            .map(|client| Self(Arc::new(client)))
            .map_err(to_js)
    }

    /// Creates a client that reaches the bridge named `domain` at `base_url`, e.g. a local
    /// deployment.
    ///
    /// # Errors
    /// Throws a `BridgeError` when `domain` or `base_url` is invalid.
    #[wasm_bindgen(js_name = withBaseUrl)]
    pub fn with_base_url(domain: &str, base_url: &str) -> Result<Self, JsValue> {
        BridgeClient::with_base_url(domain, base_url)
            .map(|client| Self(Arc::new(client)))
            .map_err(to_js)
    }

    /// The domain of the bridge deployment, as written into a Pairing URI.
    #[must_use]
    pub fn domain(&self) -> String {
        self.0.domain()
    }
}

/// The Requesting Authenticator's side of a registration: the new device.
#[wasm_bindgen(js_name = RegistrationRequester)]
pub struct JsRegistrationRequester(Arc<RegistrationRequester>);

#[wasm_bindgen(js_class = RegistrationRequester)]
impl JsRegistrationRequester {
    /// Starts a session for the authenticator derived from `seed` and publishes its request on
    /// `bridge`. A new session after an expired or failed one must use the same seed.
    ///
    /// # Errors
    /// Rejects with a `TypeError` for an unknown class, or a `RequesterError` when the seed
    /// or name is invalid or the bridge does not store the request.
    #[wasm_bindgen(js_name = start, unchecked_return_type = "Promise<RegistrationRequester>")]
    pub fn start(
        seed: Vec<u8>,
        #[wasm_bindgen(unchecked_param_type = "RequestedClass")] requested_class: &str,
        name: Option<String>,
        bridge: &JsBridgeClient,
    ) -> Promise {
        let class = parse_class(requested_class);
        let bridge = Arc::clone(&bridge.0);
        // The seed only reaches core's zeroizing guard once validation passed.
        let mut seed = Zeroizing::new(seed);
        js::promise(async move {
            let class = class?;
            let requester = RegistrationRequester::start(
                std::mem::take(&mut *seed),
                class,
                name,
                bridge,
            )
            .await
            .map_err(to_js)?;
            Ok(Self(Arc::new(requester)).into())
        })
    }

    /// The Pairing URI to show as a QR code, until the Approving Authenticator takes the
    /// request or the session ends. Never log it.
    #[wasm_bindgen(js_name = pairingUri)]
    #[must_use]
    pub fn pairing_uri(&self) -> Option<String> {
        self.0.pairing_uri()
    }

    /// The pairing code to show once the Approving Authenticator took the request, until the
    /// session ends. Show it only on this device. Never log it.
    #[wasm_bindgen(js_name = pairingCode)]
    #[must_use]
    pub fn pairing_code(&self) -> Option<String> {
        self.0.pairing_code()
    }

    /// Ends the session and discards its secrets.
    pub fn cancel(&self) {
        self.0.cancel();
    }

    /// Checks the bridge once for the response. A completed response ends the session.
    ///
    /// # Errors
    /// Rejects with a `RequesterError`. After a `Bridge` error the session stays open, so poll
    /// again; any other error ends the session.
    #[wasm_bindgen(js_name = poll, unchecked_return_type = "Promise<RequesterStatus>")]
    pub fn poll(&self) -> Promise {
        let requester = Arc::clone(&self.0);
        js::promise(
            async move { requester_status(requester.poll().await.map_err(to_js)?) },
        )
    }

    /// Checks an approved `result` against the registry using the environment defaults, and
    /// returns the new authenticator.
    ///
    /// # Errors
    /// Rejects when an argument is invalid, the seed is not this session's, or the
    /// registration is not found on-chain in time.
    #[allow(
        clippy::too_many_arguments,
        reason = "mirrors the arguments of the core method"
    )]
    #[wasm_bindgen(js_name = verifyWithDefaults, unchecked_return_type = "Promise<Registered>")]
    pub fn verify_with_defaults(
        &self,
        seed: Vec<u8>,
        result: &JsRegistrationResult,
        rpc_url: Option<String>,
        #[wasm_bindgen(unchecked_param_type = "Environment")] environment: &str,
        #[wasm_bindgen(unchecked_param_type = "Region | undefined")] region: Option<
            String,
        >,
        artifacts: &JsEmbeddedZkArtifacts,
        store: &JsCredentialStore,
    ) -> Promise {
        let requester = Arc::clone(&self.0);
        let result = Arc::clone(&result.0);
        let environment = parse_environment(environment);
        let region = parse_region(region);
        let artifacts = artifacts.source();
        let store = Arc::clone(&store.0);
        let mut seed = Zeroizing::new(seed);
        js::promise(async move {
            let (environment, region) = (environment?, region?);
            let registered = requester
                .verify_with_defaults(
                    std::mem::take(&mut *seed),
                    &result,
                    rpc_url,
                    &environment,
                    region,
                    artifacts,
                    store,
                )
                .await
                .map_err(to_js)?;
            registered_record(registered)
        })
    }

    /// Like [`Self::verify_with_defaults`], routing gateway traffic through OHTTP.
    ///
    /// # Errors
    /// Rejects when an argument is invalid, the seed is not this session's, or the
    /// registration is not found on-chain in time.
    #[allow(
        clippy::too_many_arguments,
        reason = "mirrors the arguments of the core method"
    )]
    #[wasm_bindgen(js_name = verifyWithOhttpDefaults, unchecked_return_type = "Promise<Registered>")]
    pub fn verify_with_ohttp_defaults(
        &self,
        seed: Vec<u8>,
        result: &JsRegistrationResult,
        rpc_url: Option<String>,
        #[wasm_bindgen(unchecked_param_type = "Environment")] environment: &str,
        #[wasm_bindgen(unchecked_param_type = "Region | undefined")] region: Option<
            String,
        >,
        artifacts: &JsEmbeddedZkArtifacts,
        store: &JsCredentialStore,
    ) -> Promise {
        let requester = Arc::clone(&self.0);
        let result = Arc::clone(&result.0);
        let environment = parse_environment(environment);
        let region = parse_region(region);
        let artifacts = artifacts.source();
        let store = Arc::clone(&store.0);
        let mut seed = Zeroizing::new(seed);
        js::promise(async move {
            let (environment, region) = (environment?, region?);
            let registered = requester
                .verify_with_ohttp_defaults(
                    std::mem::take(&mut *seed),
                    &result,
                    rpc_url,
                    &environment,
                    region,
                    artifacts,
                    store,
                )
                .await
                .map_err(to_js)?;
            registered_record(registered)
        })
    }

    /// Checks an approved `result` against the registry with an explicit JSON `config`, and
    /// returns the new authenticator.
    ///
    /// # Errors
    /// Rejects when the config is invalid, the seed is not this session's, or the
    /// registration is not found on-chain in time.
    #[wasm_bindgen(js_name = verify, unchecked_return_type = "Promise<Registered>")]
    pub fn verify(
        &self,
        seed: Vec<u8>,
        result: &JsRegistrationResult,
        config: String,
        artifacts: &JsEmbeddedZkArtifacts,
        store: &JsCredentialStore,
    ) -> Promise {
        let requester = Arc::clone(&self.0);
        let result = Arc::clone(&result.0);
        let artifacts = artifacts.source();
        let store = Arc::clone(&store.0);
        js::promise(async move {
            let registered = requester
                .verify(seed, &result, &config, artifacts, store)
                .await
                .map_err(to_js)?;
            registered_record(registered)
        })
    }
}

/// An approved, not yet verified registration. Its vault is only handed out by `verify`.
#[wasm_bindgen(js_name = RegistrationResult)]
pub struct JsRegistrationResult(Arc<RegistrationResult>);

#[wasm_bindgen(js_class = RegistrationResult)]
impl JsRegistrationResult {
    /// The index of the account the authenticator was registered on.
    #[wasm_bindgen(js_name = leafIndex)]
    #[must_use]
    pub fn leaf_index(&self) -> u64 {
        self.0.leaf_index()
    }

    /// The slot the authenticator was inserted at.
    #[wasm_bindgen(js_name = pubkeyId)]
    #[must_use]
    pub fn pubkey_id(&self) -> u32 {
        self.0.pubkey_id()
    }

    /// The names of the account's other authenticators known to the Approving Authenticator.
    ///
    /// # Errors
    /// Never fails in practice; building a plain object cannot fail.
    #[wasm_bindgen(unchecked_return_type = "KnownAuthenticator[]")]
    pub fn authenticators(&self) -> Result<JsValue, JsValue> {
        self.0
            .authenticators()
            .into_iter()
            .map(|known| {
                js::object(&[
                    ("pubkeyId", known.pubkey_id.into()),
                    ("name", known.name.into()),
                ])
            })
            .collect::<Result<Vec<_>, _>>()
            .map(js::array)
    }

    /// Whether the Approving Authenticator included a credential vault backup.
    #[wasm_bindgen(js_name = hasVault)]
    #[must_use]
    pub fn has_vault(&self) -> bool {
        self.0.has_vault()
    }
}

/// An encrypted request taken from the bridge, waiting for the pairing code.
#[wasm_bindgen(js_name = PendingRegistration)]
pub struct JsPendingRegistration(Arc<PendingRegistration>);

#[wasm_bindgen(js_class = PendingRegistration)]
impl JsPendingRegistration {
    /// Takes the request named by the scanned Pairing URI from its bridge, before the host
    /// prompts for the code. Never log the URI.
    ///
    /// Unlike the Swift and Kotlin bindings, this takes the one bridge the host allows: a
    /// client in a list would be moved out of the page's reach. On `BridgeNotAllowed`, the
    /// host may ask the user to confirm the bridge in the error's `domain`, then retry with a
    /// client for it.
    ///
    /// # Errors
    /// Rejects with an `ApproverError` for an invalid or expired URI, a URI naming another
    /// bridge, or a bridge failure.
    #[wasm_bindgen(js_name = receive, unchecked_return_type = "Promise<PendingRegistration>")]
    pub fn receive(uri: String, allowed_bridge: &JsBridgeClient) -> Promise {
        let bridge = Arc::clone(&allowed_bridge.0);
        js::promise(async move {
            let pending = PendingRegistration::receive(&uri, vec![bridge])
                .await
                .map_err(to_js)?;
            Ok(Self(Arc::new(pending)).into())
        })
    }

    /// Authenticates the request with the code the user entered, then validates it.
    ///
    /// # Errors
    /// Rejects with `MalformedCode` or `IncorrectCode`, after which the user may enter the
    /// code again; only an incorrect code uses one of the three attempts. Every other error
    /// ends the session.
    #[wasm_bindgen(js_name = authenticate, unchecked_return_type = "Promise<IncomingRegistration>")]
    pub fn authenticate(&self, code: String) -> Promise {
        let pending = Arc::clone(&self.0);
        js::promise(async move {
            let incoming = pending.authenticate(&code).await.map_err(to_js)?;
            Ok(JsIncomingRegistration(incoming).into())
        })
    }
}

/// An authenticated, valid registration request.
#[wasm_bindgen(js_name = IncomingRegistration)]
pub struct JsIncomingRegistration(Arc<IncomingRegistration>);

#[wasm_bindgen(js_class = IncomingRegistration)]
impl JsIncomingRegistration {
    /// The class the new authenticator asks for.
    #[wasm_bindgen(unchecked_return_type = "RequestedClass")]
    #[must_use]
    pub fn class(&self) -> String {
        class_name(self.0.class()).to_string()
    }

    /// The name the new authenticator asks for. It is untrusted and must be displayed as such.
    #[must_use]
    pub fn name(&self) -> Option<String> {
        self.0.name()
    }

    /// How many seconds are left until the response is due.
    #[wasm_bindgen(js_name = timeRemainingSecs)]
    #[must_use]
    pub fn time_remaining_secs(&self) -> u64 {
        self.0.time_remaining_secs()
    }

    /// Reads the account state of `approver` and plans the registration.
    ///
    /// # Errors
    /// Rejects with an `ApproverError`: `Refused` after answering the reason, or
    /// `AlreadyHandled` if the request was already checked or rejected.
    #[wasm_bindgen(js_name = check, unchecked_return_type = "Promise<CheckedRegistration>")]
    pub fn check(&self, approver: &JsAuthenticator) -> Promise {
        let incoming = Arc::clone(&self.0);
        let approver = Arc::clone(&approver.0);
        js::promise(async move {
            let checked = incoming.check(&approver).await.map_err(to_js)?;
            Ok(JsCheckedRegistration(checked).into())
        })
    }

    /// Refuses a request whose name the host does not accept. Resolves to whether the answer
    /// was delivered.
    ///
    /// # Errors
    /// Rejects with `AlreadyHandled` if the request was already checked or rejected.
    #[wasm_bindgen(js_name = rejectName, unchecked_return_type = "Promise<boolean>")]
    pub fn reject_name(&self) -> Promise {
        let incoming = Arc::clone(&self.0);
        js::promise(
            async move { Ok(incoming.reject_name().await.map_err(to_js)?.into()) },
        )
    }
}

/// A registration request whose account state was checked, waiting for the user's decision.
#[wasm_bindgen(js_name = CheckedRegistration)]
pub struct JsCheckedRegistration(Arc<CheckedRegistration>);

#[wasm_bindgen(js_class = CheckedRegistration)]
impl JsCheckedRegistration {
    /// The class the new authenticator asks for.
    #[wasm_bindgen(unchecked_return_type = "RequestedClass")]
    #[must_use]
    pub fn class(&self) -> String {
        class_name(self.0.class()).to_string()
    }

    /// The name the new authenticator asks for. It is untrusted and must be displayed as such.
    #[must_use]
    pub fn name(&self) -> Option<String> {
        self.0.name()
    }

    /// How the registration will be carried out.
    ///
    /// # Errors
    /// Never fails in practice; building a plain object cannot fail.
    #[wasm_bindgen(unchecked_return_type = "RegistrationPlan")]
    pub fn plan(&self) -> Result<JsValue, JsValue> {
        let (kind, pubkey_id) = match self.0.plan() {
            RegistrationPlan::Insert { pubkey_id } => ("insert", pubkey_id),
            RegistrationPlan::AlreadyRegistered { pubkey_id } => {
                ("alreadyRegistered", pubkey_id)
            }
        };
        js::object(&[("kind", kind.into()), ("pubkeyId", pubkey_id.into())])
    }

    /// How many seconds are left until the response is due.
    #[wasm_bindgen(js_name = timeRemainingSecs)]
    #[must_use]
    pub fn time_remaining_secs(&self) -> u64 {
        self.0.time_remaining_secs()
    }

    /// Declines with `user_rejected`. Resolves to whether the answer was delivered.
    ///
    /// # Errors
    /// Rejects with `AlreadyHandled` if the registration was already decided.
    #[wasm_bindgen(js_name = reject, unchecked_return_type = "Promise<boolean>")]
    pub fn reject(&self) -> Promise {
        let checked = Arc::clone(&self.0);
        js::promise(async move { Ok(checked.reject().await.map_err(to_js)?.into()) })
    }

    /// Ends the registration with `internal_error`, e.g. because the user verification
    /// failed. Resolves to whether the answer was delivered.
    ///
    /// # Errors
    /// Rejects with `AlreadyHandled` if the registration was already decided.
    #[wasm_bindgen(js_name = abort, unchecked_return_type = "Promise<boolean>")]
    pub fn abort(&self) -> Promise {
        let checked = Arc::clone(&self.0);
        js::promise(async move { Ok(checked.abort().await.map_err(to_js)?.into()) })
    }

    /// Carries out the registration and sends the response. Call it only after the user
    /// consented and the user verification succeeded.
    ///
    /// `vault` is a credential vault backup, only if the user chose to share it. The worker
    /// is busy until the insertion is final, which can take minutes.
    ///
    /// # Errors
    /// Rejects with a `TypeError` for a malformed `authenticators` entry, or an
    /// `ApproverError`: `ApproverMismatch` if `approver` is not the checked account, or
    /// `AlreadyHandled` if the registration was already decided.
    #[wasm_bindgen(js_name = approve, unchecked_return_type = "Promise<ApprovalOutcome>")]
    pub fn approve(
        &self,
        approver: &JsAuthenticator,
        vault: Option<Vec<u8>>,
        #[wasm_bindgen(unchecked_param_type = "KnownAuthenticator[]")]
        authenticators: &JsValue,
    ) -> Promise {
        let checked = Arc::clone(&self.0);
        let approver = Arc::clone(&approver.0);
        let authenticators = known_authenticators(authenticators);
        // The vault only reaches core's zeroizing guard once validation passed.
        let mut vault = vault.map(Zeroizing::new);
        js::promise(async move {
            let authenticators = authenticators?;
            let outcome = checked
                .approve(
                    &approver,
                    vault.as_deref_mut().map(std::mem::take),
                    authenticators,
                )
                .await
                .map_err(to_js)?;
            approval_outcome(&outcome)
        })
    }
}

fn parse_class(class: &str) -> Result<RequestedClass, JsValue> {
    match class {
        "admin" => Ok(RequestedClass::Admin),
        "proving" => Ok(RequestedClass::Proving),
        _ => Err(invalid_argument(&format!("Unknown class: {class}"))),
    }
}

fn requester_status(status: RequesterStatus) -> Result<JsValue, JsValue> {
    match status {
        RequesterStatus::Waiting => js::object(&[("state", "waiting".into())]),
        RequesterStatus::Retrieved => js::object(&[("state", "retrieved".into())]),
        RequesterStatus::Expired => js::object(&[("state", "expired".into())]),
        RequesterStatus::Approved { result } => js::object(&[
            ("state", "approved".into()),
            ("result", JsRegistrationResult(result).into()),
        ]),
        RequesterStatus::Refused { error } => js::object(&[
            ("state", "refused".into()),
            (
                "error",
                js::object(&[
                    (
                        "reason",
                        error.reason.map(RegistrationErrorReason::code).into(),
                    ),
                    ("code", error.code.into()),
                    ("message", error.message.into()),
                    ("detail", error.detail.into()),
                ])?,
            ),
        ]),
    }
}

fn registered_record(registered: Registered) -> Result<JsValue, JsValue> {
    let vault_backup = registered.vault_backup.map(Zeroizing::new);
    js::object(&[
        (
            "authenticator",
            JsAuthenticator(registered.authenticator).into(),
        ),
        (
            "vaultBackup",
            vault_backup
                .as_deref()
                .map(|vault| Uint8Array::from(vault.as_slice()))
                .into(),
        ),
    ])
}

const fn class_name(class: RequestedClass) -> &'static str {
    match class {
        RequestedClass::Admin => "admin",
        RequestedClass::Proving => "proving",
    }
}

fn known_authenticators(value: &JsValue) -> Result<Vec<KnownAuthenticator>, JsValue> {
    if !Array::is_array(value) {
        return Err(invalid_argument("`authenticators` must be an array"));
    }
    Array::from(value)
        .iter()
        .map(|item| {
            Ok(KnownAuthenticator {
                pubkey_id: js::u32_arg(
                    "pubkeyId",
                    js::number_field(&item, "pubkeyId")?,
                )?,
                name: js::string_field(&item, "name")?,
            })
        })
        .collect()
}

fn approval_outcome(outcome: &ApprovalOutcome) -> Result<JsValue, JsValue> {
    let result = match &outcome.result {
        ApprovalResult::Registered {
            leaf_index,
            pubkey_id,
        } => js::object(&[
            ("state", "registered".into()),
            ("leafIndex", (*leaf_index).into()),
            ("pubkeyId", (*pubkey_id).into()),
        ])?,
        ApprovalResult::Failed { reason } => {
            js::object(&[("state", "failed".into()), ("reason", reason.code().into())])?
        }
    };
    js::object(&[
        ("result", result),
        ("vaultOmitted", outcome.vault_omitted.into()),
        ("delivered", outcome.delivered.into()),
    ])
}
