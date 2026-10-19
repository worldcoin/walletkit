//! The Requesting Authenticator's side of a registration (WIP-109 §3.8).

use std::{
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};

use alloy_core::primitives::Address;
use backon::Retryable as _;
use secrecy::ExposeSecret as _;
use tokio::sync::Mutex as AsyncMutex;
use web_time::Instant;
use world_id_core::{
    primitives::{
        authenticator_message::{ErrorObject, Response},
        Config,
    },
    registration::{
        decode_response, AuthenticatorName, EncryptedPayload, PairingCode,
        PairingSecret, PairingUri, RegisterRequestMessage, RegistrationDigest,
        RegistrationErrorData, RegistrationErrorReason, RegistrationRequest,
        ResponseSecretKey, TransportError, TransportKey, MAX_NAME_LEN, REGISTER_METHOD,
    },
    Authenticator as CoreAuthenticator, AuthenticatorError, Signer,
};
use zeroize::Zeroizing;

use super::{
    before,
    bridge::{BridgeClient, BridgeError, ResponseState},
    log_tag, polling_backoff, RegistrationResult, RequestedClass,
    PLAINTEXT_VAULT_FORMAT, SESSION_TTL,
};
use crate::{
    authenticator::artifacts::WalletKitZkArtifactSource, defaults,
    error::WalletKitError, storage::CredentialStore, Authenticator, Environment,
    Region,
};

/// How long [`RegistrationRequester::verify`] waits for the indexer to show the registration.
const VERIFY_TIMEOUT: Duration = Duration::from_mins(1);

/// An error response from the Approving Authenticator (WIP-109 §3.6.3).
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct RegistrationError {
    /// The parsed WIP-109 reason, or `None` for an unrecognized error code.
    pub reason: Option<RegistrationErrorReason>,
    /// The raw `error.code`.
    pub code: String,
    /// The human-readable `error.message`.
    pub message: String,
    /// Optional implementation-specific detail from `error.data.detail`, e.g. a gateway error
    /// code.
    pub detail: Option<String>,
}

/// What [`RegistrationRequester::poll`] found on the bridge.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum RequesterStatus {
    /// The Approving Authenticator has not opened the Pairing URI yet.
    Waiting,
    /// The Approving Authenticator took the request. Show the pairing code.
    Retrieved,
    /// The Approving Authenticator approved the registration. The result must be checked with
    /// [`RegistrationRequester::verify`] before it is used.
    Approved {
        /// The unverified registration result.
        result: Arc<RegistrationResult>,
    },
    /// The Approving Authenticator refused or could not complete the registration.
    Refused {
        /// The error reported by the Approving Authenticator.
        error: RegistrationError,
    },
    /// The session expired, was cancelled, or its response was lost. Start a new session with
    /// the same seed.
    Expired,
}

/// A verified registration.
#[derive(uniffi::Record)]
pub struct Registered {
    /// The new authenticator. Its storage is not initialized yet.
    pub authenticator: Arc<Authenticator>,
    /// The shared `CredentialStore::export_vault_for_backup` output, to import with
    /// `CredentialStore::merge_vault_from_backup` once storage is initialized.
    pub vault_backup: Option<Vec<u8>>,
}

impl std::fmt::Debug for Registered {
    /// Formats [`Registered`] without printing the plaintext `vault_backup` bytes.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Registered")
            .field("authenticator", &self.authenticator)
            .field(
                "vault_backup",
                &self.vault_backup.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

/// Errors on the Requesting Authenticator's side of a registration.
///
/// Decrypt and malformed-response errors in [`RegistrationRequester::poll`] end the session;
/// bridge errors leave the session open until it expires so the caller can poll again.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum RequesterError {
    /// The requested authenticator name exceeds [`MAX_NAME_LEN`].
    #[error("authenticator name must be at most {MAX_NAME_LEN} bytes")]
    NameTooLong,
    /// The bridge could not be reached or rejected an operation.
    #[error(transparent)]
    Bridge(#[from] BridgeError),
    /// Encrypting the request or opening the response failed.
    #[error(transparent)]
    Transport(#[from] TransportError),
    /// The seed or configuration is invalid, or reading the account state failed.
    #[error(transparent)]
    Authenticator(#[from] WalletKitError),
    /// The request could not be encoded.
    #[error("failed to encode the registration request: {0}")]
    Encoding(String),
    /// The response is not a valid answer to this session's request.
    #[error("malformed registration response: {0}")]
    MalformedResponse(String),
    /// The seed passed to [`RegistrationRequester::verify`] is not the one this session asked to
    /// register.
    #[error("the seed does not belong to this registration session")]
    SeedMismatch,
    /// The registry does not show the authenticator where and how the result says it is.
    #[error("the registration result does not match the registry")]
    RegistrationMismatch,
    /// The registration could not be verified before the deadline.
    #[error("registration verification timed out")]
    VerificationTimeout,
}

/// The Requesting Authenticator's side of one registration session.
///
/// [`start`](Self::start) publishes the request. Show [`pairing_uri`](Self::pairing_uri) as a
/// QR code and link, and [`poll`](Self::poll) the bridge, e.g. every second; once the request
/// was taken, show [`pairing_code`](Self::pairing_code) instead. Check a successful result with
/// [`verify`](Self::verify).
///
/// A new session after an expired or failed one must use the **same seed**, so that an
/// insertion that already happened is found instead of repeated.
#[derive(Debug, uniffi::Object)]
pub struct RegistrationRequester {
    request: RegistrationRequest,
    digest: RegistrationDigest,
    bridge: Arc<BridgeClient>,
    poll_lock: AsyncMutex<()>,
    /// The live session, or `None` once it completed, failed, expired or was cancelled.
    session: Mutex<Option<Session>>,
}

/// The secrets and state of a live session (WIP-109 §3.3).
struct Session {
    pairing_secret: PairingSecret,
    code: PairingCode,
    transport_key: TransportKey,
    response_key: ResponseSecretKey,
    retrieved: bool,
    expires_at: Instant,
}

impl std::fmt::Debug for Session {
    /// Formats [`Session`] with [`log_tag`] instead of the session secrets or [`RequestId`].
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("request", &log_tag(&self.pairing_secret.request_id()))
            .field("retrieved", &self.retrieved)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl RegistrationRequester {
    /// Starts a session for the authenticator derived from `seed` and publishes its request on
    /// `bridge`, whose domain goes into the Pairing URI.
    ///
    /// This blocks while it derives the transport key with Argon2id (64 MiB). In a browser, call
    /// it from a Web Worker.
    ///
    /// # Errors
    ///
    /// Returns an error if the seed or name is invalid, the CSPRNG is unavailable, the request
    /// cannot be encoded or encrypted, or the bridge does not store it.
    #[uniffi::constructor]
    pub async fn start(
        seed: Vec<u8>,
        class: RequestedClass,
        name: Option<String>,
        bridge: Arc<BridgeClient>,
    ) -> Result<Self, RequesterError> {
        let seed = Zeroizing::new(seed);
        let name = name
            .map(AuthenticatorName::try_from)
            .transpose()
            .map_err(|_| RequesterError::NameTooLong)?;
        let signer =
            Signer::from_seed_bytes(&seed).map_err(AuthenticatorError::from)?;
        let pairing_secret = PairingSecret::generate()?;
        let code = PairingCode::generate();
        let transport_key = pairing_secret.transport_key(&code)?;
        let response_key = ResponseSecretKey::generate()?;
        let request_id = pairing_secret.request_id();
        let (request, digest) = RegistrationRequest::new_signed(
            signer.offchain_signer_private_key().expose_secret(),
            (class == RequestedClass::Admin).then(|| signer.onchain_signer_address()),
            response_key.public_key(),
            name,
            &request_id,
        )
        .map_err(AuthenticatorError::from)?;
        drop(signer);
        let message = RegisterRequestMessage::new(
            Some(request_id.message_id()),
            REGISTER_METHOD,
            Some(request.clone()),
        );
        let plaintext = message
            .encode()
            .map_err(|error| RequesterError::Encoding(error.to_string()))?;
        let encrypted_request = transport_key.encrypt_request(&plaintext)?;
        bridge
            .publish_request(&request_id, &encrypted_request)
            .await?;
        Ok(Self {
            request,
            digest,
            bridge,
            poll_lock: AsyncMutex::new(()),
            session: Mutex::new(Some(Session {
                pairing_secret,
                code,
                transport_key,
                response_key,
                retrieved: false,
                expires_at: Instant::now() + SESSION_TTL,
            })),
        })
    }

    /// Returns the Pairing URI until the Approving Authenticator takes the request or the
    /// session ends. Never log it.
    #[must_use]
    pub fn pairing_uri(&self) -> Option<String> {
        self.live_session(|live| {
            (!live.retrieved).then(|| {
                PairingUri {
                    secret: live.pairing_secret.clone(),
                    digest: self.digest,
                    bridge: self.bridge.bridge_domain().clone(),
                }
                .to_string()
            })
        })
        .flatten()
    }

    /// Returns the pairing code once the Approving Authenticator took the request, until the
    /// session ends. Show it only on this device. Never log it.
    #[must_use]
    pub fn pairing_code(&self) -> Option<String> {
        self.live_session(|live| live.retrieved.then(|| live.code.as_str().to_string()))
            .flatten()
    }

    /// Ends the session and discards its secrets.
    pub fn cancel(&self) {
        drop(
            self.session
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take(),
        );
    }

    /// Checks the bridge once for the response. A completed response ends the session.
    ///
    /// # Errors
    ///
    /// Returns [`RequesterError::Bridge`] if the bridge cannot be reached (leaving the session
    /// open until it expires so a later poll can retry), or [`RequesterError::Transport`] /
    /// [`RequesterError::MalformedResponse`] if the completed response cannot be opened or does
    /// not answer this session's request (which ends the session).
    pub async fn poll(&self) -> Result<RequesterStatus, RequesterError> {
        let _polling = self.poll_lock.lock().await;
        let Some((request_id, expires_at)) = self
            .live_session(|live| (live.pairing_secret.request_id(), live.expires_at))
        else {
            return Ok(RequesterStatus::Expired);
        };
        let state = before(expires_at, self.bridge.fetch_response(&request_id)).await;
        match state {
            Some(Ok(Some(ResponseState::Initialized))) => self
                .with_live_session(|_| RequesterStatus::Waiting)
                .ok_or(())
                .or(Ok(RequesterStatus::Expired)),
            Some(Ok(Some(ResponseState::Retrieved))) => self
                .with_live_session(|live| {
                    // Taking the request restarts the bridge session (WIP-109 §3.5).
                    if !live.retrieved {
                        live.retrieved = true;
                        live.expires_at = Instant::now() + SESSION_TTL;
                    }
                    RequesterStatus::Retrieved
                })
                .ok_or(())
                .or(Ok(RequesterStatus::Expired)),
            Some(Ok(Some(ResponseState::Completed(sealed)))) => {
                let Some(live) = self.take_live_session() else {
                    return Ok(RequesterStatus::Expired);
                };
                let sealed = world_id_core::registration::EncryptedPayload {
                    iv: sealed.iv,
                    payload: sealed.payload,
                };
                live.open(&sealed)
            }
            Some(Err(error)) => {
                if self.live_session(|_| ()).is_none() {
                    return Ok(RequesterStatus::Expired);
                }
                Err(error.into())
            }
            None | Some(Ok(None)) => {
                drop(self.take_live_session());
                Ok(RequesterStatus::Expired)
            }
        }
    }

    /// Checks a successful `result` against the registry using SDK defaults, and returns the new
    /// authenticator.
    ///
    /// # Errors
    ///
    /// See [`Self::verify_with_config`] for potential errors.
    #[allow(
        clippy::too_many_arguments,
        reason = "mirrors the `Authenticator` constructors with SDK defaults"
    )]
    pub async fn verify_with_defaults(
        &self,
        seed: Vec<u8>,
        result: &RegistrationResult,
        rpc_url: Option<String>,
        environment: &Environment,
        region: Option<Region>,
        artifacts: Arc<dyn WalletKitZkArtifactSource>,
        store: Arc<CredentialStore>,
    ) -> Result<Registered, RequesterError> {
        let seed = Zeroizing::new(seed);
        let config = defaults::default_config(environment, rpc_url, region)?;
        self.verify_with_config(&seed, result, config, artifacts, store)
            .await
    }

    /// Checks a successful `result` against the registry using SDK defaults routed through the
    /// OHTTP relay, and returns the new authenticator.
    ///
    /// # Errors
    ///
    /// See [`Self::verify_with_config`] for potential errors.
    #[allow(
        clippy::too_many_arguments,
        reason = "mirrors the `Authenticator` constructors with SDK defaults"
    )]
    pub async fn verify_with_ohttp_defaults(
        &self,
        seed: Vec<u8>,
        result: &RegistrationResult,
        rpc_url: Option<String>,
        environment: &Environment,
        region: Option<Region>,
        artifacts: Arc<dyn WalletKitZkArtifactSource>,
        store: Arc<CredentialStore>,
    ) -> Result<Registered, RequesterError> {
        let seed = Zeroizing::new(seed);
        let config = defaults::default_config_with_ohttp(environment, rpc_url, region)?;
        self.verify_with_config(&seed, result, config, artifacts, store)
            .await
    }

    /// Checks a successful `result` against the registry with a JSON `config`, and returns the
    /// new authenticator.
    ///
    /// # Errors
    ///
    /// See [`Self::verify_with_config`] for potential errors.
    pub async fn verify(
        &self,
        seed: Vec<u8>,
        result: &RegistrationResult,
        config: &str,
        artifacts: Arc<dyn WalletKitZkArtifactSource>,
        store: Arc<CredentialStore>,
    ) -> Result<Registered, RequesterError> {
        let seed = Zeroizing::new(seed);
        let config =
            Config::from_json(config).map_err(|_| WalletKitError::InvalidInput {
                attribute: "config".to_string(),
                reason: "Invalid config".to_string(),
            })?;
        self.verify_with_config(&seed, result, config, artifacts, store)
            .await
    }
}

impl RegistrationRequester {
    /// Runs `read` on the live session, discarding an expired one.
    fn live_session<T>(&self, read: impl FnOnce(&Session) -> T) -> Option<T> {
        let mut session = self.session.lock().unwrap_or_else(PoisonError::into_inner);
        session.take_if(|live| Instant::now() >= live.expires_at);
        session.as_ref().map(read)
    }

    /// Mutates the live session in place under the mutex, discarding an expired one.
    fn with_live_session<T>(
        &self,
        update: impl FnOnce(&mut Session) -> T,
    ) -> Option<T> {
        let mut session = self.session.lock().unwrap_or_else(PoisonError::into_inner);
        session.take_if(|live| Instant::now() >= live.expires_at);
        session.as_mut().map(update)
    }

    /// Takes the live session out when it ends.
    fn take_live_session(&self) -> Option<Session> {
        self.session
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
            .filter(|live| Instant::now() < live.expires_at)
    }

    /// Checks a successful `result` against the registry and returns the new authenticator.
    ///
    /// The indexer must show this session's key at `result.pubkey_id` on `result.leaf_index`,
    /// with the requested class. Until this succeeds the authenticator must not consider itself
    /// registered. The indexer may lag behind the registry, so this retries for up to a minute.
    ///
    /// # Errors
    ///
    /// - [`RequesterError::SeedMismatch`] if `seed` is not the one this session registers.
    /// - [`RequesterError::RegistrationMismatch`] if the key is registered at another slot or
    ///   with another class.
    /// - [`RequesterError::VerificationTimeout`] if the key is still not found when the deadline
    ///   passes. A wrong `leaf_index` cannot be told apart from indexer lag.
    /// - [`RequesterError::Authenticator`] if an account lookup fails permanently.
    pub async fn verify_with_config(
        &self,
        seed: &[u8],
        result: &RegistrationResult,
        config: Config,
        artifacts: Arc<dyn WalletKitZkArtifactSource>,
        store: Arc<CredentialStore>,
    ) -> Result<Registered, RequesterError> {
        let signer = Signer::from_seed_bytes(seed).map_err(AuthenticatorError::from)?;
        if signer.offchain_signer_pubkey().pk
            != self.request.new_authenticator_pubkey.pk
        {
            return Err(RequesterError::SeedMismatch);
        }
        drop(signer);
        let leaf_index = result.leaf_index();
        let lookup = || {
            let config = config.clone();
            let pubkey = self.request.new_authenticator_pubkey.clone();
            async move {
                let authenticators = CoreAuthenticator::fetch_account_authenticators(
                    leaf_index, &config,
                )
                .await?;
                let registered = authenticators
                    .find(&pubkey)
                    .ok_or(AuthenticatorError::PublicKeyNotFound)?;
                Ok::<_, AuthenticatorError>((authenticators, registered))
            }
        };
        let lookup = lookup
            .retry(polling_backoff().with_total_delay(Some(VERIFY_TIMEOUT)))
            .when(is_transient);
        let (authenticators, registered) =
            before(Instant::now() + VERIFY_TIMEOUT, lookup)
                .await
                .ok_or(RequesterError::VerificationTimeout)?
                .map_err(|error| {
                    if is_transient(&error) {
                        RequesterError::VerificationTimeout
                    } else {
                        error.into()
                    }
                })?;
        let address = self
            .request
            .new_authenticator_address
            .unwrap_or(Address::ZERO);
        if registered != (result.pubkey_id(), address) {
            return Err(RequesterError::RegistrationMismatch);
        }
        let inner = CoreAuthenticator::from_account_authenticators(
            seed,
            leaf_index,
            &authenticators,
            config,
            artifacts,
        )?;
        Ok(Registered {
            authenticator: Arc::new(Authenticator { inner, store }),
            vault_backup: result.0.vault.as_ref().map(|vault| vault.data.to_vec()),
        })
    }
}

impl Session {
    /// Opens the sealed response and checks that it answers this session's request (WIP-109
    /// §3.8 step 5).
    fn open(
        &self,
        sealed: &EncryptedPayload,
    ) -> Result<RequesterStatus, RequesterError> {
        let malformed = |problem: &dyn std::fmt::Display| {
            RequesterError::MalformedResponse(problem.to_string())
        };
        let plaintext = self
            .transport_key
            .decrypt_response(&self.response_key, sealed)?;
        let response =
            decode_response(&plaintext).map_err(|error| malformed(&error))?;
        let expected_id = self.pairing_secret.request_id().message_id();
        match response {
            Response::Success { id, result, .. } if id == expected_id => {
                if result
                    .vault
                    .as_ref()
                    .is_some_and(|vault| vault.format != PLAINTEXT_VAULT_FORMAT)
                {
                    return Err(malformed(&"unsupported vault format"));
                }
                Ok(RequesterStatus::Approved {
                    result: Arc::new(RegistrationResult(result)),
                })
            }
            // The outer envelope binds the response to this session, so an error with a null id
            // is accepted too.
            Response::Error { id, error, .. }
                if id.as_ref().is_none_or(|id| *id == expected_id) =>
            {
                Ok(RequesterStatus::Refused {
                    error: error.into(),
                })
            }
            _ => Err(malformed(&"the response answers another request")),
        }
    }
}

impl From<ErrorObject<RegistrationErrorData>> for RegistrationError {
    /// Converts a WIP-109 error object into [`RegistrationError`].
    fn from(error: ErrorObject<RegistrationErrorData>) -> Self {
        Self {
            reason: RegistrationErrorReason::from_code(&error.code),
            code: error.code,
            message: error.message,
            detail: error.data.and_then(|data| data.detail),
        }
    }
}

impl From<AuthenticatorError> for RequesterError {
    /// Converts an [`AuthenticatorError`] into [`RequesterError::Authenticator`].
    fn from(error: AuthenticatorError) -> Self {
        Self::Authenticator(error.into())
    }
}

/// Errors that may clear up while the indexer catches up with the registry or recovers.
fn is_transient(error: &AuthenticatorError) -> bool {
    match error {
        AuthenticatorError::PublicKeyNotFound
        | AuthenticatorError::AccountDoesNotExist
        | AuthenticatorError::NetworkError(_) => true,
        AuthenticatorError::IndexerError { status, .. }
        | AuthenticatorError::OhttpRelayError { status, .. } => {
            status.is_server_error()
                || *status == reqwest::StatusCode::TOO_MANY_REQUESTS
        }
        AuthenticatorError::ContractError(error) => {
            std::error::Error::source(error)
                .is_some_and(<dyn std::error::Error + 'static>::is::<reqwest::Error>)
                || error.to_string().starts_with("HTTP error 429 ")
                || error.to_string().starts_with("HTTP error 5")
        }
        _ => false,
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use axum::{
        extract::State,
        http::StatusCode,
        routing::{get, post},
        Json, Router,
    };
    use serde_json::json;
    use tokio::{net::TcpListener, sync::Notify};
    use world_id_core::{
        api_types::IndexerAuthenticatorsResponse,
        artifacts::dummy::DummyZkArtifactSource,
        primitives::{AuthenticatorPublicKeySet, ServiceEndpoint},
        registration::{RegistrationResult as CoreRegistrationResult, Vault},
        OnchainKeyRepresentable as _,
    };

    use super::*;
    use crate::storage::tests_utils::{temp_root_path, InMemoryStorageProvider};

    async fn serve(app: Router) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        url
    }

    #[tokio::test]
    async fn poll_preserves_session_after_bridge_error() {
        let should_fail = Arc::new(AtomicBool::new(true));
        let app = Router::new()
            .route("/request", post(|| async { StatusCode::OK }))
            .route(
                "/response/{id}",
                get(|State(should_fail): State<Arc<AtomicBool>>| async move {
                    if should_fail.swap(false, Ordering::SeqCst) {
                        Err(StatusCode::BAD_REQUEST)
                    } else {
                        Ok(Json(json!({ "status": "retrieved", "response": null })))
                    }
                }),
            )
            .with_state(should_fail);
        let url = serve(app).await;
        let bridge =
            Arc::new(BridgeClient::with_base_url("bridge.example", &url).unwrap());
        let requester = RegistrationRequester::start(
            vec![7u8; 32],
            RequestedClass::Proving,
            None,
            bridge,
        )
        .await
        .unwrap();

        let err = requester.poll().await.unwrap_err();
        assert!(matches!(err, RequesterError::Bridge(_)));
        assert!(requester.pairing_uri().is_some());

        assert_eq!(requester.poll().await.unwrap(), RequesterStatus::Retrieved);
        assert!(requester.pairing_code().is_some());
    }

    #[tokio::test]
    async fn cancel_during_in_flight_poll_is_not_undone() {
        let entered = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let app =
            Router::new()
                .route("/request", post(|| async { StatusCode::OK }))
                .route(
                    "/response/{id}",
                    get(
                        |State((entered, release)): State<(
                            Arc<Notify>,
                            Arc<Notify>,
                        )>| async move {
                            entered.notify_one();
                            release.notified().await;
                            Json(json!({ "status": "retrieved", "response": null }))
                        },
                    ),
                )
                .with_state((entered.clone(), release.clone()));
        let url = serve(app).await;
        let bridge =
            Arc::new(BridgeClient::with_base_url("bridge.example", &url).unwrap());
        let requester = Arc::new(
            RegistrationRequester::start(
                vec![9u8; 32],
                RequestedClass::Proving,
                None,
                bridge,
            )
            .await
            .unwrap(),
        );

        let polling = {
            let requester = requester.clone();
            tokio::spawn(async move { requester.poll().await.unwrap() })
        };
        entered.notified().await;
        requester.cancel();
        release.notify_one();

        assert_eq!(polling.await.unwrap(), RequesterStatus::Expired);
        assert_eq!(requester.pairing_uri(), None);
        assert_eq!(requester.pairing_code(), None);
        assert_eq!(requester.poll().await.unwrap(), RequesterStatus::Expired);
    }

    #[test]
    fn is_transient_includes_retryable_ohttp_relay_errors() {
        assert!(is_transient(&AuthenticatorError::OhttpRelayError {
            status: reqwest::StatusCode::TOO_MANY_REQUESTS,
            body: String::new(),
        }));
        assert!(is_transient(&AuthenticatorError::OhttpRelayError {
            status: reqwest::StatusCode::SERVICE_UNAVAILABLE,
            body: String::new(),
        }));
        assert!(!is_transient(&AuthenticatorError::OhttpRelayError {
            status: reqwest::StatusCode::BAD_REQUEST,
            body: String::new(),
        }));
    }

    fn authenticators_response(
        pubkeys: [ruint::aliases::U256; 2],
        addresses: [Address; 2],
        commitment: ruint::aliases::U256,
    ) -> Json<IndexerAuthenticatorsResponse> {
        Json(IndexerAuthenticatorsResponse {
            authenticator_pubkeys: pubkeys.map(Some).to_vec(),
            authenticator_addresses: addresses.map(Some).to_vec(),
            offchain_signer_commitment: commitment,
            recovery_counter: 0,
        })
    }

    async fn mock_verify_indexer(seed: [u8; 32], wrong_seed: [u8; 32]) -> String {
        let (signer, other_signer) = (
            Signer::from_seed_bytes(&seed).unwrap(),
            Signer::from_seed_bytes(&wrong_seed).unwrap(),
        );
        let (pubkey, other_pubkey) = (
            signer.offchain_signer_pubkey(),
            other_signer.offchain_signer_pubkey(),
        );
        let (encoded, other_encoded) = (
            pubkey.to_ethereum_representation().unwrap(),
            other_pubkey.to_ethereum_representation().unwrap(),
        );
        let wrong_slot_commitment =
            AuthenticatorPublicKeySet::new(vec![pubkey.clone(), other_pubkey.clone()])
                .unwrap()
                .leaf_hash()
                .into();
        let commitment = AuthenticatorPublicKeySet::new(vec![other_pubkey, pubkey])
            .unwrap()
            .leaf_hash()
            .into();
        let (admin_addr, other_addr) = (
            signer.onchain_signer_address(),
            other_signer.onchain_signer_address(),
        );
        let step = Arc::new(AtomicUsize::new(0));
        let rpc_step = Arc::new(AtomicUsize::new(0));
        serve(
            Router::new()
                .route(
                    "/authenticators",
                    post(move |State(step): State<Arc<AtomicUsize>>| async move {
                        match step.fetch_add(1, Ordering::SeqCst) {
                            0 => Ok(authenticators_response(
                                [encoded, other_encoded],
                                [Address::ZERO, other_addr],
                                wrong_slot_commitment,
                            )),
                            1 => Ok(authenticators_response(
                                [other_encoded, encoded],
                                [other_addr, admin_addr],
                                commitment,
                            )),
                            2 => Err(StatusCode::SERVICE_UNAVAILABLE),
                            _ => Ok(authenticators_response(
                                [other_encoded, encoded],
                                [other_addr, Address::ZERO],
                                commitment,
                            )),
                        }
                    }),
                )
                .with_state(step)
                .route(
                    "/rpc",
                    post(move |State(rpc_step): State<Arc<AtomicUsize>>| async move {
                        if rpc_step.fetch_add(1, Ordering::SeqCst) == 2 {
                            return Err(StatusCode::SERVICE_UNAVAILABLE);
                        }
                        Ok(Json(json!({
                            "jsonrpc": "2.0",
                            "id": 1,
                            "result": format!("0x{:064x}", 0)
                        })))
                    }),
                )
                .with_state(rpc_step),
        )
        .await
    }

    #[tokio::test]
    async fn verify_with_config_enforces_seed_slot_class_and_recovers_from_lag() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (seed, wrong_seed) = ([31u8; 32], [32u8; 32]);
        let bridge_url =
            serve(Router::new().route("/request", post(|| async { StatusCode::OK })))
                .await;
        let bridge = Arc::new(
            BridgeClient::with_base_url("bridge.example", &bridge_url).unwrap(),
        );
        let requester = RegistrationRequester::start(
            seed.to_vec(),
            RequestedClass::Proving,
            None,
            bridge,
        )
        .await
        .unwrap();

        let indexer_url = mock_verify_indexer(seed, wrong_seed).await;
        let config = Config::new(
            Some(format!("{indexer_url}/rpc")),
            480,
            Address::with_last_byte(1),
            ServiceEndpoint::direct(indexer_url.clone()),
            ServiceEndpoint::direct(indexer_url),
            Vec::new(),
            0,
        )
        .unwrap();
        let root = temp_root_path();
        let provider = InMemoryStorageProvider::new(&root);
        let store = Arc::new(CredentialStore::from_provider(&provider).unwrap());
        let result = RegistrationResult(CoreRegistrationResult {
            leaf_index: 7,
            pubkey_id: 1,
            authenticators: Vec::new(),
            vault: Some(Vault {
                format: PLAINTEXT_VAULT_FORMAT.to_string(),
                data: Zeroizing::new(b"secret-vault-bytes".to_vec()),
            }),
        });
        let verify = |s: [u8; 32]| {
            let (config, store, result) = (config.clone(), store.clone(), &result);
            let requester = &requester;
            async move {
                requester
                    .verify_with_config(
                        &s,
                        result,
                        config,
                        Arc::new(DummyZkArtifactSource),
                        store,
                    )
                    .await
            }
        };

        assert!(matches!(
            verify(wrong_seed).await.unwrap_err(),
            RequesterError::SeedMismatch
        ));
        assert!(matches!(
            verify(seed).await.unwrap_err(),
            RequesterError::RegistrationMismatch
        ));
        assert!(matches!(
            verify(seed).await.unwrap_err(),
            RequesterError::RegistrationMismatch
        ));

        let registered = verify(seed).await.unwrap();
        let debug = format!("{registered:?}");
        assert!(debug.contains("<redacted>") && !debug.contains("secret-vault-bytes"));
        assert_eq!(
            registered.vault_backup.as_deref(),
            Some(b"secret-vault-bytes".as_slice())
        );
        let _ = std::fs::remove_dir_all(root);
    }
}
