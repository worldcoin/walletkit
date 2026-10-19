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
    polling_backoff, RegistrationResult, RequestedClass, PLAINTEXT_VAULT_FORMAT,
    SESSION_TTL,
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
#[derive(Debug, uniffi::Record)]
pub struct Registered {
    /// The new authenticator. Its storage is not initialized yet.
    pub authenticator: Arc<Authenticator>,
    /// The shared `CredentialStore::export_vault_for_backup` output, to import with
    /// `CredentialStore::merge_vault_from_backup` once storage is initialized.
    pub vault_backup: Option<Vec<u8>>,
}

/// Errors on the Requesting Authenticator's side of a registration. Each one ends the session.
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
#[derive(Debug)]
struct Session {
    pairing_secret: PairingSecret,
    code: PairingCode,
    transport_key: TransportKey,
    response_key: ResponseSecretKey,
    retrieved: bool,
    expires_at: Instant,
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
        drop(self.take_live_session());
    }

    /// Checks the bridge once for the response. A completed response ends the session.
    ///
    /// # Errors
    ///
    /// Returns an error if the bridge cannot be reached, or the response cannot be opened or
    /// does not answer this session's request. Errors end the session.
    pub async fn poll(&self) -> Result<RequesterStatus, RequesterError> {
        let _polling = self.poll_lock.lock().await;
        let Some((request_id, expires_at)) = self
            .live_session(|live| (live.pairing_secret.request_id(), live.expires_at))
        else {
            return Ok(RequesterStatus::Expired);
        };
        let state = before(expires_at, self.bridge.fetch_response(&request_id)).await;
        // The session may have been cancelled during the fetch.
        let Some(mut live) = self.take_live_session() else {
            return Ok(RequesterStatus::Expired);
        };
        match state {
            Some(Ok(Some(ResponseState::Initialized))) => {
                self.restore_session(live);
                Ok(RequesterStatus::Waiting)
            }
            Some(Ok(Some(ResponseState::Retrieved))) => {
                // Taking the request restarts the bridge session (WIP-109 §3.5).
                if !live.retrieved {
                    live.retrieved = true;
                    live.expires_at = Instant::now() + SESSION_TTL;
                }
                self.restore_session(live);
                Ok(RequesterStatus::Retrieved)
            }
            Some(Ok(Some(ResponseState::Completed(sealed)))) => live.open(&sealed),
            Some(Err(error)) => Err(error.into()),
            None | Some(Ok(None)) => Ok(RequesterStatus::Expired),
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

    /// Takes the live session out, ending it unless it is restored.
    fn take_live_session(&self) -> Option<Session> {
        self.session
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
            .filter(|live| Instant::now() < live.expires_at)
    }

    fn restore_session(&self, live: Session) {
        *self.session.lock().unwrap_or_else(PoisonError::into_inner) = Some(live);
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
        let leaf_index = result.leaf_index;
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
        if registered != (result.pubkey_id, address) {
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
        AuthenticatorError::IndexerError { status, .. } => {
            status.is_server_error()
                || *status == reqwest::StatusCode::TOO_MANY_REQUESTS
        }
        _ => false,
    }
}
