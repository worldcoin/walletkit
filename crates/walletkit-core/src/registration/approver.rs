//! The Approving Authenticator's side of a registration (WIP-109 §3.7).
//!
//! The flow is split into steps so that the host can ask the user in between:
//!
//! 1. [`PendingRegistration::receive`] takes the encrypted request before code entry.
//! 2. [`PendingRegistration::authenticate`] decrypts and validates it with the entered code.
//! 3. [`IncomingRegistration::check`] reads the account state and plans the registration.
//! 4. After the consent screen and the platform's user verification, the host calls
//!    [`CheckedRegistration::approve`], or declines with [`CheckedRegistration::reject`] or
//!    [`CheckedRegistration::abort`].
//!
//! Every step that ends the registration answers the Requesting Authenticator first, and reports
//! whether the answer was delivered. If it was not, the host must tell the user that the new
//! device may not have received it, and to check it and retry from it if needed.

use std::{
    fmt::Display,
    future::Future,
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};

use alloy_core::primitives::Address;
use backon::BackoffBuilder as _;
use tokio::sync::Mutex as AsyncMutex;
use web_time::Instant;
use world_id_core::{
    primitives::{
        api_types::{GatewayErrorCode, GatewayRequestState, ServiceApiError},
        authenticator_message::{
            ErrorObject, Id, MessageError, Request, Response, Value,
        },
    },
    registration::{
        EncryptedPayload, KnownAuthenticator, PairingCode, PairingUri,
        RegistrationDigest, RegistrationErrorData, RegistrationErrorReason,
        RegistrationRequest, RegistrationResult, RequestId, ResponsePublicKey,
        TransportError, TransportKey, Vault, MAX_VAULT_SIZE, REGISTER_METHOD,
    },
    AccountAuthenticators, AuthenticatorError,
};
use zeroize::Zeroizing;

use super::{
    before,
    bridge::{BridgeClient, BridgeError},
    log_tag, polling_backoff, sleep, RequestedClass, PLAINTEXT_VAULT_FORMAT,
    SESSION_TTL,
};
use crate::{error::WalletKitError, Authenticator};

/// The largest encoded request (WIP-109 §3.5).
const MAX_REQUEST_SIZE: usize = 4 * 1024;

/// The largest encoded response: a full vault plus 4 KiB for the other fields (WIP-109 §3.5).
const MAX_RESPONSE_SIZE: usize = MAX_VAULT_SIZE + 4 * 1024;

/// How many times the user may enter the pairing code (WIP-109 §3.7.1 step 3).
const MAX_CODE_ATTEMPTS: u8 = 3;

/// Matches the nesting limit of the WIP-105 message decoder.
const RECURSION_LIMIT: usize = 32;

/// How long before the estimated session expiry the response is due (WIP-109 §3.5).
const RESPONSE_MARGIN: Duration = Duration::from_mins(1);

/// The least time before the response deadline for an insertion to still be submitted. With
/// less, its outcome would most likely be unknown.
const MIN_TRACKING_TIME: Duration = Duration::from_mins(2);

/// Errors on the Approving Authenticator's side of a registration.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum ApproverError {
    /// The scanned text is not a WIP-109 Pairing URI.
    #[error("not a registration pairing link")]
    InvalidPairingUri,
    /// The Pairing URI names a bridge the host does not allow. The host may ask the user to
    /// confirm it, then retry with a client for it (WIP-109 §3.4).
    #[error("bridge {domain} is not allowed")]
    BridgeNotAllowed {
        /// The bridge domain named by the Pairing URI.
        domain: String,
    },
    /// The request expired or was already used. The user should create a new QR code or link
    /// on the new device.
    #[error("the registration request expired or was already used")]
    Expired,
    /// The entered code is not six letters. No attempt was used.
    #[error("the pairing code must be six letters")]
    MalformedCode,
    /// The code did not authenticate the request.
    #[error("pairing code did not authenticate the request ({attempts_remaining} attempts remain)")]
    IncorrectCode {
        /// Remaining code attempts; zero means a new pairing is required.
        attempts_remaining: u8,
    },
    /// The authenticated request is invalid, or does not match the Pairing URI.
    #[error("invalid registration request: {problem}")]
    InvalidRequest {
        /// What is wrong with the request.
        problem: String,
        /// Whether the error was delivered. A request without a readable response key cannot be
        /// answered, and a notification must not be.
        delivered: bool,
    },
    /// The registration was refused (WIP-109 §3.7.2).
    #[error("registration refused: {reason:?}")]
    Refused {
        /// The reason, which was sent to the Requesting Authenticator.
        reason: RegistrationErrorReason,
        /// The failure behind the refusal, if there was one. It was not sent.
        failure: Option<WalletKitError>,
        /// Whether the reason was delivered.
        delivered: bool,
    },
    /// The bridge could not be reached or rejected an operation.
    #[error(transparent)]
    Bridge(#[from] BridgeError),
    /// Decrypting the request failed for a reason other than a wrong code.
    #[error(transparent)]
    Transport(#[from] TransportError),
    /// The authenticator passed to [`CheckedRegistration::approve`] is not the one that
    /// [`IncomingRegistration::check`] checked.
    #[error("the approver does not match the checked account")]
    ApproverMismatch,
    /// This step was already taken, so the registration has moved on or ended.
    #[error("this registration step was already taken")]
    AlreadyHandled,
}

/// How a checked registration will be carried out.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum RegistrationPlan {
    /// Insert the authenticator at `pubkey_id`.
    Insert {
        /// The slot the authenticator will be inserted at.
        pubkey_id: u32,
    },
    /// The authenticator is already registered as requested, e.g. by an earlier session whose
    /// response was lost. Approval only sends the result.
    AlreadyRegistered {
        /// The slot the authenticator is registered at.
        pubkey_id: u32,
    },
}

/// The result of [`CheckedRegistration::approve`].
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct ApprovalOutcome {
    /// Whether the authenticator was registered.
    pub result: ApprovalResult,
    /// Whether the vault was left out because it exceeds [`MAX_VAULT_SIZE`]. The host must tell
    /// the user that the vault was not shared.
    pub vault_omitted: bool,
    /// Whether the response was delivered.
    pub delivered: bool,
}

/// Whether [`CheckedRegistration::approve`] registered the authenticator.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum ApprovalResult {
    /// The authenticator is registered on-chain, even if the response was not delivered.
    Registered {
        /// The index of the account.
        leaf_index: u64,
        /// The slot the authenticator is registered at.
        pubkey_id: u32,
    },
    /// The registration did not succeed. `OutcomeUnknown` means that it may still land.
    Failed {
        /// The reason, which was sent to the Requesting Authenticator.
        reason: RegistrationErrorReason,
    },
}

/// An encrypted request taken from the bridge, waiting for code entry (WIP-109 §3.7.1).
#[derive(uniffi::Object)]
pub struct PendingRegistration {
    uri: PairingUri,
    encrypted: EncryptedPayload,
    bridge: Arc<BridgeClient>,
    /// Estimated from when the request was taken (WIP-109 §3.5).
    expires_at: Instant,
    attempts_remaining: AsyncMutex<u8>,
}

impl std::fmt::Debug for PendingRegistration {
    /// Formats [`PendingRegistration`] with a short request tag instead of the bearer [`PairingUri`].
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingRegistration")
            .field("request", &log_tag(&self.uri.secret.request_id()))
            .field("bridge", &self.bridge)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

/// An authenticated, valid registration request.
#[derive(Debug, uniffi::Object)]
pub struct IncomingRegistration {
    request: RegistrationRequest,
    respond_by: Instant,
    /// Taken by the step that moves the registration on.
    channel: Mutex<Option<ResponseChannel>>,
}

/// A registration request whose account state was checked, waiting for the user's decision.
#[derive(Debug, uniffi::Object)]
pub struct CheckedRegistration {
    request: RegistrationRequest,
    respond_by: Instant,
    approver_leaf_index: u64,
    approver_pubkey: world_id_core::EdDSAPublicKey,
    approver_address: Address,
    authenticators: AccountAuthenticators,
    plan: RegistrationPlan,
    /// Taken by the decision.
    channel: Mutex<Option<ResponseChannel>>,
}

/// Where and how to answer one request.
struct ResponseChannel {
    request_id: RequestId,
    response_pubkey: ResponsePublicKey,
    transport_key: TransportKey,
    bridge: Arc<BridgeClient>,
    expires_at: Instant,
}

impl std::fmt::Debug for ResponseChannel {
    /// Formats [`ResponseChannel`] with [`log_tag`] instead of the bearer [`RequestId`].
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResponseChannel")
            .field("request", &log_tag(&self.request_id))
            .field("response_pubkey", &self.response_pubkey)
            .field("bridge", &self.bridge)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

/// An authenticated request that fails validation (WIP-109 §3.7.1 step 4).
struct InvalidRequest {
    reason: RegistrationErrorReason,
    /// What is wrong with the request; also sent as `error.data.detail`.
    problem: String,
    /// The id and key to answer with, or `None` if the request must not or cannot be answered.
    reply: Option<(Option<Id>, Box<ResponsePublicKey>)>,
}

/// Why the Approving Authenticator refuses a valid request (WIP-109 §3.6.3).
#[derive(Debug)]
struct Refusal {
    reason: RegistrationErrorReason,
    /// Sent as `error.data.detail`.
    detail: Option<String>,
    /// The failure behind the refusal, reported to the host but never sent.
    cause: Option<Box<AuthenticatorError>>,
}

#[uniffi::export(async_runtime = "tokio")]
impl PendingRegistration {
    /// Takes the encrypted request named by the scanned Pairing URI from its bridge, before the
    /// host prompts for the code. Never log the URI.
    ///
    /// The URI's bridge must be one of `allowed_bridges`. To contact another bridge, the host
    /// must first get the user's confirmation, then pass a client for it (WIP-109 §3.4).
    ///
    /// # Errors
    ///
    /// Returns [`ApproverError::InvalidPairingUri`], [`ApproverError::BridgeNotAllowed`],
    /// [`ApproverError::Expired`] for a used or expired URI, or a bridge error.
    #[uniffi::constructor]
    pub async fn receive(
        uri: &str,
        allowed_bridges: Vec<Arc<BridgeClient>>,
    ) -> Result<Self, ApproverError> {
        let uri: PairingUri =
            uri.parse().map_err(|_| ApproverError::InvalidPairingUri)?;
        let bridge = allowed_bridges
            .into_iter()
            .find(|bridge| *bridge.bridge_domain() == uri.bridge)
            .ok_or_else(|| ApproverError::BridgeNotAllowed {
                domain: uri.bridge.to_string(),
            })?;
        let taken_at = Instant::now();
        let encrypted = bridge
            .take_request(&uri.secret.request_id())
            .await?
            .ok_or(ApproverError::Expired)?;
        Ok(Self {
            uri,
            encrypted,
            bridge,
            expires_at: taken_at + SESSION_TTL,
            attempts_remaining: AsyncMutex::new(MAX_CODE_ATTEMPTS),
        })
    }

    /// Authenticates the request with `code`, then validates it (WIP-109 §3.7.1).
    ///
    /// This blocks while it derives the transport key with Argon2id (64 MiB). In a browser, call
    /// it from a Web Worker.
    ///
    /// # Errors
    ///
    /// [`ApproverError::MalformedCode`] and [`ApproverError::IncorrectCode`] let the user enter
    /// the code again; only an incorrect code uses one of the three attempts. Every other error
    /// ends the session.
    pub async fn authenticate(
        &self,
        code: &str,
    ) -> Result<Arc<IncomingRegistration>, ApproverError> {
        let code: PairingCode =
            code.parse().map_err(|_| ApproverError::MalformedCode)?;
        let mut attempts = self.attempts_remaining.lock().await;
        if Instant::now() >= self.expires_at {
            *attempts = 0;
            return Err(ApproverError::Expired);
        }
        let Some(attempts_remaining) = attempts.checked_sub(1) else {
            return Err(ApproverError::Expired);
        };
        *attempts = attempts_remaining;
        let transport_key = self.uri.secret.transport_key(&code).inspect_err(|_| {
            *attempts = 0;
        })?;
        let plaintext = match transport_key.decrypt_request(&self.encrypted) {
            Ok(plaintext) => plaintext,
            Err(TransportError::Decrypt) => {
                return Err(ApproverError::IncorrectCode { attempts_remaining })
            }
            Err(error) => {
                *attempts = 0;
                return Err(error.into());
            }
        };
        *attempts = 0;
        drop(attempts);
        let request_id = self.uri.secret.request_id();
        match parse_request(&plaintext, &request_id, &self.uri.digest) {
            Ok(request) => Ok(Arc::new(IncomingRegistration {
                channel: Mutex::new(Some(
                    self.channel(transport_key, request.response_pubkey.clone()),
                )),
                respond_by: self
                    .expires_at
                    .checked_sub(RESPONSE_MARGIN)
                    .unwrap_or(self.expires_at),
                request,
            })),
            Err(invalid) => {
                let delivered = match invalid.reply {
                    Some((id, response_pubkey)) => {
                        let error =
                            invalid.reason.into_error(Some(invalid.problem.clone()));
                        self.channel(transport_key, *response_pubkey)
                            .send(Response::error(id, error))
                            .await
                    }
                    None => false,
                };
                tracing::warn!(
                    request = %log_tag(&request_id),
                    reason = ?invalid.reason,
                    problem = invalid.problem,
                    delivered,
                    "invalid registration request"
                );
                Err(ApproverError::InvalidRequest {
                    problem: invalid.problem,
                    delivered,
                })
            }
        }
    }
}

impl PendingRegistration {
    /// Builds the single-use response channel for this request.
    fn channel(
        &self,
        transport_key: TransportKey,
        response_pubkey: ResponsePublicKey,
    ) -> ResponseChannel {
        ResponseChannel {
            request_id: self.uri.secret.request_id(),
            response_pubkey,
            transport_key,
            bridge: self.bridge.clone(),
            expires_at: self.expires_at,
        }
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl IncomingRegistration {
    /// Returns the class the new authenticator asks for.
    #[must_use]
    pub const fn class(&self) -> RequestedClass {
        requested_class(&self.request)
    }

    /// Returns the name the new authenticator asks for. It is untrusted and must be displayed as
    /// such.
    #[must_use]
    pub fn name(&self) -> Option<String> {
        requested_name(&self.request)
    }

    /// Returns how many seconds are left until the response is due.
    #[must_use]
    pub fn time_remaining_secs(&self) -> u64 {
        secs_until(self.respond_by)
    }

    /// Reads the account state of `approver` and plans the registration (WIP-109 §3.7.2).
    ///
    /// # Errors
    ///
    /// Returns [`ApproverError::Refused`] after answering with the reason if `approver` is not an
    /// Admin Authenticator of its account (`not_authorized`), the key or address is registered
    /// differently on the account (`authenticator_conflict`), there is no free slot
    /// (`max_authenticators_reached`), or the account state cannot be read in time
    /// (`internal_error`), and [`ApproverError::AlreadyHandled`] if the request was already
    /// checked or rejected.
    pub async fn check(
        &self,
        approver: &Authenticator,
    ) -> Result<Arc<CheckedRegistration>, ApproverError> {
        let channel = take(&self.channel)?;
        let core = &approver.inner;
        match self.plan(approver).await {
            Ok((authenticators, plan)) => Ok(Arc::new(CheckedRegistration {
                request: self.request.clone(),
                respond_by: self.respond_by,
                approver_leaf_index: core.leaf_index(),
                approver_pubkey: core.offchain_pubkey(),
                approver_address: core.onchain_address(),
                authenticators,
                plan,
                channel: Mutex::new(Some(channel)),
            })),
            Err(refusal) => {
                tracing::warn!(
                    request = %log_tag(&channel.request_id),
                    reason = ?refusal.reason,
                    error = refusal.cause.as_ref().map(tracing::field::display),
                    "refusing authenticator registration"
                );
                let delivered = channel.answer(Err(refusal.to_error())).await;
                Err(ApproverError::Refused {
                    reason: refusal.reason,
                    failure: refusal.cause.map(|cause| (*cause).into()),
                    delivered,
                })
            }
        }
    }

    /// Refuses a request whose `name` the host does not accept, with `invalid_name`. Returns
    /// whether the answer was delivered.
    ///
    /// # Errors
    ///
    /// Returns [`ApproverError::AlreadyHandled`] if the request was already checked or rejected.
    pub async fn reject_name(&self) -> Result<bool, ApproverError> {
        let channel = take(&self.channel)?;
        Ok(channel
            .answer(Err(RegistrationErrorReason::InvalidName.into_error(None)))
            .await)
    }
}

impl IncomingRegistration {
    /// Returns the request. Its `name` is untrusted and must be displayed as such.
    #[must_use]
    pub const fn request(&self) -> &RegistrationRequest {
        &self.request
    }

    /// Fetches the approver's account authenticators and computes the registration plan.
    async fn plan(
        &self,
        approver: &Authenticator,
    ) -> Result<(AccountAuthenticators, RegistrationPlan), Refusal> {
        let core = &approver.inner;
        let authenticators =
            match self.before_deadline(core.fetch_authenticators()).await? {
                Ok(authenticators) => authenticators,
                Err(AuthenticatorError::AccountDoesNotExist) => {
                    return Err(RegistrationErrorReason::NotAuthorized.into());
                }
                Err(error) => return Err(Refusal::internal_error(error)),
            };
        let plan = plan_registration(
            &authenticators,
            &core.offchain_pubkey(),
            core.onchain_address(),
            &self.request,
        )?;
        Ok((authenticators, plan))
    }

    /// Runs `future` until the response is due, and refuses with `internal_error` after that.
    async fn before_deadline<F: Future>(
        &self,
        future: F,
    ) -> Result<F::Output, Refusal> {
        before(self.respond_by, future)
            .await
            .ok_or_else(|| RegistrationErrorReason::InternalError.into())
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl CheckedRegistration {
    /// Returns the class the new authenticator asks for.
    #[must_use]
    pub const fn class(&self) -> RequestedClass {
        requested_class(&self.request)
    }

    /// Returns the name the new authenticator asks for. It is untrusted and must be displayed as
    /// such.
    #[must_use]
    pub fn name(&self) -> Option<String> {
        requested_name(&self.request)
    }

    /// Returns how the registration will be carried out.
    #[must_use]
    pub const fn plan(&self) -> RegistrationPlan {
        self.plan
    }

    /// Returns how many seconds are left until the response is due, e.g. to show how long the
    /// user has to decide.
    #[must_use]
    pub fn time_remaining_secs(&self) -> u64 {
        secs_until(self.respond_by)
    }

    /// Declines with `user_rejected`, because the user rejected the request or cancelled the
    /// platform's user verification (WIP-109 §3.7.3). Returns whether the answer was delivered.
    ///
    /// # Errors
    ///
    /// Returns [`ApproverError::AlreadyHandled`] if the registration was already decided.
    pub async fn reject(&self) -> Result<bool, ApproverError> {
        self.decline(RegistrationErrorReason::UserRejected).await
    }

    /// Ends the registration with `internal_error`, e.g. because the platform's user
    /// verification failed or is unavailable (WIP-109 §3.7.3). Returns whether the answer was
    /// delivered.
    ///
    /// # Errors
    ///
    /// Returns [`ApproverError::AlreadyHandled`] if the registration was already decided.
    pub async fn abort(&self) -> Result<bool, ApproverError> {
        self.decline(RegistrationErrorReason::InternalError).await
    }

    /// Carries out the registration and sends the response (WIP-109 §3.7.4 and §3.7.5).
    ///
    /// Call it only after the user consented and the platform's user verification succeeded,
    /// also for an authenticator that is already registered (WIP-109 §3.7.3). `vault` is the
    /// `CredentialStore::export_vault_for_backup` output, only if the user chose to share it; a
    /// vault over [`MAX_VAULT_SIZE`] is left out. `authenticators` names the account's other
    /// authenticators.
    ///
    /// Unless the authenticator is already registered, this submits `InsertAuthenticator` and
    /// tracks it until it is final on-chain or definitively failed. An insertion is never
    /// retried. If its outcome is still unknown when the response is due, the answer is
    /// `outcome_unknown`. If less than two minutes are left, nothing is submitted and the answer
    /// is `internal_error`.
    ///
    /// # Errors
    ///
    /// Returns [`ApproverError::ApproverMismatch`] if `approver` is not the authenticator that
    /// [`IncomingRegistration::check`] checked, or [`ApproverError::AlreadyHandled`] if the
    /// registration was already decided.
    pub async fn approve(
        &self,
        approver: &Authenticator,
        vault: Option<Vec<u8>>,
        authenticators: Vec<KnownAuthenticator>,
    ) -> Result<ApprovalOutcome, ApproverError> {
        let vault = vault.map(Zeroizing::new);
        let core = &approver.inner;
        if core.leaf_index() != self.approver_leaf_index
            || core.offchain_pubkey().pk != self.approver_pubkey.pk
            || core.onchain_address() != self.approver_address
        {
            return Err(ApproverError::ApproverMismatch);
        }
        let channel = take(&self.channel)?;
        let vault_omitted = vault
            .as_ref()
            .is_some_and(|data| data.len() > MAX_VAULT_SIZE);
        let mut result = RegistrationResult {
            leaf_index: self.approver_leaf_index,
            // Every valid slot encodes to the same single CBOR byte, so checking the size with
            // this placeholder holds for the slot that registration assigns.
            pubkey_id: 0,
            authenticators,
            vault: vault.filter(|_| !vault_omitted).map(|data| Vault {
                format: PLAINTEXT_VAULT_FORMAT.to_string(),
                data,
            }),
        };
        let registered = self.register(approver, &channel, &result).await;
        let delivered = match &registered {
            Ok(pubkey_id) => {
                result.pubkey_id = *pubkey_id;
                channel.answer(Ok(&result)).await
            }
            Err(refusal) => {
                tracing::warn!(
                    request = %log_tag(&channel.request_id),
                    reason = ?refusal.reason,
                    detail = refusal.detail,
                    error = refusal.cause.as_ref().map(tracing::field::display),
                    "authenticator registration did not succeed"
                );
                channel.answer(Err(refusal.to_error())).await
            }
        };
        Ok(ApprovalOutcome {
            result: match registered {
                Ok(pubkey_id) => ApprovalResult::Registered {
                    leaf_index: result.leaf_index,
                    pubkey_id,
                },
                Err(refusal) => ApprovalResult::Failed {
                    reason: refusal.reason,
                },
            },
            vault_omitted,
            delivered,
        })
    }
}

impl CheckedRegistration {
    /// Returns the request.
    #[must_use]
    pub const fn request(&self) -> &RegistrationRequest {
        &self.request
    }

    /// Declines the registration with `reason` and delivers the error response.
    async fn decline(
        &self,
        reason: RegistrationErrorReason,
    ) -> Result<bool, ApproverError> {
        let channel = take(&self.channel)?;
        Ok(channel.answer(Err(reason.into_error(None))).await)
    }

    /// Registers the authenticator as planned and returns its slot.
    async fn register(
        &self,
        approver: &Authenticator,
        channel: &ResponseChannel,
        result: &RegistrationResult,
    ) -> Result<u32, Refusal> {
        // Checked before submitting, so that an oversized response cannot leave a registered
        // authenticator that never learns its result.
        let response: Response<_, RegistrationErrorData> =
            Response::success(channel.request_id.message_id(), result);
        if !response
            .encode()
            .map(Zeroizing::new)
            .is_ok_and(|encoded| encoded.len() <= MAX_RESPONSE_SIZE)
        {
            return Err(Refusal::from(RegistrationErrorReason::InternalError)
                .with_detail("the approval exceeds the response size limit"));
        }
        match self.plan {
            RegistrationPlan::AlreadyRegistered { pubkey_id } => Ok(pubkey_id),
            RegistrationPlan::Insert { .. }
                if self.respond_by.saturating_duration_since(Instant::now())
                    < MIN_TRACKING_TIME =>
            {
                Err(Refusal::from(RegistrationErrorReason::InternalError)
                    .with_detail("approved too close to the session expiry"))
            }
            RegistrationPlan::Insert { pubkey_id } => {
                self.insert(approver, channel, pubkey_id).await
            }
        }
    }

    /// Submits `InsertAuthenticator` and tracks it until it is final, definitively failed, or
    /// the response is due (WIP-109 §3.7.4).
    async fn insert(
        &self,
        approver: &Authenticator,
        channel: &ResponseChannel,
        pubkey_id: u32,
    ) -> Result<u32, Refusal> {
        let core = &approver.inner;
        let respond_by = self.respond_by;
        let request = &self.request;
        let submission = core.insert_authenticator_at(
            self.authenticators.key_set(),
            pubkey_id,
            request.new_authenticator_pubkey.clone(),
            onchain_address(request),
        );
        let insertion = before(respond_by, submission)
            .await
            .ok_or_else(|| Refusal::from(RegistrationErrorReason::OutcomeUnknown))?
            .map_err(classify_submission_error)?;

        let mut submitted = false;
        for delay in polling_backoff().build() {
            let Some(status) = before(respond_by, core.poll_status(&insertion)).await
            else {
                break;
            };
            match status {
                Ok(GatewayRequestState::Finalized { .. }) => {
                    return self.confirm_registration(approver, channel).await;
                }
                Ok(GatewayRequestState::Failed { error_code, .. }) => {
                    return Err(classify_failure(error_code.as_ref(), submitted));
                }
                Ok(GatewayRequestState::Submitted { .. }) => submitted = true,
                Ok(GatewayRequestState::Queued | GatewayRequestState::Batching) => {}
                Err(error) => tracing::warn!(
                    request = %log_tag(&channel.request_id),
                    %error,
                    "failed to poll the gateway request"
                ),
            }
            if before(respond_by, sleep(delay)).await.is_none() {
                break;
            }
        }
        tracing::warn!(
            request = %log_tag(&channel.request_id),
            gateway_request_id = %insertion,
            submitted,
            "insertion outcome unknown at the response deadline"
        );
        Err(RegistrationErrorReason::OutcomeUnknown.into())
    }

    /// Refreshes the account state until it shows the inserted authenticator, and returns its
    /// slot (WIP-109 §3.7.4 step 5).
    async fn confirm_registration(
        &self,
        approver: &Authenticator,
        channel: &ResponseChannel,
    ) -> Result<u32, Refusal> {
        let request = &self.request;
        for delay in polling_backoff().build() {
            let Some(authenticators) =
                before(self.respond_by, approver.inner.fetch_authenticators()).await
            else {
                break;
            };
            match authenticators {
                Ok(authenticators) => {
                    if let Some((slot, address)) =
                        authenticators.find(&request.new_authenticator_pubkey)
                    {
                        return if address == onchain_address(request) {
                            Ok(slot)
                        } else {
                            Err(RegistrationErrorReason::AuthenticatorConflict.into())
                        };
                    }
                }
                Err(error) => tracing::warn!(
                    request = %log_tag(&channel.request_id),
                    %error,
                    "failed to refresh the account state after the insertion"
                ),
            }
            if before(self.respond_by, sleep(delay)).await.is_none() {
                break;
            }
        }
        tracing::warn!(
            request = %log_tag(&channel.request_id),
            "finalized registration not visible before the response deadline"
        );
        Err(RegistrationErrorReason::OutcomeUnknown.into())
    }
}

impl ResponseChannel {
    /// Answers the request with `answer`, correlated with its id.
    async fn answer(
        &self,
        answer: Result<&RegistrationResult, ErrorObject<RegistrationErrorData>>,
    ) -> bool {
        let id = self.request_id.message_id();
        self.send(match answer {
            Ok(result) => Response::success(id, result),
            Err(error) => Response::error(Some(id), error),
        })
        .await
    }

    /// Seals and delivers `response` before the session expires, and returns whether it was
    /// delivered.
    async fn send(
        &self,
        response: Response<&RegistrationResult, RegistrationErrorData>,
    ) -> bool {
        let delivery = Box::pin(async {
            let encoded = Zeroizing::new(response.encode()?);
            let sealed = self
                .transport_key
                .encrypt_response(&self.response_pubkey, &encoded)?;
            before(
                self.expires_at,
                self.bridge.put_response(&self.request_id, &sealed),
            )
            .await
            .unwrap_or(Err(BridgeError::Timeout))?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        })
        .await;
        if let Err(error) = &delivery {
            tracing::warn!(
                request = %log_tag(&self.request_id),
                %error,
                "failed to deliver the registration response"
            );
        }
        delivery.is_ok()
    }
}

impl Refusal {
    /// A refusal with `internal_error`, because reading the account state failed.
    fn internal_error(cause: AuthenticatorError) -> Self {
        Self {
            cause: Some(Box::new(cause)),
            ..RegistrationErrorReason::InternalError.into()
        }
    }

    /// Attaches an implementation-specific detail message to the refusal.
    fn with_detail(self, detail: impl Into<String>) -> Self {
        Self {
            detail: Some(detail.into()),
            ..self
        }
    }

    /// Converts this refusal into a WIP-109 error object.
    fn to_error(&self) -> ErrorObject<RegistrationErrorData> {
        self.reason.into_error(self.detail.clone())
    }
}

impl From<RegistrationErrorReason> for Refusal {
    /// Builds a [`Refusal`] with no detail or underlying cause.
    fn from(reason: RegistrationErrorReason) -> Self {
        Self {
            reason,
            detail: None,
            cause: None,
        }
    }
}

/// Takes the response channel for the step that moves the registration on.
fn take(
    channel: &Mutex<Option<ResponseChannel>>,
) -> Result<ResponseChannel, ApproverError> {
    channel
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .take()
        .ok_or(ApproverError::AlreadyHandled)
}

/// Returns the authenticator class requested by `request`.
const fn requested_class(request: &RegistrationRequest) -> RequestedClass {
    if request.new_authenticator_address.is_some() {
        RequestedClass::Admin
    } else {
        RequestedClass::Proving
    }
}

/// Extracts the requested display name as a `String`, if present.
fn requested_name(request: &RegistrationRequest) -> Option<String> {
    request.name.as_ref().map(|name| name.as_str().to_string())
}

/// Returns the whole seconds remaining before `deadline`, or zero if it has passed.
fn secs_until(deadline: Instant) -> u64 {
    deadline.saturating_duration_since(Instant::now()).as_secs()
}

/// Decodes and validates a decrypted request in the order of WIP-109 §3.7.1 step 4: CBOR
/// (`parse_error`), envelope and id (`invalid_request`), method (`method_not_found`), then
/// params and the Pairing URI's digest (`invalid_params`).
///
/// An invalid request is answered only if it carries an unambiguous, valid
/// `params.response_pubkey` to seal the answer to. A notification is never answered.
fn parse_request(
    plaintext: &[u8],
    request_id: &RequestId,
    uri_digest: &RegistrationDigest,
) -> Result<RegistrationRequest, InvalidRequest> {
    let value = decode_value(plaintext).map_err(|error| InvalidRequest {
        reason: RegistrationErrorReason::ParseError,
        problem: error.to_string(),
        reply: None,
    })?;
    let response_pubkey = response_pubkey_of(&value).map(Box::new);
    let invalid = |reason, id: Option<&Id>, problem: &dyn Display| InvalidRequest {
        reason,
        problem: problem.to_string(),
        reply: response_pubkey.clone().map(|key| (id.cloned(), key)),
    };
    let envelope: Request<Value> = value.deserialized().map_err(|error| {
        invalid(RegistrationErrorReason::InvalidRequest, None, &error)
    })?;
    let Some(id) = &envelope.id else {
        return Err(InvalidRequest {
            reason: RegistrationErrorReason::InvalidRequest,
            problem: "the request is a notification".to_string(),
            reply: None,
        });
    };
    let invalid = |reason, problem: &dyn Display| invalid(reason, Some(id), problem);
    if *id != request_id.message_id() {
        return Err(invalid(
            RegistrationErrorReason::InvalidRequest,
            &"the request id does not match the pairing link",
        ));
    }
    if envelope.method != REGISTER_METHOD {
        return Err(invalid(
            RegistrationErrorReason::MethodNotFound,
            &format_args!("unexpected method {}", envelope.method.as_str()),
        ));
    }
    let invalid_params = |problem: &dyn Display| {
        invalid(RegistrationErrorReason::InvalidParams, problem)
    };
    let params = envelope
        .params
        .as_ref()
        .ok_or_else(|| invalid_params(&"missing params"))?;
    let request = RegistrationRequest::from_params(params)
        .map_err(|error| invalid_params(&error))?;
    let digest = request
        .digest(request_id)
        .map_err(|error| invalid_params(&error))?;
    if digest != *uri_digest {
        return Err(invalid_params(
            &"the request does not match the pairing link",
        ));
    }
    if !request.verify_signature(&digest) {
        return Err(invalid_params(&"invalid registration_sig"));
    }
    Ok(request)
}

/// Decodes bounded CBOR without a schema, so that an invalid request keeps its error class and
/// its response key.
fn decode_value(plaintext: &[u8]) -> Result<Value, MessageError> {
    if plaintext.len() > MAX_REQUEST_SIZE {
        return Err(MessageError::TooLarge);
    }
    let mut remaining = plaintext;
    let value = ciborium::de::from_reader_with_recursion_limit(
        &mut remaining,
        RECURSION_LIMIT,
    )?;
    if !remaining.is_empty() {
        return Err(MessageError::TrailingData);
    }
    Ok(value)
}

/// Reads `params.response_pubkey` from a request that may fail validation.
fn response_pubkey_of(request: &Value) -> Option<ResponsePublicKey> {
    let key = unique_field(unique_field(request, "params")?, "response_pubkey")?
        .as_bytes()?;
    ResponsePublicKey::from_bytes(key).ok()
}

/// Returns the value of `key` in `map`, if `map` is a map that has it exactly once.
fn unique_field<'a>(map: &'a Value, key: &str) -> Option<&'a Value> {
    let mut values = map
        .as_map()?
        .iter()
        .filter(|(k, _)| k.as_text() == Some(key))
        .map(|(_, value)| value);
    let value = values.next()?;
    values.next().is_none().then_some(value)
}

/// Decides how to register the requested authenticator on the account, for the approver with
/// `approver_pubkey` and management key `approver_address` (WIP-109 §3.7.2 steps 2 to 5).
fn plan_registration(
    authenticators: &AccountAuthenticators,
    approver_pubkey: &world_id_core::EdDSAPublicKey,
    approver_address: Address,
    request: &RegistrationRequest,
) -> Result<RegistrationPlan, RegistrationErrorReason> {
    if authenticators
        .find(approver_pubkey)
        .map(|(_, address)| address)
        != Some(approver_address)
    {
        return Err(RegistrationErrorReason::NotAuthorized);
    }
    if let Some((pubkey_id, address)) =
        authenticators.find(&request.new_authenticator_pubkey)
    {
        return if address == onchain_address(request) {
            Ok(RegistrationPlan::AlreadyRegistered { pubkey_id })
        } else {
            Err(RegistrationErrorReason::AuthenticatorConflict)
        };
    }
    if request
        .new_authenticator_address
        .is_some_and(|address| authenticators.addresses().contains(&Some(address)))
    {
        return Err(RegistrationErrorReason::AuthenticatorConflict);
    }
    authenticators
        .lowest_free_pubkey_id()
        .map(|pubkey_id| RegistrationPlan::Insert { pubkey_id })
        .ok_or(RegistrationErrorReason::MaxAuthenticatorsReached)
}

/// The address the registry records for the requested authenticator: its management key, or the
/// zero address for a Proving Authenticator (WIP-104).
fn onchain_address(request: &RegistrationRequest) -> Address {
    request.new_authenticator_address.unwrap_or(Address::ZERO)
}

/// Classifies a failure to submit `InsertAuthenticator`.
///
/// The gateway answering with a client error is definitive. Failing before anything was sent is
/// an internal error. Any other failure may have happened after the gateway accepted the
/// operation, so its outcome is unknown.
fn classify_submission_error(error: AuthenticatorError) -> Refusal {
    let (reason, code) = match &error {
        AuthenticatorError::MaxAuthenticatorsReached => {
            (RegistrationErrorReason::MaxAuthenticatorsReached, None)
        }
        AuthenticatorError::PrimitiveError(_) => {
            (RegistrationErrorReason::InternalError, None)
        }
        AuthenticatorError::GatewayError { status, body }
            if status.is_client_error() =>
        {
            let code = serde_json::from_str::<ServiceApiError<GatewayErrorCode>>(body)
                .map(|error| error.code)
                .ok();
            let reason = match code {
                Some(GatewayErrorCode::AuthenticatorAlreadyExists) => {
                    RegistrationErrorReason::AuthenticatorConflict
                }
                Some(GatewayErrorCode::PubkeyIdOutOfBounds) => {
                    RegistrationErrorReason::MaxAuthenticatorsReached
                }
                _ => RegistrationErrorReason::OperationFailed,
            };
            (reason, code)
        }
        _ => (RegistrationErrorReason::OutcomeUnknown, None),
    };
    Refusal {
        reason,
        detail: code.map(|code| code.to_string()),
        cause: Some(Box::new(error)),
    }
}

/// Classifies a gateway request that ended as failed.
///
/// A revert is definitive. Before the transaction was submitted, only the registry's own checks
/// are definitive. Any other failure, including the gateway's catch-all `bad_request` for errors
/// sending the transaction, may still land on-chain.
fn classify_failure(error_code: Option<&GatewayErrorCode>, submitted: bool) -> Refusal {
    let reason = match error_code {
        Some(GatewayErrorCode::TransactionReverted) => {
            RegistrationErrorReason::OperationFailed
        }
        _ if submitted => RegistrationErrorReason::OutcomeUnknown,
        Some(GatewayErrorCode::AuthenticatorAlreadyExists) => {
            RegistrationErrorReason::AuthenticatorConflict
        }
        Some(GatewayErrorCode::PubkeyIdOutOfBounds) => {
            RegistrationErrorReason::MaxAuthenticatorsReached
        }
        Some(
            GatewayErrorCode::MismatchedSignatureNonce
            | GatewayErrorCode::PubkeyIdInUse
            | GatewayErrorCode::AuthenticatorDoesNotBelongToAccount,
        ) => RegistrationErrorReason::OperationFailed,
        _ => RegistrationErrorReason::OutcomeUnknown,
    };
    Refusal {
        reason,
        detail: error_code.map(ToString::to_string),
        cause: None,
    }
}

#[cfg(test)]
mod tests {
    use axum::{
        http::StatusCode,
        routing::{get, post, put},
        Json, Router,
    };
    use secrecy::ExposeSecret as _;
    use serde_json::Value;
    use test_case::test_case;
    use tokio::net::TcpListener;
    use world_id_core::{
        api_types::IndexerAuthenticatorsResponse,
        artifacts::dummy::DummyZkArtifactSource,
        primitives::{AuthenticatorPublicKeySet, Config, ServiceEndpoint},
        registration::{PairingSecret, RegisterRequestMessage, ResponseSecretKey},
        OnchainKeyRepresentable as _, Signer,
    };

    use super::*;
    use crate::storage::{
        tests_utils::{temp_root_path, InMemoryStorageProvider},
        CredentialStore,
    };

    #[test_case(Some(&GatewayErrorCode::TransactionReverted), true => RegistrationErrorReason::OperationFailed; "a revert is definitive")]
    #[test_case(Some(&GatewayErrorCode::PubkeyIdInUse), true => RegistrationErrorReason::OutcomeUnknown; "a broadcast transaction may still land")]
    #[test_case(None, true => RegistrationErrorReason::OutcomeUnknown; "an unexplained failure after broadcast")]
    #[test_case(Some(&GatewayErrorCode::PubkeyIdInUse), false => RegistrationErrorReason::OperationFailed; "a registry check before broadcast")]
    #[test_case(Some(&GatewayErrorCode::AuthenticatorAlreadyExists), false => RegistrationErrorReason::AuthenticatorConflict; "an existing authenticator before broadcast")]
    #[test_case(Some(&GatewayErrorCode::BadRequest), false => RegistrationErrorReason::OutcomeUnknown; "the catch-all may hide a sent transaction")]
    fn gateway_failures_are_definitive_only_when_nothing_can_land(
        error_code: Option<&GatewayErrorCode>,
        submitted: bool,
    ) -> RegistrationErrorReason {
        classify_failure(error_code, submitted).reason
    }

    async fn serve(app: Router) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        url
    }

    async fn make_pending_registration() -> (Arc<PendingRegistration>, String, [u8; 32])
    {
        let requester_seed = [11u8; 32];
        let signer = Signer::from_seed_bytes(&requester_seed).unwrap();
        let pairing_secret = PairingSecret::generate().unwrap();
        let code = PairingCode::generate();
        let transport_key = pairing_secret.transport_key(&code).unwrap();
        let response_key = ResponseSecretKey::generate().unwrap();
        let request_id = pairing_secret.request_id();
        let (request, digest) = RegistrationRequest::new_signed(
            signer.offchain_signer_private_key().expose_secret(),
            None,
            response_key.public_key(),
            None,
            &request_id,
        )
        .unwrap();
        let plaintext = RegisterRequestMessage::new(
            Some(request_id.message_id()),
            REGISTER_METHOD,
            Some(request),
        )
        .encode()
        .unwrap();
        let encrypted = transport_key.encrypt_request(&plaintext).unwrap();
        let body = serde_json::to_value(&encrypted).unwrap();
        let app = Router::new()
            .route(
                "/request/{id}",
                get(move || {
                    let body = body.clone();
                    async move { Json::<Value>(body) }
                }),
            )
            .route("/response/{id}", put(|| async { StatusCode::CREATED }));
        let url = serve(app).await;
        let bridge =
            Arc::new(BridgeClient::with_base_url("bridge.example", &url).unwrap());
        let uri = PairingUri {
            secret: pairing_secret,
            digest,
            bridge: "bridge.example".parse().unwrap(),
        }
        .to_string();
        let pending = PendingRegistration::receive(&uri, vec![bridge])
            .await
            .unwrap();
        (Arc::new(pending), code.as_str().to_string(), requester_seed)
    }

    async fn make_test_authenticator(seed: [u8; 32], leaf_index: u64) -> Authenticator {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let signer = Signer::from_seed_bytes(&seed).unwrap();
        let pubkey = signer.offchain_signer_pubkey();
        let encoded = pubkey.to_ethereum_representation().unwrap();
        let commitment = AuthenticatorPublicKeySet::new(vec![pubkey])
            .unwrap()
            .leaf_hash()
            .into();
        let address = signer.onchain_signer_address();
        let indexer_url = serve(Router::new().route(
            "/authenticators",
            post(move || async move {
                Json(IndexerAuthenticatorsResponse {
                    authenticator_pubkeys: vec![Some(encoded)],
                    authenticator_addresses: vec![Some(address)],
                    offchain_signer_commitment: commitment,
                    recovery_counter: 0,
                })
            }),
        ))
        .await;
        let config = Config::new(
            None,
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
        let authenticator = Authenticator::init_with_leaf_index_and_config(
            &seed,
            leaf_index,
            config,
            Arc::new(DummyZkArtifactSource),
            store,
        )
        .await
        .unwrap();
        let _ = std::fs::remove_dir_all(root);
        authenticator
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_authenticate_calls_only_advance_once() {
        let (pending, code, _) = make_pending_registration().await;
        let first = {
            let pending = pending.clone();
            let code = code.clone();
            tokio::spawn(async move { pending.authenticate(&code).await })
        };
        let second = {
            let pending = pending.clone();
            tokio::spawn(async move { pending.authenticate(&code).await })
        };
        let (res_a, res_b) = tokio::join!(first, second);
        let (res_a, res_b) = (res_a.unwrap(), res_b.unwrap());
        assert_eq!(
            usize::from(res_a.is_ok()) + usize::from(res_b.is_ok()),
            1,
            "exactly one concurrent authenticate call may succeed: {res_a:?}, {res_b:?}"
        );
        let err = res_a.err().or_else(|| res_b.err()).unwrap();
        assert!(matches!(err, ApproverError::Expired), "{err:?}");
    }

    #[tokio::test]
    async fn approve_rejects_mismatched_approver_without_consuming_channel() {
        let (pending, code, _) = make_pending_registration().await;
        let request_id = pending.uri.secret.request_id().to_string();
        assert!(!format!("{pending:?}").contains(&request_id));

        let incoming = pending.authenticate(&code).await.unwrap();
        assert!(!format!("{incoming:?}").contains(&request_id));

        let approver_a = make_test_authenticator([21u8; 32], 1).await;
        let approver_b = make_test_authenticator([22u8; 32], 2).await;

        let checked = incoming.check(&approver_a).await.unwrap();
        assert!(!format!("{checked:?}").contains(&request_id));
        let err = checked
            .approve(&approver_b, Some(vec![1, 2, 3]), Vec::new())
            .await
            .unwrap_err();
        assert!(matches!(err, ApproverError::ApproverMismatch), "{err:?}");

        // Channel was not consumed by the rejected call, so declining still delivers.
        assert!(checked.reject().await.unwrap());
    }

    fn make_account(
        slots: &[(world_id_core::EdDSAPublicKey, Address)],
    ) -> AccountAuthenticators {
        let pks = slots.iter().map(|(pk, _)| pk.clone()).collect();
        let encs = slots
            .iter()
            .map(|(pk, _)| Some(pk.to_ethereum_representation().unwrap()))
            .collect();
        let addrs = slots.iter().map(|(_, addr)| Some(*addr)).collect();
        let commitment = AuthenticatorPublicKeySet::new(pks)
            .unwrap()
            .leaf_hash()
            .into();
        AccountAuthenticators::try_from(IndexerAuthenticatorsResponse {
            authenticator_pubkeys: encs,
            authenticator_addresses: addrs,
            offchain_signer_commitment: commitment,
            recovery_counter: 0,
        })
        .unwrap()
    }

    #[test]
    fn plan_registration_checks_authorization_conflicts_capacity_and_idempotency() {
        let admin = Signer::from_seed_bytes(&[41u8; 32]).unwrap();
        let other = Signer::from_seed_bytes(&[42u8; 32]).unwrap();
        let candidate = Signer::from_seed_bytes(&[43u8; 32]).unwrap();
        let (admin_pk, other_pk, candidate_pk) = (
            admin.offchain_signer_pubkey(),
            other.offchain_signer_pubkey(),
            candidate.offchain_signer_pubkey(),
        );
        let (admin_addr, other_addr, candidate_addr) = (
            admin.onchain_signer_address(),
            other.onchain_signer_address(),
            candidate.onchain_signer_address(),
        );

        let request_id = PairingSecret::generate().unwrap().request_id();
        let make_req = |signer: &Signer, addr: Option<Address>| {
            RegistrationRequest::new_signed(
                signer.offchain_signer_private_key().expose_secret(),
                addr,
                ResponseSecretKey::generate().unwrap().public_key(),
                None,
                &request_id,
            )
            .unwrap()
            .0
        };
        let proving_req = make_req(&candidate, None);
        let admin_req = make_req(&candidate, Some(candidate_addr));
        let colliding_addr_req = make_req(&candidate, Some(other_addr));

        let two_slot =
            make_account(&[(admin_pk.clone(), admin_addr), (other_pk, other_addr)]);
        assert_eq!(
            plan_registration(&two_slot, &candidate_pk, candidate_addr, &proving_req),
            Err(RegistrationErrorReason::NotAuthorized)
        );
        assert_eq!(
            plan_registration(&two_slot, &admin_pk, Address::ZERO, &proving_req),
            Err(RegistrationErrorReason::NotAuthorized)
        );
        assert_eq!(
            plan_registration(&two_slot, &admin_pk, admin_addr, &colliding_addr_req),
            Err(RegistrationErrorReason::AuthenticatorConflict)
        );

        let with_candidate = make_account(&[
            (admin_pk.clone(), admin_addr),
            (candidate_pk, Address::ZERO),
        ]);
        assert_eq!(
            plan_registration(&with_candidate, &admin_pk, admin_addr, &proving_req),
            Ok(RegistrationPlan::AlreadyRegistered { pubkey_id: 1 })
        );
        assert_eq!(
            plan_registration(&with_candidate, &admin_pk, admin_addr, &admin_req),
            Err(RegistrationErrorReason::AuthenticatorConflict)
        );

        let mut full_slots = vec![(admin_pk.clone(), admin_addr)];
        for i in 1..7u8 {
            let s = Signer::from_seed_bytes(&[50 + i; 32]).unwrap();
            full_slots.push((s.offchain_signer_pubkey(), Address::ZERO));
        }
        let full = make_account(&full_slots);
        assert_eq!(
            plan_registration(&full, &admin_pk, admin_addr, &proving_req),
            Err(RegistrationErrorReason::MaxAuthenticatorsReached)
        );
        let existing_sixth = Signer::from_seed_bytes(&[56u8; 32]).unwrap();
        let existing_req = make_req(&existing_sixth, None);
        assert_eq!(
            plan_registration(&full, &admin_pk, admin_addr, &existing_req),
            Ok(RegistrationPlan::AlreadyRegistered { pubkey_id: 6 })
        );
    }

    #[tokio::test]
    async fn approve_reports_outcome_unknown_without_retrying_ambiguous_submission() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (pending, code, _) = make_pending_registration().await;
        let incoming = pending.authenticate(&code).await.unwrap();

        let seed = [61u8; 32];
        let signer = Signer::from_seed_bytes(&seed).unwrap();
        let pubkey = signer.offchain_signer_pubkey();
        let encoded = pubkey.to_ethereum_representation().unwrap();
        let commitment = AuthenticatorPublicKeySet::new(vec![pubkey])
            .unwrap()
            .leaf_hash()
            .into();
        let address = signer.onchain_signer_address();
        let submissions = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let submissions_clone = submissions.clone();
        let service_url = serve(
            Router::new()
                .route(
                    "/authenticators",
                    post(move || async move {
                        Json(IndexerAuthenticatorsResponse {
                            authenticator_pubkeys: vec![Some(encoded)],
                            authenticator_addresses: vec![Some(address)],
                            offchain_signer_commitment: commitment,
                            recovery_counter: 0,
                        })
                    }),
                )
                .route(
                    "/signature-nonce",
                    post(|| async {
                        Json(serde_json::json!({ "signature_nonce": "0x0" }))
                    }),
                )
                .route(
                    "/insert-authenticator",
                    post(move || {
                        let submissions = submissions_clone.clone();
                        async move {
                            submissions
                                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            StatusCode::SERVICE_UNAVAILABLE
                        }
                    }),
                ),
        )
        .await;
        let config = Config::new(
            None,
            480,
            Address::with_last_byte(1),
            ServiceEndpoint::direct(service_url.clone()),
            ServiceEndpoint::direct(service_url),
            Vec::new(),
            0,
        )
        .unwrap();
        let root = temp_root_path();
        let provider = InMemoryStorageProvider::new(&root);
        let store = Arc::new(CredentialStore::from_provider(&provider).unwrap());
        let approver = Authenticator::init_with_leaf_index_and_config(
            &seed,
            1,
            config,
            Arc::new(DummyZkArtifactSource),
            store,
        )
        .await
        .unwrap();
        let _ = std::fs::remove_dir_all(root);

        let checked = incoming.check(&approver).await.unwrap();
        let outcome = checked
            .approve(&approver, Some(vec![1, 2, 3]), Vec::new())
            .await
            .unwrap();
        assert_eq!(
            submissions.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "an ambiguous submission must never be retried"
        );
        assert_eq!(
            outcome.result,
            ApprovalResult::Failed {
                reason: RegistrationErrorReason::OutcomeUnknown
            }
        );
        assert!(outcome.delivered);
    }

    #[test]
    fn parse_request_validates_envelope_method_digest_signature_and_reply_key() {
        let signer = Signer::from_seed_bytes(&[71u8; 32]).unwrap();
        let other = Signer::from_seed_bytes(&[72u8; 32]).unwrap();
        let request_id = PairingSecret::generate().unwrap().request_id();
        let other_id = PairingSecret::generate().unwrap().request_id();
        let response_pk = ResponseSecretKey::generate().unwrap().public_key();
        let (valid_req, valid_digest) = RegistrationRequest::new_signed(
            signer.offchain_signer_private_key().expose_secret(),
            None,
            response_pk,
            None,
            &request_id,
        )
        .unwrap();

        let valid_bytes = RegisterRequestMessage::new(
            Some(request_id.message_id()),
            REGISTER_METHOD,
            Some(valid_req.clone()),
        )
        .encode()
        .unwrap();
        assert_eq!(
            parse_request(&valid_bytes, &request_id, &valid_digest).ok(),
            Some(valid_req.clone())
        );

        // Malformed CBOR: ParseError with no reply.
        let err = parse_request(&[0xff, 0x00], &request_id, &valid_digest).unwrap_err();
        assert_eq!(err.reason, RegistrationErrorReason::ParseError);
        assert!(err.reply.is_none());

        // Notification (id: None): InvalidRequest with no reply.
        let notif_bytes =
            RegisterRequestMessage::new(None, REGISTER_METHOD, Some(valid_req.clone()))
                .encode()
                .unwrap();
        let err = parse_request(&notif_bytes, &request_id, &valid_digest).unwrap_err();
        assert_eq!(err.reason, RegistrationErrorReason::InvalidRequest);
        assert!(err.reply.is_none());

        // Mismatched request id: InvalidRequest with reply key extracted.
        let wrong_id_bytes = RegisterRequestMessage::new(
            Some(other_id.message_id()),
            REGISTER_METHOD,
            Some(valid_req),
        )
        .encode()
        .unwrap();
        let err =
            parse_request(&wrong_id_bytes, &request_id, &valid_digest).unwrap_err();
        assert_eq!(err.reason, RegistrationErrorReason::InvalidRequest);
        assert!(err.reply.is_some());

        // Mismatched URI digest: InvalidParams with reply key extracted.
        let (_, other_digest) = RegistrationRequest::new_signed(
            other.offchain_signer_private_key().expose_secret(),
            None,
            ResponseSecretKey::generate().unwrap().public_key(),
            None,
            &request_id,
        )
        .unwrap();
        let err = parse_request(&valid_bytes, &request_id, &other_digest).unwrap_err();
        assert_eq!(err.reason, RegistrationErrorReason::InvalidParams);
        assert!(err.reply.is_some());
    }
}
