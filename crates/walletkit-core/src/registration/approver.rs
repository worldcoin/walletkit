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

use std::{fmt::Display, future::Future, time::Duration};

use alloy_core::primitives::Address;
use backon::BackoffBuilder as _;
use web_time::Instant;
use world_id_core::{
    primitives::{
        api_types::{GatewayErrorCode, GatewayRequestState, ServiceApiError},
        authenticator_message::{
            ErrorObject, Id, MessageError, Request, Response, Value,
        },
    },
    registration::{
        BridgeDomain, EncryptedPayload, KnownAuthenticator, PairingCode, PairingUri,
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
    log_tag, polling_backoff, sleep, PLAINTEXT_VAULT_FORMAT, SESSION_TTL,
};
use crate::Authenticator;

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
#[derive(Debug, thiserror::Error)]
pub enum ApproverError {
    /// The Pairing URI names a bridge the host does not allow. The host may ask the user to
    /// confirm it, then retry with a client for it (WIP-109 §3.4).
    #[error("bridge {0} is not allowed")]
    BridgeNotAllowed(BridgeDomain),
    /// The request expired or was already used. The user should create a new QR code or link
    /// on the new device.
    #[error("the registration request expired or was already used")]
    Expired,
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
        /// The failure behind the refusal, if there was one.
        #[source]
        cause: Option<Box<AuthenticatorError>>,
        /// Whether the reason was delivered.
        delivered: bool,
    },
    /// The bridge could not be reached or rejected an operation.
    #[error(transparent)]
    Bridge(#[from] BridgeError),
    /// Decrypting the request failed for a reason other than a wrong code.
    #[error(transparent)]
    Transport(#[from] TransportError),
}

/// How a checked registration will be carried out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
#[derive(Debug)]
pub struct ApprovalOutcome {
    /// The registration result, or the reason it failed. A successful result means that the
    /// authenticator is registered on-chain, even if the response was not delivered.
    pub result: Result<RegistrationResult, RegistrationErrorReason>,
    /// Whether the vault was left out because it exceeds [`MAX_VAULT_SIZE`]. The host must tell
    /// the user that the vault was not shared.
    pub vault_omitted: bool,
    /// Whether the response was delivered.
    pub delivered: bool,
}

/// An encrypted request taken from the bridge, waiting for code entry (WIP-109 §3.7.1).
#[derive(Debug)]
pub struct PendingRegistration {
    uri: PairingUri,
    encrypted: EncryptedPayload,
    bridge: BridgeClient,
    /// Estimated from when the request was taken (WIP-109 §3.5).
    expires_at: Instant,
    attempts_remaining: u8,
}

/// An authenticated, valid registration request.
#[derive(Debug)]
pub struct IncomingRegistration {
    request: RegistrationRequest,
    channel: ResponseChannel,
    respond_by: Instant,
}

/// A registration request whose account state was checked, waiting for the user's decision.
#[derive(Debug)]
pub struct CheckedRegistration {
    incoming: IncomingRegistration,
    authenticators: AccountAuthenticators,
    plan: RegistrationPlan,
}

/// Where and how to answer one request.
#[derive(Debug)]
struct ResponseChannel {
    request_id: RequestId,
    response_pubkey: ResponsePublicKey,
    transport_key: TransportKey,
    bridge: BridgeClient,
    expires_at: Instant,
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

impl PendingRegistration {
    /// Takes the encrypted request from the URI's bridge, before the host prompts for the code.
    ///
    /// The URI's bridge must be one of `allowed_bridges`. To contact another bridge, the host
    /// must first get the user's confirmation, then pass a client for it (WIP-109 §3.4).
    ///
    /// # Errors
    ///
    /// Returns [`ApproverError::BridgeNotAllowed`], [`ApproverError::Expired`] for a used or
    /// expired URI, or a bridge error.
    pub async fn receive(
        uri: &PairingUri,
        allowed_bridges: &[BridgeClient],
    ) -> Result<Self, ApproverError> {
        let bridge = allowed_bridges
            .iter()
            .find(|bridge| *bridge.domain() == uri.bridge)
            .ok_or_else(|| ApproverError::BridgeNotAllowed(uri.bridge.clone()))?
            .clone();
        let taken_at = Instant::now();
        let encrypted = bridge
            .take_request(&uri.secret.request_id())
            .await?
            .ok_or(ApproverError::Expired)?;
        Ok(Self {
            uri: uri.clone(),
            encrypted,
            bridge,
            expires_at: taken_at + SESSION_TTL,
            attempts_remaining: MAX_CODE_ATTEMPTS,
        })
    }

    /// Authenticates the request with `code`, then validates it (WIP-109 §3.7.1).
    ///
    /// This blocks while it derives the transport key with Argon2id (64 MiB). In a browser, call
    /// it from a Web Worker.
    ///
    /// # Errors
    ///
    /// [`ApproverError::IncorrectCode`] lets the user enter the code again, up to three attempts
    /// in total. Every other error ends the session.
    pub async fn authenticate(
        &mut self,
        code: &PairingCode,
    ) -> Result<IncomingRegistration, ApproverError> {
        if self.attempts_remaining == 0 || Instant::now() >= self.expires_at {
            return Err(ApproverError::Expired);
        }
        self.attempts_remaining -= 1;
        let transport_key = self.uri.secret.transport_key(code)?;
        let plaintext = match transport_key.decrypt_request(&self.encrypted) {
            Ok(plaintext) => plaintext,
            Err(TransportError::Decrypt) => {
                return Err(ApproverError::IncorrectCode {
                    attempts_remaining: self.attempts_remaining,
                })
            }
            Err(error) => {
                self.attempts_remaining = 0;
                return Err(error.into());
            }
        };
        self.attempts_remaining = 0;
        let request_id = self.uri.secret.request_id();
        match parse_request(&plaintext, &request_id, &self.uri.digest) {
            Ok(request) => Ok(IncomingRegistration {
                channel: self.channel(transport_key, request.response_pubkey.clone()),
                respond_by: self
                    .expires_at
                    .checked_sub(RESPONSE_MARGIN)
                    .unwrap_or(self.expires_at),
                request,
            }),
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

impl IncomingRegistration {
    /// Returns the request. Its `name` is untrusted and must be displayed as such.
    #[must_use]
    pub const fn request(&self) -> &RegistrationRequest {
        &self.request
    }

    /// Reads the account state of `approver` and plans the registration (WIP-109 §3.7.2).
    ///
    /// # Errors
    ///
    /// Returns [`ApproverError::Refused`] after answering with the reason if `approver` is not an
    /// Admin Authenticator of its account (`not_authorized`), the key or address is registered
    /// differently (`authenticator_conflict`), there is no free slot
    /// (`max_authenticators_reached`), or the account state cannot be read in time
    /// (`internal_error`).
    pub async fn check(
        self,
        approver: &Authenticator,
    ) -> Result<CheckedRegistration, ApproverError> {
        match self.plan(approver).await {
            Ok((authenticators, plan)) => Ok(CheckedRegistration {
                incoming: self,
                authenticators,
                plan,
            }),
            Err(refusal) => {
                tracing::warn!(
                    request = %log_tag(&self.channel.request_id),
                    reason = ?refusal.reason,
                    error = refusal.cause.as_ref().map(tracing::field::display),
                    "refusing authenticator registration"
                );
                let delivered = self.channel.answer(Err(refusal.to_error())).await;
                Err(ApproverError::Refused {
                    reason: refusal.reason,
                    cause: refusal.cause,
                    delivered,
                })
            }
        }
    }

    /// Refuses a request whose `name` the host does not accept, with `invalid_name`. Returns
    /// whether the answer was delivered.
    #[must_use = "the host must tell the user if the answer was not delivered"]
    pub async fn reject_name(self) -> bool {
        self.channel
            .answer(Err(RegistrationErrorReason::InvalidName.into_error(None)))
            .await
    }

    async fn plan(
        &self,
        approver: &Authenticator,
    ) -> Result<(AccountAuthenticators, RegistrationPlan), Refusal> {
        let core = &approver.inner;
        // Step 1: the registry, not the indexer, decides whether the approver is still an Admin
        // Authenticator of its account.
        match self
            .before_deadline(core.fetch_leaf_index_of(core.onchain_address()))
            .await?
        {
            Ok(leaf_index) if leaf_index == core.leaf_index() => {}
            Ok(_) | Err(AuthenticatorError::AccountDoesNotExist) => {
                return Err(RegistrationErrorReason::NotAuthorized.into());
            }
            Err(error) => return Err(Refusal::internal_error(error)),
        }
        let authenticators = self
            .before_deadline(core.fetch_authenticators())
            .await?
            .map_err(Refusal::internal_error)?;
        let plan = plan_registration(
            &authenticators,
            &core.offchain_pubkey(),
            core.onchain_address(),
            &self.request,
        )?;
        // Step 4: a new management key must not be registered to any account yet.
        if let (RegistrationPlan::Insert { .. }, Some(address)) =
            (plan, self.request.new_authenticator_address)
        {
            match self
                .before_deadline(core.fetch_leaf_index_of(address))
                .await?
            {
                Err(AuthenticatorError::AccountDoesNotExist) => {}
                Ok(_) => {
                    return Err(RegistrationErrorReason::AuthenticatorConflict.into())
                }
                Err(error) => return Err(Refusal::internal_error(error)),
            }
        }
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

impl CheckedRegistration {
    /// Returns the request.
    #[must_use]
    pub const fn request(&self) -> &RegistrationRequest {
        &self.incoming.request
    }

    /// Returns how the registration will be carried out.
    #[must_use]
    pub const fn plan(&self) -> RegistrationPlan {
        self.plan
    }

    /// Returns when the response is due, e.g. to show how long the user has to decide.
    #[must_use]
    pub const fn respond_by(&self) -> Instant {
        self.incoming.respond_by
    }

    /// Declines with `user_rejected`, because the user rejected the request or cancelled the
    /// platform's user verification (WIP-109 §3.7.3). Returns whether the answer was delivered.
    #[must_use = "the host must tell the user if the answer was not delivered"]
    pub async fn reject(self) -> bool {
        self.decline(RegistrationErrorReason::UserRejected).await
    }

    /// Ends the registration with `internal_error`, e.g. because the platform's user
    /// verification failed or is unavailable (WIP-109 §3.7.3). Returns whether the answer was
    /// delivered.
    #[must_use = "the host must tell the user if the answer was not delivered"]
    pub async fn abort(self) -> bool {
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
    pub async fn approve(
        self,
        approver: &Authenticator,
        vault: Option<Zeroizing<Vec<u8>>>,
        authenticators: Vec<KnownAuthenticator>,
    ) -> ApprovalOutcome {
        let vault_omitted = vault
            .as_ref()
            .is_some_and(|data| data.len() > MAX_VAULT_SIZE);
        let mut result = RegistrationResult {
            leaf_index: approver.inner.leaf_index(),
            // Every valid slot encodes to the same single CBOR byte, so checking the size with
            // this placeholder holds for the slot that registration assigns.
            pubkey_id: 0,
            authenticators,
            vault: vault.filter(|_| !vault_omitted).map(|data| Vault {
                format: PLAINTEXT_VAULT_FORMAT.to_string(),
                data,
            }),
        };
        let registered = self.register(approver, &result).await;
        let delivered = match &registered {
            Ok(pubkey_id) => {
                result.pubkey_id = *pubkey_id;
                self.incoming.channel.answer(Ok(&result)).await
            }
            Err(refusal) => {
                tracing::warn!(
                    request = %log_tag(&self.incoming.channel.request_id),
                    reason = ?refusal.reason,
                    detail = refusal.detail,
                    error = refusal.cause.as_ref().map(tracing::field::display),
                    "authenticator registration did not succeed"
                );
                self.incoming.channel.answer(Err(refusal.to_error())).await
            }
        };
        ApprovalOutcome {
            result: registered.map(|_| result).map_err(|refusal| refusal.reason),
            vault_omitted,
            delivered,
        }
    }

    async fn decline(self, reason: RegistrationErrorReason) -> bool {
        self.incoming
            .channel
            .answer(Err(reason.into_error(None)))
            .await
    }

    /// Registers the authenticator as planned and returns its slot.
    async fn register(
        &self,
        approver: &Authenticator,
        result: &RegistrationResult,
    ) -> Result<u32, Refusal> {
        // Checked before submitting, so that an oversized response cannot leave a registered
        // authenticator that never learns its result.
        let response: Response<_, RegistrationErrorData> =
            Response::success(self.incoming.channel.request_id.message_id(), result);
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
                if self.respond_by().saturating_duration_since(Instant::now())
                    < MIN_TRACKING_TIME =>
            {
                Err(Refusal::from(RegistrationErrorReason::InternalError)
                    .with_detail("approved too close to the session expiry"))
            }
            RegistrationPlan::Insert { pubkey_id } => {
                self.insert(approver, pubkey_id).await
            }
        }
    }

    /// Submits `InsertAuthenticator` and tracks it until it is final, definitively failed, or
    /// the response is due (WIP-109 §3.7.4).
    async fn insert(
        &self,
        approver: &Authenticator,
        pubkey_id: u32,
    ) -> Result<u32, Refusal> {
        let core = &approver.inner;
        let respond_by = self.respond_by();
        let request = &self.incoming.request;
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
                    return self.confirm_registration(approver).await;
                }
                Ok(GatewayRequestState::Failed { error_code, .. }) => {
                    return Err(classify_failure(error_code.as_ref(), submitted));
                }
                Ok(GatewayRequestState::Submitted { .. }) => submitted = true,
                Ok(GatewayRequestState::Queued | GatewayRequestState::Batching) => {}
                Err(error) => tracing::warn!(
                    request = %log_tag(&self.incoming.channel.request_id),
                    %error,
                    "failed to poll the gateway request"
                ),
            }
            if before(respond_by, sleep(delay)).await.is_none() {
                break;
            }
        }
        tracing::warn!(
            request = %log_tag(&self.incoming.channel.request_id),
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
    ) -> Result<u32, Refusal> {
        let request = &self.incoming.request;
        for delay in polling_backoff().build() {
            let Some(authenticators) =
                before(self.respond_by(), approver.inner.fetch_authenticators()).await
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
                    request = %log_tag(&self.incoming.channel.request_id),
                    %error,
                    "failed to refresh the account state after the insertion"
                ),
            }
            if before(self.respond_by(), sleep(delay)).await.is_none() {
                break;
            }
        }
        tracing::warn!(
            request = %log_tag(&self.incoming.channel.request_id),
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

    fn with_detail(self, detail: impl Into<String>) -> Self {
        Self {
            detail: Some(detail.into()),
            ..self
        }
    }

    fn to_error(&self) -> ErrorObject<RegistrationErrorData> {
        self.reason.into_error(self.detail.clone())
    }
}

impl From<RegistrationErrorReason> for Refusal {
    fn from(reason: RegistrationErrorReason) -> Self {
        Self {
            reason,
            detail: None,
            cause: None,
        }
    }
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
/// `approver_pubkey` and management key `approver_address` (WIP-109 §3.7.2 steps 1, 3 and 5).
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
    use test_case::test_case;

    use super::*;

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
}
