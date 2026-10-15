//! Registering a new authenticator through an existing Admin Authenticator, as defined in
//! [WIP-109](https://github.com/worldcoin/world-id-protocol/blob/main/docs/WIPs/wip-109.md).
//!
//! The **Requesting Authenticator** (the new device) starts a [`RegistrationRequester`], which
//! publishes an encrypted request on a message-bridge, then shows its [`PairingUri`] and, once
//! the request was taken, its [`PairingCode`].
//!
//! The **Approving Authenticator** (an existing Admin Authenticator) takes the request with
//! [`PendingRegistration::receive`] and decrypts it with the code the user enters. The host
//! checks the account with [`IncomingRegistration::check`], asks for consent, and either
//! [`CheckedRegistration::approve`]s, which inserts the authenticator on-chain, or declines.
//! Every outcome is answered to the Requesting Authenticator, which verifies a successful result
//! with [`RegistrationRequester::verify`].
//!
//! The wire format and cryptography come from [`world_id_core::registration`].
//!
//! # Blocking key derivation
//!
//! [`RegistrationRequester::start`] and [`PendingRegistration::authenticate`] derive the
//! transport key from the pairing code with Argon2id (64 MiB), synchronously. In a browser, call
//! them from a Web Worker rather than the main thread.

use std::{future::Future, time::Duration};

use backon::{ExponentialBuilder, Sleeper as _};
use futures_util::future::{select, Either};
use web_time::Instant;
use world_id_core::registration::RequestId;

mod approver;
mod bridge;
mod requester;

pub use approver::{
    ApprovalOutcome, ApproverError, CheckedRegistration, IncomingRegistration,
    PendingRegistration, RegistrationPlan,
};
pub use bridge::{BridgeClient, BridgeError};
pub use requester::{
    Registered, RegistrationRequester, RequestedClass, RequesterError, RequesterStatus,
};
pub use world_id_core::registration::{
    AuthenticatorName, BridgeDomain, KnownAuthenticator, PairingCode, PairingUri,
    RegistrationErrorData, RegistrationErrorReason, RegistrationRequest,
    RegistrationResult, MAX_VAULT_SIZE,
};

/// The format of the shared vault: a `CredentialStore::export_vault_for_backup` export.
const PLAINTEXT_VAULT_FORMAT: &str = "walletkit_plaintext_v1";

/// The message-bridge session lifetime, from which both sides estimate the session expiry
/// (WIP-109 §3.5).
const SESSION_TTL: Duration = Duration::from_mins(15);

/// Runs `future` until `deadline`, returning `None` if the deadline passes first. A future whose
/// deadline has passed is never polled.
async fn before<F: Future>(deadline: Instant, future: F) -> Option<F::Output> {
    let now = Instant::now();
    if now >= deadline {
        return None;
    }
    let timeout = sleep(deadline - now);
    match select(std::pin::pin!(future), std::pin::pin!(timeout)).await {
        Either::Left((output, _)) => Some(output),
        Either::Right(_) => None,
    }
}

/// Sleeps for `duration`, on native and browser targets alike.
async fn sleep(duration: Duration) {
    backon::DefaultSleeper::default().sleep(duration).await;
}

/// Delays between polls of an outcome that takes a while: from one second, doubling up to eight,
/// with jitter. Callers stop at their own deadline.
fn polling_backoff() -> ExponentialBuilder {
    ExponentialBuilder::default()
        .with_min_delay(Duration::from_secs(1))
        .with_max_delay(Duration::from_secs(8))
        .without_max_times()
        .with_jitter()
}

/// A short tag that correlates the log lines of one session. The request id itself is never
/// logged: it is the only key to the session's bridge routes.
fn log_tag(request_id: &RequestId) -> String {
    use sha2::Digest as _;
    hex::encode(&sha2::Sha256::digest(request_id.as_bytes())[..4])
}
