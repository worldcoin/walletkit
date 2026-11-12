//! Error types for the WIP-109 authenticator registration flows.

use reqwest::StatusCode;
use world_id_core::{
    primitives::authenticator_message::ErrorObject,
    registration::{RegistrationErrorData, RegistrationErrorReason, TransportError},
    AuthenticatorError,
};

use crate::error::WalletKitError;

/// Errors from talking to the message-bridge.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error, uniffi::Error)]
pub enum BridgeError {
    /// The bridge domain is not a valid DNS name with a named top-level label.
    #[error("invalid bridge domain: {0}")]
    InvalidDomain(String),
    /// The bridge URL cannot be built.
    #[error("invalid bridge URL: {0}")]
    InvalidUrl(String),
    /// The request failed in transit. The error carries no URL: the bridge routes contain the
    /// request id, which is the only key to the session.
    #[error("bridge request failed: {0}")]
    Transport(String),
    /// The bridge answered with a status the operation does not expect.
    #[error("bridge returned unexpected status {status}")]
    UnexpectedStatus {
        /// The HTTP status code.
        status: u16,
    },
    /// The bridge returned malformed JSON.
    #[error("invalid bridge response: {0}")]
    Json(String),
    /// The bridge response exceeded the bridge's body limit.
    #[error("bridge response exceeds the 5 MiB body limit")]
    TooLarge,
    /// The operation exhausted its time budget.
    #[error("bridge operation timed out")]
    Timeout,
}

impl From<StatusCode> for BridgeError {
    /// Converts an unexpected HTTP status code into [`BridgeError::UnexpectedStatus`].
    fn from(status: StatusCode) -> Self {
        Self::UnexpectedStatus {
            status: status.as_u16(),
        }
    }
}

impl From<reqwest::Error> for BridgeError {
    /// Converts a reqwest transport error into [`BridgeError::Transport`] with the URL stripped.
    fn from(error: reqwest::Error) -> Self {
        Self::Transport(error.without_url().to_string())
    }
}

impl From<serde_json::Error> for BridgeError {
    /// Converts a JSON deserialization error into [`BridgeError::Json`].
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error.to_string())
    }
}

/// Errors on the Requesting Authenticator's side of a registration.
///
/// Decrypt and malformed-response errors in
/// [`RegistrationRequester::poll`](super::RegistrationRequester::poll) end the session; bridge
/// errors leave the session open until it expires so the caller can poll again.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum RequesterError {
    /// The requested authenticator name exceeds [`MAX_NAME_LEN`](super::MAX_NAME_LEN).
    #[error("authenticator name must be at most {} bytes", super::MAX_NAME_LEN)]
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
    /// The seed passed to [`RegistrationRequester::verify`](super::RegistrationRequester::verify)
    /// is not the one this session asked to register.
    #[error("the seed does not belong to this registration session")]
    SeedMismatch,
    /// The registry does not show the authenticator where and how the result says it is.
    #[error("the registration result does not match the registry")]
    RegistrationMismatch,
    /// The registration could not be verified before the deadline.
    #[error("registration verification timed out")]
    VerificationTimeout,
}

impl From<AuthenticatorError> for RequesterError {
    /// Converts an [`AuthenticatorError`] into [`RequesterError::Authenticator`].
    fn from(error: AuthenticatorError) -> Self {
        Self::Authenticator(error.into())
    }
}

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
    /// The authenticator passed to
    /// [`CheckedRegistration::approve`](super::CheckedRegistration::approve) is not the one that
    /// [`IncomingRegistration::check`](super::IncomingRegistration::check) checked.
    #[error("the approver does not match the checked account")]
    ApproverMismatch,
    /// This step was already taken, so the registration has moved on or ended.
    #[error("this registration step was already taken")]
    AlreadyHandled,
}
