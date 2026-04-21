//! Shared credential types, JSON helpers, and the async `IssuerDriver` UniFFI
//! callback interface for the host-mediated Issuers SDK experiment.
//!
//! Two traits serve different audiences:
//!
//! * **[`IssuerDriver`]** — async UniFFI callback interface implemented by
//!   foreign-language hosts (Python, Swift, Kotlin).  All routing happens here
//!   in Rust via the blanket impl below.
//! * **[`Issuer`]** — ergonomic Rust trait implemented by `orb-kit`,
//!   `nfc-kit`, etc.  The blanket `impl<T: Issuer> IssuerDriver for T`
//!   dispatches incoming [`IssuerMsg`]s automatically.

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ── Domain types ──────────────────────────────────────────────────────────────

/// Request sent from the host to a credential issuer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialRequest {
    /// Opaque identifier for the credential subject (nullifier hash stub).
    pub user_id: String,
}

/// Credential returned by an issuer (SD-JWT stub for the demo).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Credential {
    pub id: String,
    pub issuer: String,
    pub data: String,
}

// ── Error type ────────────────────────────────────────────────────────────────

/// Errors surfaced through the `IssuerDriver` FFI boundary.
#[derive(Debug, Clone, PartialEq, Eq, Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum SdkError {
    #[error("invalid json: {0}")]
    InvalidJson(String),
    #[error("user_id must not be empty")]
    EmptyUserId,
    #[error("issuance failed: {0}")]
    IssuanceFailed(String),
    /// Included for forward-compatibility as the message enum grows.
    #[error("unsupported message: {0}")]
    UnsupportedMessage(String),
}

// ── Message protocol ──────────────────────────────────────────────────────────

/// All issuer operations encoded as enum variants.
///
/// New operations only require new variants here and in [`IssuerValue`];
/// the FFI surface stays stable.
#[derive(Debug, Clone, uniffi::Enum)]
pub enum IssuerMsg {
    /// Fetch a credential for the JSON-serialised [`CredentialRequest`].
    FetchCredential { request_json: String },
}

/// All issuer return values encoded as enum variants.
#[derive(Debug, Clone, uniffi::Enum)]
pub enum IssuerValue {
    /// A successfully issued credential, JSON-serialised.
    Credential { json: String },
}

// ── IssuerDriver — async UniFFI callback interface ────────────────────────────

/// Async single-method UniFFI callback interface for foreign-language hosts.
///
/// Order matters: `#[uniffi::export(with_foreign)]` must come before
/// `#[async_trait::async_trait]` so UniFFI sees the native `async fn` first.
#[uniffi::export(with_foreign)]
#[async_trait::async_trait]
pub trait IssuerDriver: Send + Sync {
    async fn handle_message(&self, msg: IssuerMsg) -> Result<IssuerValue, SdkError>;
}

// ── Issuer — ergonomic Rust trait ─────────────────────────────────────────────

/// Ergonomic Rust trait for issuer implementations.
///
/// The blanket impl below automatically satisfies [`IssuerDriver`], so
/// implementors never write message-dispatch code.
#[async_trait::async_trait]
pub trait Issuer: Send + Sync {
    async fn fetch_credential(&self, request_json: String) -> Result<String, SdkError>;
}

// ── Blanket impl: Issuer → IssuerDriver ───────────────────────────────────────

#[async_trait::async_trait]
impl<T: Issuer + Send + Sync> IssuerDriver for T {
    async fn handle_message(&self, msg: IssuerMsg) -> Result<IssuerValue, SdkError> {
        match msg {
            IssuerMsg::FetchCredential { request_json } => self
                .fetch_credential(request_json)
                .await
                .map(|json| IssuerValue::Credential { json }),
        }
    }
}

// ── JSON helpers ──────────────────────────────────────────────────────────────

pub fn to_json<T: Serialize>(value: &T) -> Result<String, SdkError> {
    serde_json::to_string(value).map_err(|e| SdkError::InvalidJson(e.to_string()))
}

pub fn validate_request(request: &CredentialRequest) -> Result<(), SdkError> {
    if request.user_id.trim().is_empty() {
        return Err(SdkError::EmptyUserId);
    }
    Ok(())
}

pub fn parse_request_json(json: &str) -> Result<CredentialRequest, SdkError> {
    let request: CredentialRequest =
        serde_json::from_str(json).map_err(|e| SdkError::InvalidJson(e.to_string()))?;
    validate_request(&request)?;
    Ok(request)
}

pub fn build_credential_json(id: &str, issuer: &str, data: String) -> Result<String, SdkError> {
    to_json(&Credential {
        id: id.to_string(),
        issuer: issuer.to_string(),
        data,
    })
}

// ── UniFFI scaffolding ────────────────────────────────────────────────────────

// Also generates `uniffi_reexport_scaffolding!()` for dependent cdylibs.
uniffi::setup_scaffolding!("issuer_sdk");

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    struct EchoIssuer;

    #[async_trait::async_trait]
    impl Issuer for EchoIssuer {
        async fn fetch_credential(&self, request_json: String) -> Result<String, SdkError> {
            let req = parse_request_json(&request_json)?;
            build_credential_json("test-id", "echo", req.user_id)
        }
    }

    #[test]
    fn parses_valid_request() {
        let req = parse_request_json(r#"{"user_id":"user-abc"}"#).unwrap();
        assert_eq!(req.user_id, "user-abc");
    }

    #[test]
    fn rejects_blank_user_id() {
        assert_eq!(
            parse_request_json(r#"{"user_id":"   "}"#).unwrap_err(),
            SdkError::EmptyUserId
        );
    }

    #[test]
    fn rejects_empty_user_id() {
        assert_eq!(
            parse_request_json(r#"{"user_id":""}"#).unwrap_err(),
            SdkError::EmptyUserId
        );
    }

    #[test]
    fn builds_credential_json() {
        let json = build_credential_json("cred-1", "orb-kit", "stub".to_string()).unwrap();
        let cred: Credential = serde_json::from_str(&json).unwrap();
        assert_eq!(cred.issuer, "orb-kit");
    }

    #[tokio::test]
    async fn issuer_fetch_credential_works() {
        let json = EchoIssuer
            .fetch_credential(r#"{"user_id":"user-abc"}"#.to_string())
            .await
            .unwrap();
        let cred: Credential = serde_json::from_str(&json).unwrap();
        assert_eq!(cred.issuer, "echo");
        assert_eq!(cred.data, "user-abc");
    }

    #[tokio::test]
    async fn blanket_dispatches_fetch_credential() {
        let driver: &dyn IssuerDriver = &EchoIssuer;
        let result = driver
            .handle_message(IssuerMsg::FetchCredential {
                request_json: r#"{"user_id":"blanket-user"}"#.to_string(),
            })
            .await
            .unwrap();
        let IssuerValue::Credential { json } = result;
        let cred: Credential = serde_json::from_str(&json).unwrap();
        assert_eq!(cred.data, "blanket-user");
    }

    #[tokio::test]
    async fn blanket_propagates_sdk_error() {
        let driver: &dyn IssuerDriver = &EchoIssuer;
        let err = driver
            .handle_message(IssuerMsg::FetchCredential {
                request_json: r#"{"user_id":""}"#.to_string(),
            })
            .await
            .unwrap_err();
        assert_eq!(err, SdkError::EmptyUserId);
    }

    #[test]
    fn unsupported_message_error_formats() {
        let err = SdkError::UnsupportedMessage("WeirdOp".to_string());
        assert!(err.to_string().contains("WeirdOp"));
    }
}
