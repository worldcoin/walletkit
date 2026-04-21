//! Shared credential types, JSON helpers, and the `IssuerDriver` interface
//! for the host-mediated Issuers SDK experiment.
//!
//! This crate is intentionally **domain-agnostic**: it knows nothing about
//! Orb hardware, NFC documents, or any specific issuance pathway.  All
//! domain-specific logic lives exclusively in `orb-kit` and `nfc-kit`.
//!
//! Compiled as a source dependency (rlib) — not a cross-binary ABI.

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use thiserror::Error;

/// Result type used across the shared SDK crate.
pub type SdkResult<T> = Result<T, SdkError>;

// ──────────────────────────────────────────────────────────────────────────────
// Domain types
// ──────────────────────────────────────────────────────────────────────────────

/// Request sent from the host to a credential issuer.
///
/// Kept intentionally minimal so `issuer-sdk` and `issuer-host` remain
/// fully generic.  Issuer implementations may encode additional context
/// (e.g. issuance pathway, document type) inside their own request
/// structures that they serialize into/out of the `user_id` string, or
/// they may extend the JSON payload at their own layer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialRequest {
    /// Opaque identifier for the credential subject.
    ///
    /// In production this would be a nullifier hash or World ID commitment.
    pub user_id: String,
}

/// Credential returned by an issuer.
///
/// In production this would carry a signed SD-JWT or similar structure
/// (see `IdentityCredential` in oxide). Kept simple for the demo.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Credential {
    /// Opaque credential identifier (e.g. UUID).
    pub id: String,
    /// Name of the issuer that produced this credential.
    pub issuer: String,
    /// Encoded credential payload (SD-JWT stub in this demo).
    pub data: String,
}

// ──────────────────────────────────────────────────────────────────────────────
// Error type
// ──────────────────────────────────────────────────────────────────────────────

/// Shared errors for validation, serialization, and issuance failures.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SdkError {
    /// JSON could not be parsed or serialized.
    #[error("invalid json: {0}")]
    InvalidJson(String),
    /// The `user_id` field was blank after trimming whitespace.
    #[error("user_id must not be empty")]
    EmptyUserId,
    /// An issuer implementation reported a failure.
    #[error("issuance failed: {0}")]
    IssuanceFailed(String),
}

// ──────────────────────────────────────────────────────────────────────────────
// IssuerDriver — the core cross-binary interface
// ──────────────────────────────────────────────────────────────────────────────

/// Synchronous driver interface implemented by each credential issuer.
///
/// This is the Rust-level contract the host uses to dispatch credential
/// requests to whichever implementation (Orb, NFC, …) has been registered.
/// The host calls this synchronously via `tokio::task::spawn_blocking`;
/// implementors may internally block on async work.
///
/// Defined here so that `orb-kit` and `nfc-kit` can implement it directly at
/// the Rust level without depending on `issuer-host`.
///
/// The `#[uniffi::export(with_foreign)]` annotation that makes this trait
/// available as a UniFFI callback interface lives in `issuer-host`, which owns
/// the FFI scaffolding namespace.  `issuer-host` re-exports this trait and
/// declares a blanket-compatible UniFFI wrapper there.
pub trait IssuerDriver: Send + Sync {
    /// Accept a JSON-serialized [`CredentialRequest`] and return a
    /// JSON-serialized [`Credential`], or a [`SdkError`] on failure.
    fn fetch_credential(&self, request_json: String) -> Result<String, SdkError>;
}

// ──────────────────────────────────────────────────────────────────────────────
// JSON helpers
// ──────────────────────────────────────────────────────────────────────────────

/// Serializes any serde-compatible value into JSON.
pub fn to_json<T>(value: &T) -> SdkResult<String>
where
    T: Serialize,
{
    serde_json::to_string(value).map_err(|e| SdkError::InvalidJson(e.to_string()))
}

/// Parses any serde-compatible value from JSON.
pub fn from_json<T>(json: &str) -> SdkResult<T>
where
    T: DeserializeOwned,
{
    serde_json::from_str(json).map_err(|e| SdkError::InvalidJson(e.to_string()))
}

// ──────────────────────────────────────────────────────────────────────────────
// Request helpers
// ──────────────────────────────────────────────────────────────────────────────

/// Validates a credential request.
pub fn validate_request(request: &CredentialRequest) -> SdkResult<()> {
    if request.user_id.trim().is_empty() {
        return Err(SdkError::EmptyUserId);
    }
    Ok(())
}

/// Parses and validates a [`CredentialRequest`] from JSON.
pub fn parse_request_json(json: &str) -> SdkResult<CredentialRequest> {
    let request: CredentialRequest = from_json(json)?;
    validate_request(&request)?;
    Ok(request)
}

/// Builds a [`Credential`] and serializes it to JSON.
pub fn build_credential_json(id: &str, issuer: &str, data: String) -> SdkResult<String> {
    to_json(&Credential {
        id: id.to_string(),
        issuer: issuer.to_string(),
        data,
    })
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_request() {
        let req = parse_request_json(r#"{"user_id":"user-abc"}"#).expect("request should parse");
        assert_eq!(req.user_id, "user-abc");
    }

    #[test]
    fn rejects_blank_user_id() {
        let error =
            parse_request_json(r#"{"user_id":"   "}"#).expect_err("blank user_id should fail");
        assert_eq!(error, SdkError::EmptyUserId);
    }

    #[test]
    fn rejects_empty_user_id() {
        let error =
            parse_request_json(r#"{"user_id":""}"#).expect_err("empty user_id should fail");
        assert_eq!(error, SdkError::EmptyUserId);
    }

    #[test]
    fn builds_credential_json() {
        let json = build_credential_json("cred-1", "orb-kit", "stub-data".to_string())
            .expect("credential should serialize");
        let cred: Credential = serde_json::from_str(&json).expect("json should parse");
        assert_eq!(cred.issuer, "orb-kit");
        assert_eq!(cred.data, "stub-data");
    }
}
