//! Shared credential types, JSON helpers, and the `IssuerDriver` UniFFI
//! callback interface for the host-mediated Issuers SDK experiment.
//!
//! This crate is intentionally **domain-agnostic**: it knows nothing about
//! Orb hardware, NFC documents, or any specific issuance pathway.  All
//! domain-specific logic lives exclusively in `orb-kit` and `nfc-kit`.
//!
//! ## UniFFI scaffolding
//!
//! `issuer-sdk` owns `uniffi::setup_scaffolding!("issuer_sdk")` and is compiled
//! as a `cdylib` + `rlib`.  Crates that embed the SDK's exported symbols (such
//! as `issuer-host`) call `issuer_sdk::uniffi_reexport_scaffolding!()` so the
//! linker includes those symbols in their own binary — exactly the same pattern
//! used between `walletkit-core` and `walletkit` in the main branch.

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use thiserror::Error;

// ──────────────────────────────────────────────────────────────────────────────
// Domain types
// ──────────────────────────────────────────────────────────────────────────────

/// Request sent from the host to a credential issuer.
///
/// Kept intentionally minimal — `issuer-sdk` and `issuer-host` remain fully
/// generic.  Issuer implementations encode any pathway-specific context (Orb,
/// NFC, …) in their own serialization layer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialRequest {
    /// Opaque identifier for the credential subject.
    ///
    /// In production this would be a nullifier hash or World ID commitment.
    pub user_id: String,
}

/// Credential returned by an issuer.
///
/// In production this would carry a signed SD-JWT (see `IdentityCredential` in
/// oxide).  Kept simple for the demo.
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

/// Errors surfaced through the `IssuerDriver` FFI boundary.
///
/// Declared as a flat UniFFI error so it can be the error type of
/// `IssuerDriver::fetch_credential` without needing a per-variant FFI layout.
#[derive(Debug, Clone, PartialEq, Eq, Error, uniffi::Error)]
#[uniffi(flat_error)]
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
// IssuerDriver — the core UniFFI callback interface
// ──────────────────────────────────────────────────────────────────────────────

/// Synchronous driver interface implemented by each credential issuer.
///
/// Declared with `#[uniffi::export(with_foreign)]` so that foreign-language
/// hosts (Python, Swift, Kotlin) can implement it and pass it to
/// `IssuerHost::register_issuer` as a callback object.
///
/// `orb-kit` and `nfc-kit` also implement this trait directly at the Rust
/// level (blocking on their internal async work) so they can be used from
/// native Rust code that holds an `Arc<dyn IssuerDriver>`.
#[uniffi::export(with_foreign)]
pub trait IssuerDriver: Send + Sync {
    /// Accept a JSON-serialized [`CredentialRequest`] and return a
    /// JSON-serialized [`Credential`], or a [`SdkError`] on failure.
    fn fetch_credential(&self, request_json: String) -> Result<String, SdkError>;
}

// ──────────────────────────────────────────────────────────────────────────────
// JSON helpers
// ──────────────────────────────────────────────────────────────────────────────

/// Serializes any serde-compatible value into JSON.
pub fn to_json<T: Serialize>(value: &T) -> Result<String, SdkError> {
    serde_json::to_string(value).map_err(|e| SdkError::InvalidJson(e.to_string()))
}

/// Parses any serde-compatible value from JSON.
pub fn from_json<T: DeserializeOwned>(json: &str) -> Result<String, SdkError>
where
    T: Serialize,
{
    let value: T =
        serde_json::from_str(json).map_err(|e| SdkError::InvalidJson(e.to_string()))?;
    to_json(&value)
}

/// Validates a [`CredentialRequest`].
pub fn validate_request(request: &CredentialRequest) -> Result<(), SdkError> {
    if request.user_id.trim().is_empty() {
        return Err(SdkError::EmptyUserId);
    }
    Ok(())
}

/// Parses and validates a [`CredentialRequest`] from JSON.
pub fn parse_request_json(json: &str) -> Result<CredentialRequest, SdkError> {
    let request: CredentialRequest =
        serde_json::from_str(json).map_err(|e| SdkError::InvalidJson(e.to_string()))?;
    validate_request(&request)?;
    Ok(request)
}

/// Builds a [`Credential`] and serializes it to JSON.
pub fn build_credential_json(id: &str, issuer: &str, data: String) -> Result<String, SdkError> {
    to_json(&Credential {
        id: id.to_string(),
        issuer: issuer.to_string(),
        data,
    })
}

// ──────────────────────────────────────────────────────────────────────────────
// UniFFI scaffolding
// ──────────────────────────────────────────────────────────────────────────────

// This also generates the `uniffi_reexport_scaffolding!()` macro that
// dependent cdylibs (e.g. `issuer-host`) call to force the linker to include
// these symbols in their own binary.
uniffi::setup_scaffolding!("issuer_sdk");

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
