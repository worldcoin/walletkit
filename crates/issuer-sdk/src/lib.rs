//! Shared credential types, JSON helpers, and the message-based `IssuerDriver`
//! UniFFI callback interface for the host-mediated Issuers SDK experiment.
//!
//! ## Design
//!
//! Two traits serve different audiences:
//!
//! * **[`IssuerDriver`]** — the *UniFFI* callback interface.  Foreign-language
//!   hosts (Python, Swift, Kotlin) implement exactly one method:
//!   `handle_message(msg: IssuerMsg) -> Result<IssuerValue, SdkError>`.
//!   All operations are encoded as variants of [`IssuerMsg`]; results come back
//!   as variants of [`IssuerValue`].  Adding a new operation only requires a
//!   new variant in each enum — the FFI surface stays stable.
//!
//! * **[`Issuer`]** — the ergonomic *Rust* trait.  Rust crates (`orb-kit`,
//!   `nfc-kit`) implement typed methods like `fetch_credential`.  A blanket
//!   `impl<T: Issuer> IssuerDriver for T` dispatches incoming [`IssuerMsg`]s
//!   to the appropriate method automatically, so Rust implementors never
//!   touch the message enum.
//!
//! ## UniFFI scaffolding
//!
//! `issuer-sdk` owns `uniffi::setup_scaffolding!("issuer_sdk")` and is compiled
//! as `cdylib + rlib`.  Dependent cdylibs (`issuer-host`) call
//! `issuer_sdk::uniffi_reexport_scaffolding!()` to force the linker to include
//! these symbols — the same pattern as `walletkit-core` / `walletkit` in main.

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ──────────────────────────────────────────────────────────────────────────────
// Domain types
// ──────────────────────────────────────────────────────────────────────────────

/// Request sent from the host to a credential issuer.
///
/// Kept minimal — `issuer-sdk` and `issuer-host` remain fully domain-agnostic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialRequest {
    /// Opaque identifier for the credential subject.
    ///
    /// In production this would be a nullifier hash or World ID commitment.
    pub user_id: String,
}

/// Credential returned by an issuer.
///
/// In production this carries a signed SD-JWT (see `IdentityCredential` in
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
/// `IssuerDriver::handle_message` without needing a per-variant FFI layout.
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
    /// A handler received a message variant it does not recognise.
    ///
    /// Included for forward-compatibility: when new [`IssuerMsg`] variants are
    /// added, old implementations can return this error rather than panicking.
    #[error("unsupported message: {0}")]
    UnsupportedMessage(String),
}

// ──────────────────────────────────────────────────────────────────────────────
// Message protocol
// ──────────────────────────────────────────────────────────────────────────────

/// All issuer operations encoded as an enum.
///
/// The host constructs one of these variants and passes it to
/// [`IssuerDriver::handle_message`].  Adding a new operation only requires a
/// new variant here and a corresponding one in [`IssuerValue`]; the FFI
/// surface (`handle_message`) stays unchanged.
#[derive(Debug, Clone, uniffi::Enum)]
pub enum IssuerMsg {
    /// Request to fetch a credential for the given JSON-serialised
    /// [`CredentialRequest`].
    FetchCredential { request_json: String },
}

/// All issuer return values encoded as an enum.
///
/// Returned by [`IssuerDriver::handle_message`].  The caller matches on the
/// variant to extract the typed result.
#[derive(Debug, Clone, uniffi::Enum)]
pub enum IssuerValue {
    /// A successfully issued credential, JSON-serialised.
    Credential { json: String },
}

// ──────────────────────────────────────────────────────────────────────────────
// IssuerDriver — UniFFI callback interface (foreign-language path)
// ──────────────────────────────────────────────────────────────────────────────

/// Single-method UniFFI callback interface.
///
/// Foreign-language implementations (Python adapters, Swift, Kotlin) only need
/// to handle one method.  The message enum carries all the information needed
/// to dispatch to the right operation.
///
/// Rust implementors should prefer implementing [`Issuer`] instead; the blanket
/// `impl<T: Issuer> IssuerDriver for T` takes care of the dispatch.
#[uniffi::export(with_foreign)]
pub trait IssuerDriver: Send + Sync {
    /// Dispatch an [`IssuerMsg`] and return the matching [`IssuerValue`], or a
    /// [`SdkError`] on failure.
    fn handle_message(&self, msg: IssuerMsg) -> Result<IssuerValue, SdkError>;
}

// ──────────────────────────────────────────────────────────────────────────────
// Issuer — ergonomic Rust trait (native path)
// ──────────────────────────────────────────────────────────────────────────────

/// Ergonomic Rust trait for issuer implementations.
///
/// Rust crates (`orb-kit`, `nfc-kit`) implement the typed methods here.
/// The blanket impl below automatically satisfies [`IssuerDriver`] for any
/// `T: Issuer`, so implementors never need to touch the message enum.
pub trait Issuer: Send + Sync {
    /// Fetch a credential for the given JSON-serialised [`CredentialRequest`].
    fn fetch_credential(&self, request_json: String) -> Result<String, SdkError>;
}

// ──────────────────────────────────────────────────────────────────────────────
// Blanket impl: Issuer → IssuerDriver
// ──────────────────────────────────────────────────────────────────────────────

/// Any type that implements [`Issuer`] automatically satisfies [`IssuerDriver`].
///
/// The blanket impl is defined here (same crate as both traits), so the orphan
/// rule is satisfied.  Incoming [`IssuerMsg`] variants are matched and
/// dispatched to the appropriate [`Issuer`] method.
impl<T: Issuer + Send + Sync> IssuerDriver for T {
    fn handle_message(&self, msg: IssuerMsg) -> Result<IssuerValue, SdkError> {
        match msg {
            IssuerMsg::FetchCredential { request_json } => self
                .fetch_credential(request_json)
                .map(|json| IssuerValue::Credential { json }),
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// JSON helpers
// ──────────────────────────────────────────────────────────────────────────────

/// Serializes any serde-compatible value into JSON.
pub fn to_json<T: Serialize>(value: &T) -> Result<String, SdkError> {
    serde_json::to_string(value).map_err(|e| SdkError::InvalidJson(e.to_string()))
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

// Also generates `uniffi_reexport_scaffolding!()` for dependent cdylibs.
uniffi::setup_scaffolding!("issuer_sdk");

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── helper: a minimal in-process Issuer impl ──────────────────────────────

    struct EchoIssuer;

    impl Issuer for EchoIssuer {
        fn fetch_credential(&self, request_json: String) -> Result<String, SdkError> {
            // validate the request, then echo it back as the credential data
            let req = parse_request_json(&request_json)?;
            build_credential_json("test-id", "echo", req.user_id)
        }
    }

    // ── CredentialRequest / JSON helpers ─────────────────────────────────────

    #[test]
    fn parses_valid_request() {
        let req = parse_request_json(r#"{"user_id":"user-abc"}"#).expect("should parse");
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
        let json = build_credential_json("cred-1", "orb-kit", "stub".to_string())
            .expect("should serialize");
        let cred: Credential = serde_json::from_str(&json).expect("should parse");
        assert_eq!(cred.issuer, "orb-kit");
        assert_eq!(cred.data, "stub");
    }

    // ── Issuer trait ──────────────────────────────────────────────────────────

    #[test]
    fn issuer_fetch_credential_works() {
        let issuer = EchoIssuer;
        let json = issuer
            .fetch_credential(r#"{"user_id":"user-abc"}"#.to_string())
            .expect("should succeed");
        let cred: Credential = serde_json::from_str(&json).unwrap();
        assert_eq!(cred.issuer, "echo");
        assert_eq!(cred.data, "user-abc");
    }

    // ── Blanket impl: Issuer → IssuerDriver ───────────────────────────────────

    #[test]
    fn blanket_impl_dispatches_fetch_credential() {
        // EchoIssuer implements Issuer; the blanket gives it IssuerDriver for free.
        let driver: &dyn IssuerDriver = &EchoIssuer;
        let result = driver
            .handle_message(IssuerMsg::FetchCredential {
                request_json: r#"{"user_id":"blanket-user"}"#.to_string(),
            })
            .expect("blanket dispatch should succeed");

        let IssuerValue::Credential { json } = result;
        let cred: Credential = serde_json::from_str(&json).unwrap();
        assert_eq!(cred.issuer, "echo");
        assert_eq!(cred.data, "blanket-user");
    }

    #[test]
    fn blanket_impl_propagates_sdk_error() {
        let driver: &dyn IssuerDriver = &EchoIssuer;
        let err = driver
            .handle_message(IssuerMsg::FetchCredential {
                request_json: r#"{"user_id":""}"#.to_string(),
            })
            .expect_err("empty user_id should fail");
        assert_eq!(err, SdkError::EmptyUserId);
    }

    // ── SdkError variants ─────────────────────────────────────────────────────

    #[test]
    fn unsupported_message_error_formats() {
        let err = SdkError::UnsupportedMessage("WeirdOp".to_string());
        assert!(err.to_string().contains("WeirdOp"));
    }
}
