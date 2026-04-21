//! NfcKit — NFC identity-document credential issuer for the host-mediated Issuers SDK experiment.
//!
//! `NfcIssuer` simulates the NFC uniqueness-service issuance pathway (see
//! `NfcBackend` / `nfc_backend_api` in oxide).  In a real implementation it
//! would decrypt the Personal Custody Package (PCP), verify the NFC document
//! data, and return a signed SD-JWT credential.
//!
//! ## Trait layering
//!
//! * `NfcIssuer` implements [`issuer_sdk::Issuer`] — the ergonomic Rust trait.
//! * The blanket `impl<T: Issuer> IssuerDriver for T` in `issuer-sdk` then
//!   automatically satisfies [`issuer_sdk::IssuerDriver`], so `NfcIssuer` can
//!   be registered with an `IssuerHost` without any manual message dispatch.
//! * For foreign-language hosts (Python adapters), `fetch_credential_async` is
//!   exported via UniFFI and wrapped in an adapter that implements
//!   `IssuerDriver` on the foreign side.

use issuer_sdk::{build_credential_json, parse_request_json, Issuer, SdkError};
use thiserror::Error;

/// Errors returned by the NFC issuer's async pathway.
#[derive(Debug, Error, uniffi::Error)]
pub enum NfcKitError {
    /// Shared SDK error.
    #[error("issuer-sdk error: {0}")]
    Sdk(String),
}

impl From<SdkError> for NfcKitError {
    fn from(error: SdkError) -> Self {
        Self::Sdk(error.to_string())
    }
}

/// Issuer that mints credentials via an NFC identity document.
///
/// Corresponds to the `NfcBackend` in oxide which interacts with the NFC
/// uniqueness service to verify passport / identity-card data.
#[derive(uniffi::Object)]
pub struct NfcIssuer;

impl Default for NfcIssuer {
    fn default() -> Self {
        Self::new()
    }
}

// ── Rust-native path: impl Issuer (sync wrapper) ─────────────────────────────

/// Implement the ergonomic [`Issuer`] trait.
///
/// Blocks on the async pathway using the current Tokio runtime handle — safe
/// when called from `tokio::task::spawn_blocking` (how `IssuerHost` invokes
/// the driver) or from `tokio::task::block_in_place` in tests.
///
/// The blanket `impl<T: Issuer> IssuerDriver for T` in `issuer-sdk` then
/// provides `handle_message` for free.
impl Issuer for NfcIssuer {
    fn fetch_credential(&self, request_json: String) -> Result<String, SdkError> {
        tokio::runtime::Handle::current()
            .block_on(self.fetch_credential_async(request_json))
            .map_err(|e| SdkError::IssuanceFailed(e.to_string()))
    }
}

// ── Foreign-language path: async UniFFI export ────────────────────────────────

#[uniffi::export(async_runtime = "tokio")]
impl NfcIssuer {
    /// Creates a new `NfcIssuer`.
    #[uniffi::constructor]
    pub fn new() -> Self {
        Self
    }

    /// Fetches a credential using the NFC document issuance pathway (async).
    ///
    /// In production this would:
    /// 1. Load and decrypt the Personal Custody Package (PCP) from device storage.
    /// 2. Call `/v2/decrypt-pcp-keys` on the NFC uniqueness service.
    /// 3. Unseal the identity credential and decode the SD-JWT.
    ///
    /// # Errors
    ///
    /// Returns an error if the request JSON is invalid or issuance fails.
    pub async fn fetch_credential_async(
        &self,
        request_json: String,
    ) -> Result<String, NfcKitError> {
        // Simulate NFC document read + network round-trip latency.
        tokio::time::sleep(std::time::Duration::from_millis(1)).await;

        let request = parse_request_json(&request_json)?;

        let credential_id = uuid::Uuid::new_v4().to_string();
        let stub_data = format!(
            "eyJhbGciOiJFUzI1NiIsInR5cCI6IlNELUpXVCJ9.stub.nfc.{}",
            request.user_id
        );

        build_credential_json(&credential_id, "nfc-kit", stub_data).map_err(Into::into)
    }
}

uniffi::setup_scaffolding!("nfc_kit");

#[cfg(test)]
mod tests {
    use super::NfcIssuer;
    use issuer_sdk::{Credential, IssuerDriver, IssuerMsg, IssuerValue, Issuer};

    // ── async path ────────────────────────────────────────────────────────────

    #[tokio::test(flavor = "multi_thread")]
    async fn issues_nfc_credential_async() {
        let issuer = NfcIssuer::new();
        let response = issuer
            .fetch_credential_async(r#"{"user_id":"user-xyz"}"#.to_string())
            .await
            .expect("should issue credential");

        let cred: Credential = serde_json::from_str(&response).expect("should parse");
        assert_eq!(cred.issuer, "nfc-kit");
        assert!(cred.data.contains("user-xyz"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn rejects_blank_user_id_async() {
        let issuer = NfcIssuer::new();
        assert!(
            issuer
                .fetch_credential_async(r#"{"user_id":""}"#.to_string())
                .await
                .is_err()
        );
    }

    // ── Issuer trait (sync, via block_in_place) ───────────────────────────────

    #[tokio::test(flavor = "multi_thread")]
    async fn issues_nfc_credential_via_issuer_trait() {
        let issuer = NfcIssuer::new();
        let response = tokio::task::block_in_place(|| {
            issuer.fetch_credential(r#"{"user_id":"user-issuer"}"#.to_string())
        })
        .expect("Issuer::fetch_credential should succeed");

        let cred: Credential = serde_json::from_str(&response).expect("should parse");
        assert_eq!(cred.issuer, "nfc-kit");
        assert!(cred.data.contains("user-issuer"));
    }

    // ── IssuerDriver blanket impl (handle_message) ────────────────────────────

    #[tokio::test(flavor = "multi_thread")]
    async fn blanket_handle_message_fetch_credential() {
        // NfcIssuer implements Issuer; the blanket gives it IssuerDriver.
        let driver: &dyn IssuerDriver = &NfcIssuer::new();

        let value = tokio::task::block_in_place(|| {
            driver.handle_message(IssuerMsg::FetchCredential {
                request_json: r#"{"user_id":"blanket-nfc"}"#.to_string(),
            })
        })
        .expect("blanket dispatch should succeed");

        let IssuerValue::Credential { json } = value;
        let cred: Credential = serde_json::from_str(&json).expect("should parse");
        assert_eq!(cred.issuer, "nfc-kit");
        assert!(cred.data.contains("blanket-nfc"));
    }
}
