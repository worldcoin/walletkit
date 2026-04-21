//! NfcKit — NFC identity-document credential issuer for the host-mediated Issuers SDK.
//!
//! ## Trait layering
//!
//! * `NfcIssuer` implements [`issuer_sdk::Issuer`] with native async fn.
//! * The blanket `impl<T: Issuer> IssuerDriver for T` in `issuer-sdk` provides
//!   `handle_message` for free — no manual dispatch code needed here.
//! * The exported `handle_message` method below delegates to the blanket so
//!   Python (and Swift / Kotlin) can call it directly as an async UniFFI method.

use issuer_sdk::{
    build_credential_json, parse_request_json, Issuer, IssuerDriver, IssuerMsg, IssuerValue,
    SdkError,
};
use thiserror::Error;

/// Errors returned by the NFC issuer's async pathway.
#[derive(Debug, Error, uniffi::Error)]
pub enum NfcKitError {
    #[error("issuer-sdk error: {0}")]
    Sdk(String),
}

impl From<SdkError> for NfcKitError {
    fn from(error: SdkError) -> Self {
        Self::Sdk(error.to_string())
    }
}

/// Issuer that mints credentials via an NFC identity document.
#[derive(uniffi::Object)]
pub struct NfcIssuer;

impl Default for NfcIssuer {
    fn default() -> Self {
        Self::new()
    }
}

// ── Ergonomic Rust trait impl ─────────────────────────────────────────────────

/// Implement [`Issuer`] with native async fn.
///
/// The blanket `impl<T: Issuer> IssuerDriver for T` in `issuer-sdk` then
/// provides `handle_message` automatically.
#[async_trait::async_trait]
impl Issuer for NfcIssuer {
    async fn fetch_credential(&self, request_json: String) -> Result<String, SdkError> {
        self.fetch_credential_async(request_json)
            .await
            .map_err(|e| SdkError::IssuanceFailed(e.to_string()))
    }
}

// ── UniFFI exports ────────────────────────────────────────────────────────────

#[uniffi::export(async_runtime = "tokio")]
impl NfcIssuer {
    #[uniffi::constructor]
    pub fn new() -> Self {
        Self
    }

    /// NFC-pathway credential issuance (async, exported via UniFFI).
    ///
    /// In production: PCP decrypt → `/v2/decrypt-pcp-keys` → SD-JWT unseal.
    pub async fn fetch_credential_async(
        &self,
        request_json: String,
    ) -> Result<String, NfcKitError> {
        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        let request = parse_request_json(&request_json)?;
        let id = uuid::Uuid::new_v4().to_string();
        let data = format!(
            "eyJhbGciOiJFUzI1NiIsInR5cCI6IlNELUpXVCJ9.stub.nfc.{}",
            request.user_id
        );
        build_credential_json(&id, "nfc-kit", data).map_err(Into::into)
    }

    /// Async `handle_message` exported so foreign adapters can delegate to it
    /// directly — the routing from `IssuerMsg` to `Issuer::fetch_credential`
    /// happens inside the blanket impl in `issuer-sdk`.
    pub async fn handle_message(
        &self,
        msg: IssuerMsg,
    ) -> Result<IssuerValue, SdkError> {
        <Self as IssuerDriver>::handle_message(self, msg).await
    }
}

uniffi::setup_scaffolding!("nfc_kit");

#[cfg(test)]
mod tests {
    use super::NfcIssuer;
    use issuer_sdk::{Credential, IssuerDriver, IssuerMsg, IssuerValue, Issuer};

    #[tokio::test]
    async fn issues_nfc_credential_async() {
        let response = NfcIssuer::new()
            .fetch_credential_async(r#"{"user_id":"user-xyz"}"#.to_string())
            .await
            .unwrap();
        let cred: Credential = serde_json::from_str(&response).unwrap();
        assert_eq!(cred.issuer, "nfc-kit");
        assert!(cred.data.contains("user-xyz"));
    }

    #[tokio::test]
    async fn rejects_blank_user_id() {
        assert!(NfcIssuer::new()
            .fetch_credential_async(r#"{"user_id":""}"#.to_string())
            .await
            .is_err());
    }

    #[tokio::test]
    async fn issuer_trait_fetch_credential() {
        let json = NfcIssuer::new()
            .fetch_credential(r#"{"user_id":"user-issuer"}"#.to_string())
            .await
            .unwrap();
        let cred: Credential = serde_json::from_str(&json).unwrap();
        assert_eq!(cred.issuer, "nfc-kit");
        assert!(cred.data.contains("user-issuer"));
    }

    #[tokio::test]
    async fn blanket_handle_message_fetch_credential() {
        let driver: &dyn IssuerDriver = &NfcIssuer::new();
        let value = driver
            .handle_message(IssuerMsg::FetchCredential {
                request_json: r#"{"user_id":"blanket-nfc"}"#.to_string(),
            })
            .await
            .unwrap();
        let IssuerValue::Credential { json } = value;
        let cred: Credential = serde_json::from_str(&json).unwrap();
        assert_eq!(cred.issuer, "nfc-kit");
        assert!(cred.data.contains("blanket-nfc"));
    }
}
