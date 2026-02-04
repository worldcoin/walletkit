use crate::{error::WalletKitError, request::Request, Environment};

use super::types::{NfcCredential, NfcRefreshResponse};

const ZKP_AUTH_HEADER: &str = "x-zkp-proof";
const ATTESTATION_GATEWAY_HEADER: &str = "attestation-gateway-token";

/// NFC credential issuer API client.
#[derive(uniffi::Object)]
pub struct NfcIssuer {
    base_url: String,
    request: Request,
}

#[uniffi::export(async_runtime = "tokio")]
impl NfcIssuer {
    /// Create a new NFC issuer for the specified environment.
    #[uniffi::constructor]
    #[must_use]
    pub fn new(environment: &Environment) -> Self {
        let base_url = match environment {
            Environment::Staging => "https://nfc.stage-crypto.worldcoin.org",
            Environment::Production => "https://nfc.crypto.worldcoin.org",
        }
        .to_string();

        Self {
            base_url,
            request: Request::new(),
        }
    }

    /// Refresh an NFC credential (migrate legacy PCP to v4).
    ///
    /// The `request_body` comes from Oxide's `prepare_nfc_refresh_payload()`.
    ///
    /// # Errors
    ///
    /// Returns error on network failure or invalid response.
    pub async fn refresh_nfc_credential(
        &self,
        request_body: &str,
        zkp_auth_header: &str,
        attestation_token: &str,
    ) -> Result<NfcCredential, WalletKitError> {
        let url = format!("{}/v2/refresh", self.base_url);

        let headers = [
            (ZKP_AUTH_HEADER, zkp_auth_header),
            (ATTESTATION_GATEWAY_HEADER, attestation_token),
        ];

        let response = self
            .request
            .post_raw_json(&url, request_body, &headers)
            .await?;

        let status = response.status();
        if !status.is_success() {
            let error_body = response.text().await.unwrap_or_default();
            return Err(WalletKitError::NetworkError {
                url,
                status: Some(status.as_u16()),
                error: format!("NFC refresh failed: {error_body}"),
            });
        }

        // Parse API response
        let refresh_response: NfcRefreshResponse =
            response
                .json()
                .await
                .map_err(|e| WalletKitError::SerializationError {
                    error: format!("Failed to parse NFC refresh response: {e}"),
                })?;

        // Parse and return the credential
        refresh_response.result.parse()
    }
}

impl NfcIssuer {
    /// Create an issuer with a custom base URL (for testing).
    #[cfg(test)]
    #[must_use]
    pub fn with_base_url(base_url: &str) -> Self {
        Self {
            base_url: base_url.to_string(),
            request: Request::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_staging_url() {
        let issuer = NfcIssuer::new(&Environment::Staging);
        assert_eq!(issuer.base_url, "https://nfc.stage-crypto.worldcoin.org");
    }

    #[test]
    fn test_production_url() {
        let issuer = NfcIssuer::new(&Environment::Production);
        assert_eq!(issuer.base_url, "https://nfc.crypto.worldcoin.org");
    }
}
