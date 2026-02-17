use crate::error::WalletKitError;
use crate::Environment;
use reqwest::multipart::Form;
use reqwest::Client;
use serde::Deserialize;
use std::collections::HashMap;
use std::time::Duration;

/// Response from POP refresh endpoint
#[derive(Deserialize, Debug, Eq, PartialEq)]
pub struct RefreshCredentialsResponse {
    pub success: bool,
    pub credential: Option<String>,
    pub message: Option<String>,
}

/// Proof of Human credential issuer API client
#[derive(uniffi::Object)]
pub struct ProofOfHumanIssuer {
    base_url: String,
    client: Client,
    timeout: Duration,
}

#[uniffi::export]
impl ProofOfHumanIssuer {
    /// Create a new TFH POP issuer with the specified base URL
    #[uniffi::constructor]
    #[must_use]
    pub fn new(environment: &Environment, timeout: Option<Duration>) -> Self {
        let base_url = match environment {
            Environment::Staging => "https://app.stage.orb.worldcoin.org",
            Environment::Production => "https://app.orb.worldcoin.org",
        }
        .to_string();

        Self {
            base_url,
            client: Client::new(),
            timeout: timeout.unwrap_or(Duration::from_secs(60)),
        }
    }
}

impl ProofOfHumanIssuer {
    /// Refresh a POP credential (proof of personhood).
    ///
    /// Calls the `/api/v1/refresh` endpoint and returns a parsed credential string.
    ///
    /// # Arguments
    ///
    /// * `multipart_form` - The multipart form with pcp data to send in the request.
    /// * `headers` - The headers to send in the request. Expected headers are `x-zkp-proof` and `attestation-gateway-token`.
    /// * `id_commitment` - The ID commitment to use in the request.
    ///
    ///
    /// Returns error on network failure or invalid response.
    /// # Errors
    ///
    /// Returns error on network failure or invalid response.
    pub async fn refresh_pop_credential(
        &self,
        multipart_form: Form,
        headers: HashMap<String, String>,
        id_commitment: &str,
    ) -> Result<String, WalletKitError> {
        let url = format!("{}/api/v1/refresh?idComm={}", self.base_url, id_commitment);

        let mut request = self
            .client
            .post(url)
            .timeout(self.timeout)
            .multipart(multipart_form);

        for (key, value) in headers {
            request = request.header(key, value);
        }
        request = request.header(
            "User-Agent",
            format!("walletkit-core/{}", env!("CARGO_PKG_VERSION")),
        );

        let response = request.send().await?;
        let credential = self.parse_refresh_credentials_response(response).await?;
        Ok(credential)
    }

    async fn parse_refresh_credentials_response(
        &self,
        response: reqwest::Response,
    ) -> Result<String, WalletKitError> {
        let status = response.status();
        if !status.is_success() {
            let error_message = response
                .text()
                .await
                .unwrap_or_else(|_| String::from("Unknown error"));
            return Err(WalletKitError::NetworkError {
                url: "/refresh".to_string(),
                status: Some(status.as_u16()),
                error: error_message,
            });
        }

        let response_text = response.text().await?;
        let refresh_credentials_response =
            serde_json::from_str::<RefreshCredentialsResponse>(&response_text)
                .map_err(|e| WalletKitError::SerializationError {
                    error: format!("Failed to parse POP refresh response: {e}"),
                })?;

        if !refresh_credentials_response.success {
            return Err(WalletKitError::NetworkError {
                url: "/refresh".to_string(),
                status: Some(status.as_u16()),
                error: refresh_credentials_response.message.unwrap_or_default(),
            });
        }

        refresh_credentials_response.credential.ok_or_else(|| {
            WalletKitError::SerializationError {
                error: "Missing credential in successful response".to_string(),
            }
        })
    }
}

#[cfg(test)]
impl ProofOfHumanIssuer {
    /// Create an issuer with a custom base URL (for testing).
    #[must_use]
    pub fn with_base_url(base_url: &str) -> Self {
        Self {
            base_url: base_url.to_string(),
            client: Client::new(),
            timeout: Duration::from_secs(60),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockito::Server;
    use reqwest::multipart::Part;

    #[tokio::test]
    async fn test_refresh_pop_credential_success() {
        let mut server = Server::new_async().await;

        let mock = server
            .mock("POST", "/api/v1/refresh?idComm=test_id")
            .match_header(
                "content-type",
                mockito::Matcher::Regex("multipart/form-data.*".to_string()),
            )
            .match_header("x-test-header", "test_value")
            .with_status(200)
            .with_body(
                r#"{"success": true, "credential": "credential_xyz", "message": null}"#,
            )
            .create_async()
            .await;

        let issuer = ProofOfHumanIssuer::with_base_url(&server.url());

        let form = Form::new().part("field1", Part::text("value1"));

        let mut headers = HashMap::new();
        headers.insert("x-test-header".to_string(), "test_value".to_string());

        let result = issuer
            .refresh_pop_credential(form, headers, "test_id")
            .await;

        mock.assert_async().await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "credential_xyz");

        drop(server);
    }

    #[tokio::test]
    async fn test_refresh_pop_credential_failure_in_response() {
        let mut server = Server::new_async().await;

        let mock = server.mock("POST", "/api/v1/refresh?idComm=test_id")
            .with_status(200)
            .with_body(r#"{"success": false, "credential": null, "message": "Credential expired"}"#)
            .create_async()
            .await;

        let issuer = ProofOfHumanIssuer::with_base_url(&server.url());

        let form = Form::new();
        let headers = HashMap::new();

        let result = issuer
            .refresh_pop_credential(form, headers, "test_id")
            .await;

        mock.assert_async().await;
        assert!(result.is_err());
        match result.unwrap_err() {
            WalletKitError::NetworkError { error, .. } => {
                assert_eq!(error, "Credential expired");
            }
            _ => panic!("Expected NetworkError"),
        }

        drop(server);
    }
}
