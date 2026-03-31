use crate::error::WalletKitError;
use crate::http_request::Request;
use reqwest::Method;
use serde::{Deserialize, Serialize};

/// Request payload for registering or unregistering a recovery binding.
///
/// Serialized as JSON with `leafIndex` (camelCase) to match the `PoP` backend API.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, uniffi::Record)]
pub struct ManageRecoveryBindingRequest {
    /// Hex-encoded subject identifier of the recovery binding.
    pub sub: String,
    /// The authenticator's leaf index in the World ID Merkle tree.
    #[serde(rename = "leafIndex")]
    pub leaf_index: u64,
}

#[derive(Deserialize)]
struct ChallengeResponse {
    challenge: String,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, uniffi::Record)]
pub struct RecoveryBindingResponse {
    #[serde(rename = "recoveryAgent")]
    pub recovery_agent: String,
}

/// Low-level HTTP client for the Proof-of-Personhood (`PoP`) backend API.
///
/// Handles the REST calls for recovery binding management and challenge retrieval.
/// All requests that mutate state require a security token (signature) and a
/// challenge, passed via `X-Auth-Signature` and `X-Auth-Challenge` headers.
///
/// This client is not meant to be used directly — prefer [`super::RecoveryBindingManager`],
/// which orchestrates the full challenge-response signing flow.
pub struct PopBackendClient {
    request: Request,
    base_url: String,
}

impl PopBackendClient {
    /// Creates a new client targeting the given base URL.
    #[must_use]
    pub fn new(base_url: String) -> Self {
        let request = Request::new();
        Self { request, base_url }
    }
}

impl PopBackendClient {
    /// Registers a new recovery binding via `POST /api/v1/recovery-binding`.
    ///
    /// # Errors
    ///
    /// * [`WalletKitError::RecoveryBindingAlreadyExists`] — HTTP 409 (binding already registered).
    /// * [`WalletKitError::NetworkError`] — any other non-success status.
    pub async fn bind_recovery_agent(
        &self,
        request: ManageRecoveryBindingRequest,
        security_token: String,
        challenge: String,
    ) -> Result<(), WalletKitError> {
        let url: String = format!("{}/api/v1/recovery-binding", self.base_url);
        let response = self
            .request
            .post(&url)
            .json(&request)
            .header("X-Auth-Signature", security_token)
            .header("X-Auth-Challenge", challenge)
            .send()
            .await?;

        let response_status = response.status();
        match response_status {
            reqwest::StatusCode::CREATED | reqwest::StatusCode::OK => Ok(()),
            reqwest::StatusCode::CONFLICT => {
                Err(WalletKitError::RecoveryBindingAlreadyExists)
            }
            _ => {
                let error_message = response
                    .text()
                    .await
                    .unwrap_or_else(|e| format!("Unknown error: {e:?}"));
                Err(WalletKitError::NetworkError {
                    url,
                    error: error_message,
                    status: Some(response_status.as_u16()),
                })
            }
        }
    }

    /// Removes a recovery binding via `DELETE /api/v1/recovery-binding`.
    ///
    /// # Errors
    ///
    /// * [`WalletKitError::AccountDoesNotExist`] — HTTP 404 (no binding found).
    /// * [`WalletKitError::NetworkError`] — any other non-success status.
    pub async fn unbind_recovery_agent(
        &self,
        request: ManageRecoveryBindingRequest,
        security_token: String,
        challenge: String,
    ) -> Result<(), WalletKitError> {
        let url: String = format!("{}/api/v1/recovery-binding", self.base_url);
        let response = self
            .request
            .req(Method::DELETE, url.as_str())
            .json(&request)
            .header("X-Auth-Signature", security_token)
            .header("X-Auth-Challenge", challenge)
            .send()
            .await?;
        let response_status = response.status();
        match response_status {
            reqwest::StatusCode::OK => Ok(()),
            reqwest::StatusCode::NOT_FOUND => {
                Err(WalletKitError::RecoveryBindingDoesNotExist)
            }
            _ => {
                let error_message = response
                    .text()
                    .await
                    .unwrap_or_else(|e| format!("Unknown error: {e:?}"));
                Err(WalletKitError::NetworkError {
                    url,
                    error: error_message,
                    status: Some(response_status.as_u16()),
                })
            }
        }
    }

    /// Fetches a one-time challenge string via `GET /api/v1/challenge`.
    ///
    /// The returned challenge is used as input to the commitment signature
    /// required by the register/unregister endpoints.
    ///
    /// # Errors
    ///
    /// * [`WalletKitError::NetworkError`] — non-success HTTP status.
    /// * [`WalletKitError::SerializationError`] — response body is not valid JSON.
    pub async fn get_challenge(&self) -> Result<String, WalletKitError> {
        let url = format!("{}/api/v1/challenge", self.base_url);
        let response = self.request.get(url.as_str()).send().await?;

        let response_status = response.status();
        if !response_status.is_success() {
            let error_message = response
                .text()
                .await
                .unwrap_or_else(|e| format!("Unknown error: {e:?}"));
            return Err(WalletKitError::NetworkError {
                url,
                status: Some(response_status.as_u16()),
                error: error_message,
            });
        }

        let challenge_response: ChallengeResponse =
            response
                .json()
                .await
                .map_err(|e| WalletKitError::SerializationError {
                    error: format!("Failed to parse challenge response: {e}"),
                })?;

        Ok(challenge_response.challenge)
    }

    /// Fetches a recovery binding via `GET /api/v1/recovery-binding`.
    ///
    /// # Errors
    ///
    /// * [`WalletKitError::NetworkError`] — non-success HTTP status.
    /// * [`WalletKitError::SerializationError`] — response body is not valid JSON.
    /// * [`WalletKitError::RecoveryBindingDoesNotExist`] — HTTP 404 (no binding found).
    pub async fn get_recovery_binding(
        &self,
        leaf_index: u64,
    ) -> Result<RecoveryBindingResponse, WalletKitError> {
        let url = format!(
            "{}/api/v1/recovery-binding?leafIndex={leaf_index}",
            self.base_url
        );
        let response = self.request.get(url.as_str()).send().await?;

        let status = response.status();
        if status.is_success() {
            let recovery_binding: RecoveryBindingResponse = response.json().await?;
            return Ok(recovery_binding);
        }
        match status {
            reqwest::StatusCode::NOT_FOUND => {
                Err(WalletKitError::RecoveryBindingDoesNotExist)
            }
            _ => {
                let error_message = response
                    .text()
                    .await
                    .unwrap_or_else(|e| format!("Unknown error: {e:?}"));
                Err(WalletKitError::NetworkError {
                    url,
                    error: error_message,
                    status: Some(status.as_u16()),
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[tokio::test]
    async fn test_register_recovery_agent_success() {
        let mut server = mockito::Server::new_async().await;
        let url = server.url();

        let request = ManageRecoveryBindingRequest {
            sub: "test-sub-123".to_string(),
            leaf_index: 42,
        };

        let mock = server
            .mock("POST", "/api/v1/recovery-binding")
            .match_body(mockito::Matcher::Json(serde_json::json!({
                "sub": "test-sub-123",
                "leafIndex": 42,
            })))
            .match_header("X-Auth-Signature", "security_token")
            .match_header("X-Auth-Challenge", "challenge")
            .with_status(201)
            .with_body("{}")
            .create_async()
            .await;

        let pop_api_client = PopBackendClient::new(url.clone());

        let result = pop_api_client
            .bind_recovery_agent(
                request,
                "security_token".to_string(),
                "challenge".to_string(),
            )
            .await;

        assert!(result.is_ok(), "Expected success but got error: {result:?}");
        mock.assert_async().await;
        drop(server);
    }

    #[tokio::test]
    async fn test_register_recovery_agent_conflict() {
        let mut server = mockito::Server::new_async().await;
        let url = server.url();

        let request = ManageRecoveryBindingRequest {
            sub: "test-sub-123".to_string(),
            leaf_index: 42,
        };

        let mock = server
            .mock("POST", "/api/v1/recovery-binding")
            .match_body(mockito::Matcher::Json(serde_json::json!({
                "sub": "test-sub-123",
                "leafIndex": 42,
            })))
            .match_header("X-Auth-Signature", "security_token")
            .match_header("X-Auth-Challenge", "challenge")
            .with_status(409)
            .with_body("Recovery agent already exists")
            .create_async()
            .await;

        let pop_api_client = PopBackendClient::new(url.clone());

        let result = pop_api_client
            .bind_recovery_agent(
                request,
                "security_token".to_string(),
                "challenge".to_string(),
            )
            .await;

        assert!(result.is_err(), "Expected error but got success");
        let err = result.unwrap_err();
        assert!(
            matches!(err, WalletKitError::RecoveryBindingAlreadyExists),
            "Expected RecoveryBindingAlreadyExists error, got: {err:?}"
        );
        mock.assert_async().await;
        drop(server);
    }

    #[tokio::test]
    async fn test_unregister_recovery_agent_success() {
        let mut server = mockito::Server::new_async().await;
        let url = server.url();

        let request = ManageRecoveryBindingRequest {
            sub: "test-sub-123".to_string(),
            leaf_index: 42,
        };

        let mock = server
            .mock("DELETE", "/api/v1/recovery-binding")
            .match_body(mockito::Matcher::Json(serde_json::json!({
                "sub": "test-sub-123",
                "leafIndex": 42,
            })))
            .match_header("X-Auth-Signature", "security_token")
            .match_header("X-Auth-Challenge", "challenge")
            .with_status(200)
            .with_body("{}")
            .create_async()
            .await;

        let pop_api_client = PopBackendClient::new(url.clone());

        let result = pop_api_client
            .unbind_recovery_agent(
                request,
                "security_token".to_string(),
                "challenge".to_string(),
            )
            .await;

        assert!(result.is_ok(), "Expected success but got error: {result:?}");
        mock.assert_async().await;
        drop(server);
    }

    #[tokio::test]
    async fn test_unregister_recovery_agent_not_found() {
        let mut server = mockito::Server::new_async().await;
        let url = server.url();

        let request = ManageRecoveryBindingRequest {
            sub: "test-sub-123".to_string(),
            leaf_index: 42,
        };

        let mock = server
            .mock("DELETE", "/api/v1/recovery-binding")
            .match_body(mockito::Matcher::Json(serde_json::json!({
                "sub": "test-sub-123",
                "leafIndex": 42,
            })))
            .match_header("X-Auth-Signature", "security_token")
            .match_header("X-Auth-Challenge", "challenge")
            .with_status(404)
            .with_body("Recovery agent not found")
            .create_async()
            .await;

        let pop_api_client = PopBackendClient::new(url.clone());

        let result = pop_api_client
            .unbind_recovery_agent(
                request,
                "security_token".to_string(),
                "challenge".to_string(),
            )
            .await;

        assert!(result.is_err(), "Expected error but got success");
        let err = result.unwrap_err();
        assert!(
            matches!(err, WalletKitError::RecoveryBindingDoesNotExist),
            "Expected RecoveryBindingDoesNotExist error, got: {err:?}"
        );
        mock.assert_async().await;
        drop(server);
    }

    #[tokio::test]
    async fn test_get_recovery_binding_success() {
        let mut server = mockito::Server::new_async().await;
        let url = server.url();

        let mock = server
            .mock("GET", "/api/v1/recovery-binding?leafIndex=42")
            .with_status(200)
            .with_body("{\"recoveryAgent\": \"0x1234567890abcdef\"}")
            .create_async()
            .await;

        let pop_api_client = PopBackendClient::new(url.clone());

        let result = pop_api_client.get_recovery_binding(42).await;
        assert!(result.is_ok(), "Expected success but got error: {result:?}");
        mock.assert_async().await;
        assert_eq!(result.unwrap().recovery_agent, "0x1234567890abcdef");
        drop(server);
    }

    #[tokio::test]
    async fn test_get_recovery_binding_not_found() {
        let mut server = mockito::Server::new_async().await;
        let url = server.url();

        let mock = server
            .mock("GET", "/api/v1/recovery-binding?leafIndex=42")
            .with_status(404)
            .with_body("Recovery agent not found")
            .create_async()
            .await;

        let pop_api_client = PopBackendClient::new(url.clone());

        let result = pop_api_client.get_recovery_binding(42).await;
        assert!(result.is_err(), "Expected error but got success");
        let err = result.unwrap_err();
        assert!(
            matches!(err, WalletKitError::RecoveryBindingDoesNotExist),
            "Expected RecoveryBindingDoesNotExist error, got: {err:?}"
        );
        mock.assert_async().await;
        drop(server);
    }
}
