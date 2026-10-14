use crate::error::WalletKitError;
use crate::http_request::Request;
use reqwest::Method;
use serde::{Deserialize, Serialize};
use std::error::Error as _;
use std::fmt::Write as _;

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
    /// The signature of the recovery agent update.
    pub signature: String,
    /// The nonce of the recovery agent update.
    pub nonce: String,
    /// The checksummed hex address of the recovery agent (e.g. `"0x1234…"`).
    #[serde(rename = "recoveryAgent")]
    pub recovery_agent: String,
}

#[derive(Deserialize)]
struct ChallengeResponse {
    challenge: String,
}

/// Error body returned by the recovery binding endpoints, carrying the sentinel error name.
#[derive(Deserialize)]
struct RecoveryBindingErrorResponse {
    error: String,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, uniffi::Record)]
pub struct RecoveryBindingResponse {
    #[serde(rename = "recoveryAgent")]
    pub recovery_agent: Option<String>,
    #[serde(rename = "pendingRecoveryAgent")]
    pub pending_recovery_agent: Option<String>,
    #[serde(rename = "executeAfter")]
    pub execute_after: Option<String>,
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
    pub fn new(base_url: String, user_agent: String) -> Self {
        let request = Request::new(user_agent);
        Self { request, base_url }
    }
}

impl PopBackendClient {
    /// Registers a new recovery binding via `POST /api/v1/recovery-binding`.
    ///
    /// # Errors
    ///
    /// * [`WalletKitError::IdentityNotFound`], [`WalletKitError::NoSuccessfulCaptureFound`],
    ///   [`WalletKitError::DebugReportNotFound`]: HTTP 404 Not Found, split by the `error`
    ///   field of the response body. An unrecognized body maps to `DebugReportNotFound`.
    /// * [`WalletKitError::NotEligibleForRecovery`] — HTTP 412 Precondition Failed.
    /// * [`WalletKitError::NetworkError`] — request or response-body read failure, or another
    ///   non-success status. Rejections retain the response body and HTTP status.
    pub async fn bind_recovery_agent(
        &self,
        request: ManageRecoveryBindingRequest,
        security_token: String,
        challenge: String,
    ) -> Result<(), WalletKitError> {
        let url: String = format!("{}/api/v1/recovery-binding", self.base_url);
        let endpoint = self.diagnostic_endpoint("/api/v1/recovery-binding");
        let response = self
            .request
            .post(&url)
            .json(&request)
            .header("X-Auth-Signature", security_token)
            .header("X-Auth-Challenge", challenge)
            .send()
            .await
            .map_err(|error| request_error("POST", &endpoint, error))?;

        let response_status = response.status();
        match response_status {
            reqwest::StatusCode::CREATED | reqwest::StatusCode::OK => Ok(()),
            reqwest::StatusCode::NOT_FOUND => {
                Err(eligibility_error(&endpoint, response).await)
            }
            reqwest::StatusCode::PRECONDITION_FAILED => {
                Err(WalletKitError::NotEligibleForRecovery)
            }
            _ => Err(response_error("POST", &endpoint, response).await),
        }
    }

    /// Removes a recovery binding via `DELETE /api/v1/recovery-binding`.
    ///
    /// # Errors
    ///
    /// * [`WalletKitError::AccountDoesNotExist`] — HTTP 404 (no binding found).
    /// * [`WalletKitError::NetworkError`] — request or response-body read failure, or another
    ///   non-success status.
    pub async fn unbind_recovery_agent(
        &self,
        request: ManageRecoveryBindingRequest,
        security_token: String,
        challenge: String,
    ) -> Result<(), WalletKitError> {
        let url: String = format!("{}/api/v1/recovery-binding", self.base_url);
        let endpoint = self.diagnostic_endpoint("/api/v1/recovery-binding");
        let response = self
            .request
            .req(Method::DELETE, url.as_str())
            .json(&request)
            .header("X-Auth-Signature", security_token)
            .header("X-Auth-Challenge", challenge)
            .send()
            .await
            .map_err(|error| request_error("DELETE", &endpoint, error))?;
        let response_status = response.status();
        match response_status {
            reqwest::StatusCode::OK => Ok(()),
            reqwest::StatusCode::NOT_FOUND => {
                Err(WalletKitError::RecoveryBindingDoesNotExist)
            }
            _ => Err(response_error("DELETE", &endpoint, response).await),
        }
    }

    /// Fetches a one-time challenge string via `GET /api/v1/challenge`.
    ///
    /// The returned challenge is used as input to the commitment signature
    /// required by the register/unregister endpoints.
    ///
    /// # Errors
    ///
    /// * [`WalletKitError::NetworkError`] — non-success HTTP status, request failure,
    ///   response-body read failure, or JSON decode failure.
    pub async fn get_challenge(&self) -> Result<String, WalletKitError> {
        let url = format!("{}/api/v1/challenge", self.base_url);
        let endpoint = self.diagnostic_endpoint("/api/v1/challenge");
        let response = self
            .request
            .get(url.as_str())
            .send()
            .await
            .map_err(|error| request_error("GET", &endpoint, error))?;
        if !response.status().is_success() {
            return Err(response_error("GET", &endpoint, response).await);
        }
        let challenge_response: ChallengeResponse =
            json_response("GET", &endpoint, response).await?;
        Ok(challenge_response.challenge)
    }

    /// Fetches a recovery binding via `GET /api/v1/recovery-binding`.
    ///
    /// # Errors
    ///
    /// * [`WalletKitError::NetworkError`] — non-success HTTP status, request failure,
    ///   response-body read failure, or JSON decode failure.
    /// * [`WalletKitError::RecoveryBindingDoesNotExist`] — HTTP 404 (no binding found).
    pub async fn get_recovery_binding(
        &self,
        leaf_index: u64,
    ) -> Result<RecoveryBindingResponse, WalletKitError> {
        let url = format!(
            "{}/api/v1/recovery-binding?leafIndex={leaf_index}",
            self.base_url
        );
        let endpoint = self.diagnostic_endpoint("/api/v1/recovery-binding");
        let response = self
            .request
            .get(url.as_str())
            .send()
            .await
            .map_err(|error| request_error("GET", &endpoint, error))?;
        let status = response.status();
        if status.is_success() {
            return json_response("GET", &endpoint, response).await;
        }
        if status == reqwest::StatusCode::NOT_FOUND {
            return Err(WalletKitError::RecoveryBindingDoesNotExist);
        }
        Err(response_error("GET", &endpoint, response).await)
    }

    fn diagnostic_endpoint(&self, route: &str) -> String {
        reqwest::Url::parse(&format!("{}{route}", self.base_url)).map_or_else(
            |_| route.to_string(),
            |url| format!("{}{}", url.origin().ascii_serialization(), url.path()),
        )
    }
}

/// Maps a 404 from `POST /api/v1/recovery-binding` to the eligibility failure named in the body.
///
/// An unrecognized body keeps the historical [`WalletKitError::DebugReportNotFound`] mapping.
async fn eligibility_error(
    endpoint: &str,
    response: reqwest::Response,
) -> WalletKitError {
    let status = response.status().as_u16();
    let context = response_context(&response);
    let body = match response.bytes().await {
        Ok(body) => body,
        Err(error) => {
            return WalletKitError::NetworkError {
                url: endpoint.to_string(),
                status: Some(status),
                error: format!(
                    "POST failed to read error body; {context}: {}",
                    request_cause(error)
                ),
            }
        }
    };
    match serde_json::from_slice::<RecoveryBindingErrorResponse>(&body)
        .map(|body| body.error)
        .as_deref()
    {
        Ok("IdentityNotFound") => WalletKitError::IdentityNotFound,
        Ok("NoSuccessfulCaptureFound") => WalletKitError::NoSuccessfulCaptureFound,
        _ => WalletKitError::DebugReportNotFound,
    }
}

fn request_error(
    method: &str,
    endpoint: &str,
    error: reqwest::Error,
) -> WalletKitError {
    WalletKitError::NetworkError {
        url: endpoint.to_string(),
        status: error.status().map(|status| status.as_u16()),
        error: format!("{method} request failed: {}", request_cause(error)),
    }
}

fn request_cause(error: reqwest::Error) -> String {
    let error = error.without_url();
    let mut message = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        message.push_str(": ");
        message.push_str(&cause.to_string());
        source = cause.source();
    }
    message
}

async fn response_error(
    method: &str,
    endpoint: &str,
    response: reqwest::Response,
) -> WalletKitError {
    let status = response.status().as_u16();
    let context = response_context(&response);
    let message = match response.text().await {
        Ok(body) => format!("{method} response rejected; {context}; body={body:?}"),
        Err(error) => format!(
            "{method} failed to read error body; {context}: {}",
            request_cause(error)
        ),
    };
    WalletKitError::NetworkError {
        url: endpoint.to_string(),
        status: Some(status),
        error: message,
    }
}

async fn json_response<T: serde::de::DeserializeOwned>(
    method: &str,
    endpoint: &str,
    response: reqwest::Response,
) -> Result<T, WalletKitError> {
    let status = response.status().as_u16();
    let context = response_context(&response);
    response.json().await.map_err(|error| {
        // Serde messages can echo successful authentication values.
        let mut json_detail = None;
        let mut source = error.source();
        while let Some(cause) = source {
            if let Some(json) = cause.downcast_ref::<serde_json::Error>() {
                json_detail = Some(format!(
                    "JSON {:?} at line {} column {}",
                    json.classify(),
                    json.line(),
                    json.column()
                ));
                break;
            }
            source = cause.source();
        }
        let (failure, detail) = match json_detail {
            Some(detail) => ("failed to decode JSON response", detail),
            None => ("failed to read response body", request_cause(error)),
        };
        WalletKitError::NetworkError {
            url: endpoint.to_string(),
            status: Some(status),
            error: format!("{method} {failure}; {context}: {detail}"),
        }
    })
}

fn response_context(response: &reqwest::Response) -> String {
    let mut context = format!("status={}", response.status());
    for name in [
        "content-type",
        "x-request-id",
        "x-amzn-requestid",
        "x-amzn-trace-id",
        "traceparent",
        "cf-ray",
    ] {
        if let Some(value) = response.headers().get(name) {
            let value = value.to_str().unwrap_or("<non-UTF8>");
            write!(context, "; {name}={value:?}")
                .expect("writing to a String cannot fail");
        }
    }
    context
}

#[cfg(test)]
mod tests {

    use super::*;
    use test_case::test_case;

    #[tokio::test]
    async fn test_register_recovery_agent_success() {
        let mut server = mockito::Server::new_async().await;
        let url = server.url();

        let recovery_agent = "0x1234567890abcdef".to_string();
        let request = ManageRecoveryBindingRequest {
            sub: "test-sub-123".to_string(),
            leaf_index: 42,
            signature: "0x1234567890abcdef".to_string(),
            nonce: "0x1234567890abcdef1".to_string(),
            recovery_agent: recovery_agent.clone(),
        };

        let mock = server
            .mock("POST", "/api/v1/recovery-binding")
            .match_body(mockito::Matcher::Json(serde_json::json!({
                "sub": "test-sub-123",
                "leafIndex": 42,
                "signature": "0x1234567890abcdef",
                "nonce": "0x1234567890abcdef1",
                "recoveryAgent": "0x1234567890abcdef",
            })))
            .match_header("X-Auth-Signature", "security_token")
            .match_header("X-Auth-Challenge", "challenge")
            .with_status(201)
            .with_body("{}")
            .create_async()
            .await;

        let pop_api_client =
            PopBackendClient::new(url.clone(), "test-user-agent".to_string());

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

    #[test_case(r#"{"error":"IdentityNotFound"}"#, "identity_not_found")]
    #[test_case(
        r#"{"error":"NoSuccessfulCaptureFound"}"#,
        "no_successful_capture_found"
    )]
    #[test_case(r#"{"error":"DebugReportNotFound"}"#, "debug_report_not_found")]
    #[test_case(r#"{"error":"SomethingNewFromTheBackend"}"#, "debug_report_not_found")]
    #[test_case("not json at all", "debug_report_not_found")]
    #[tokio::test]
    async fn test_register_recovery_agent_404_maps_to_eligibility_error(
        response_body: &str,
        expected_error: &str,
    ) {
        let mut server = mockito::Server::new_async().await;
        let url = server.url();

        let request = ManageRecoveryBindingRequest {
            sub: "test-sub-123".to_string(),
            leaf_index: 42,
            signature: "0x1234567890abcdef".to_string(),
            nonce: "0x1234567890abcdef1".to_string(),
            recovery_agent: "0x1234567890abcdef".to_string(),
        };

        let mock = server
            .mock("POST", "/api/v1/recovery-binding")
            .match_body(mockito::Matcher::Json(serde_json::json!({
                "sub": "test-sub-123",
                "leafIndex": 42,
                "signature": "0x1234567890abcdef",
                "nonce": "0x1234567890abcdef1",
                "recoveryAgent": "0x1234567890abcdef",
            })))
            .match_header("X-Auth-Signature", "security_token")
            .match_header("X-Auth-Challenge", "challenge")
            .with_status(404)
            .with_body(response_body)
            .create_async()
            .await;

        let pop_api_client =
            PopBackendClient::new(url.clone(), "test-user-agent".to_string());

        let result = pop_api_client
            .bind_recovery_agent(
                request,
                "security_token".to_string(),
                "challenge".to_string(),
            )
            .await;

        let err = result.expect_err("Expected error but got success");
        assert_eq!(err.to_string(), expected_error);
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
            signature: "0x1234567890abcdef".to_string(),
            nonce: "0x1234567890abcdef1".to_string(),
            recovery_agent: "0x0000000000000000000000000000000000000000".to_string(),
        };

        let mock = server
            .mock("DELETE", "/api/v1/recovery-binding")
            .match_body(mockito::Matcher::Json(serde_json::json!({
                "sub": "test-sub-123",
                "leafIndex": 42,
                "signature": "0x1234567890abcdef",
                "nonce": "0x1234567890abcdef1",
                "recoveryAgent": "0x0000000000000000000000000000000000000000",
            })))
            .match_header("X-Auth-Signature", "security_token")
            .match_header("X-Auth-Challenge", "challenge")
            .with_status(200)
            .with_body("{}")
            .create_async()
            .await;

        let pop_api_client =
            PopBackendClient::new(url.clone(), "test-user-agent".to_string());

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

        let recovery_agent = "0x0000000000000000000000000000000000000000".to_string();
        let request = ManageRecoveryBindingRequest {
            sub: "test-sub-123".to_string(),
            leaf_index: 42,
            signature: "0x1234567890abcdef".to_string(),
            nonce: "0x1234567890abcdef1".to_string(),
            recovery_agent: recovery_agent.clone(),
        };

        let mock = server
            .mock("DELETE", "/api/v1/recovery-binding")
            .match_body(mockito::Matcher::Json(serde_json::json!({
                "sub": "test-sub-123",
                "leafIndex": 42,
                "signature": "0x1234567890abcdef",
                "nonce": "0x1234567890abcdef1",
                "recoveryAgent": "0x0000000000000000000000000000000000000000",
            })))
            .match_header("X-Auth-Signature", "security_token")
            .match_header("X-Auth-Challenge", "challenge")
            .with_status(404)
            .with_body("Recovery agent not found")
            .create_async()
            .await;

        let pop_api_client =
            PopBackendClient::new(url.clone(), "test-user-agent".to_string());

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

        let pop_api_client =
            PopBackendClient::new(url.clone(), "test-user-agent".to_string());

        let result = pop_api_client.get_recovery_binding(42).await;
        assert!(result.is_ok(), "Expected success but got error: {result:?}");
        mock.assert_async().await;
        assert_eq!(
            result.unwrap().recovery_agent,
            Some("0x1234567890abcdef".to_string())
        );
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

        let pop_api_client =
            PopBackendClient::new(url.clone(), "test-user-agent".to_string());

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

    #[tokio::test]
    async fn test_get_recovery_binding_no_pending_recovery_agent() {
        let mut server = mockito::Server::new_async().await;
        let url = server.url();

        let mock = server
            .mock("GET", "/api/v1/recovery-binding?leafIndex=42")
            .with_status(200)
            .with_body("{\"recoveryAgent\": \"0x1234567890abcdef\"}")
            .create_async()
            .await;

        let pop_api_client =
            PopBackendClient::new(url.clone(), "test-user-agent".to_string());

        let result = pop_api_client.get_recovery_binding(42).await;
        assert!(result.is_ok(), "Expected success but got error: {result:?}");
        mock.assert_async().await;
        let recovery_binding = result.unwrap();
        assert_eq!(recovery_binding.pending_recovery_agent, None);
        assert_eq!(recovery_binding.execute_after, None);
        assert_eq!(
            recovery_binding.recovery_agent,
            Some("0x1234567890abcdef".to_string())
        );
        drop(server);
    }

    #[tokio::test]
    async fn test_get_recovery_binding_with_pending_recovery_agent() {
        let mut server = mockito::Server::new_async().await;
        let url = server.url();

        let mock = server
            .mock("GET", "/api/v1/recovery-binding?leafIndex=42")
            .with_status(200)
            .with_body("{\"recoveryAgent\": \"0x0000000000000000000000000000000000000001\", \"pendingRecoveryAgent\": \"0x0000000000000000000000000000000000000000\", \"executeAfter\": \"0x01\"}")
            .create_async()
            .await;

        let pop_api_client =
            PopBackendClient::new(url.clone(), "test-user-agent".to_string());

        let result = pop_api_client.get_recovery_binding(42).await;
        assert!(result.is_ok(), "Expected success but got error: {result:?}");
        mock.assert_async().await;
        let recovery_binding = result.unwrap();
        assert_eq!(
            recovery_binding.pending_recovery_agent,
            Some("0x0000000000000000000000000000000000000000".to_string())
        );
        assert_eq!(recovery_binding.execute_after, Some("0x01".to_string()));
        assert_eq!(
            recovery_binding.recovery_agent,
            Some("0x0000000000000000000000000000000000000001".to_string())
        );
        drop(server);
    }
    #[tokio::test]
    async fn recovery_transport_error_keeps_operation_and_source_cause() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let client =
            PopBackendClient::new(format!("https://{address}"), "test-agent".into());
        let error = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            client.get_recovery_binding(987_654_321),
        )
        .await
        .unwrap()
        .unwrap_err();
        let displayed = error.to_string();
        assert!(displayed.contains("GET"), "missing operation: {displayed}");
        assert!(
            displayed.contains("/api/v1/recovery-binding"),
            "missing endpoint: {displayed}"
        );
        assert!(
            displayed.to_lowercase().contains("refused"),
            "missing source cause: {displayed}"
        );
        assert!(!displayed.contains("987654321"));
        assert!(!format!("{error:?}").contains("987654321"));
    }
    fn recovery_request() -> ManageRecoveryBindingRequest {
        ManageRecoveryBindingRequest {
            sub: "PRIVATE_SUB".into(),
            leaf_index: 987_654_321,
            signature: "PRIVATE_SIGNATURE".into(),
            nonce: "PRIVATE_NONCE".into(),
            recovery_agent: "PRIVATE_RECOVERY_AGENT".into(),
        }
    }

    async fn call_recovery_endpoint(
        client: &PopBackendClient,
        method: &str,
        route: &str,
    ) -> Result<(), WalletKitError> {
        match (method, route) {
            ("POST", _) => {
                client
                    .bind_recovery_agent(
                        recovery_request(),
                        "PRIVATE_AUTH_SIGNATURE".into(),
                        "PRIVATE_AUTH_CHALLENGE".into(),
                    )
                    .await
            }
            ("DELETE", _) => {
                client
                    .unbind_recovery_agent(
                        recovery_request(),
                        "PRIVATE_AUTH_SIGNATURE".into(),
                        "PRIVATE_AUTH_CHALLENGE".into(),
                    )
                    .await
            }
            ("GET", "/api/v1/challenge") => client.get_challenge().await.map(|_| ()),
            ("GET", _) => client.get_recovery_binding(987_654_321).await.map(|_| ()),
            _ => panic!("unsupported fixture endpoint"),
        }
    }

    #[test_case("POST", "/api/v1/recovery-binding")]
    #[test_case("DELETE", "/api/v1/recovery-binding")]
    #[test_case("GET", "/api/v1/recovery-binding")]
    #[test_case("GET", "/api/v1/challenge")]
    #[tokio::test]
    async fn rejection_displays_method_status_body_and_response_metadata(
        method: &str,
        route: &str,
    ) {
        let mut server = mockito::Server::new_async().await;
        let uri = if method == "GET" && route == "/api/v1/recovery-binding" {
            format!("{route}?leafIndex=987654321")
        } else {
            route.to_string()
        };
        let mock = server
            .mock(method, uri.as_str())
            .with_status(503)
            .with_header("content-type", "application/json")
            .with_header("x-request-id", "request-abc123")
            .with_header("cf-ray", "ray-123-FRA")
            .with_body(r#"{"error":"upstream maintenance"}"#)
            .create_async()
            .await;
        let client = PopBackendClient::new(server.url(), "test-agent".into());
        let error = call_recovery_endpoint(&client, method, route)
            .await
            .unwrap_err();
        let displayed = error.to_string();
        for expected in [
            method,
            route,
            "503",
            "upstream maintenance",
            "application/json",
            "request-abc123",
            "ray-123-FRA",
        ] {
            assert!(
                displayed.contains(expected),
                "missing {expected}: {displayed}"
            );
        }
        for private in [
            "PRIVATE_",
            "987654321",
            "X-Auth-Signature",
            "X-Auth-Challenge",
        ] {
            assert!(
                !displayed.contains(private),
                "request data leaked: {displayed}"
            );
        }
        assert!(matches!(
            error,
            WalletKitError::NetworkError {
                status: Some(503),
                ..
            }
        ));
        mock.assert_async().await;
        drop(server);
    }

    #[test_case("/api/v1/challenge", "{", "Eof")]
    #[test_case("/api/v1/recovery-binding", "{", "Eof")]
    #[test_case("/api/v1/challenge", r#""PRIVATE_SUCCESS_CHALLENGE""#, "Data")]
    #[test_case("/api/v1/recovery-binding", r#""PRIVATE_SUCCESS_BINDING""#, "Data")]
    #[test_case("/api/v1/challenge", r#"{"challenge":123456789101112}"#, "Data")]
    #[test_case(
        "/api/v1/recovery-binding",
        r#"{"recoveryAgent":123456789101112}"#,
        "Data"
    )]
    #[tokio::test]
    async fn decode_failure_displays_context_without_successful_auth_data(
        route: &str,
        body: &str,
        category: &str,
    ) {
        let mut server = mockito::Server::new_async().await;
        let uri = if route == "/api/v1/recovery-binding" {
            format!("{route}?leafIndex=987654321")
        } else {
            route.to_string()
        };
        let mock = server
            .mock("GET", uri.as_str())
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_header("x-request-id", "decode-request-123")
            .with_body(body)
            .create_async()
            .await;
        let client = PopBackendClient::new(server.url(), "test-agent".into());
        let error = call_recovery_endpoint(&client, "GET", route)
            .await
            .unwrap_err();
        let displayed = error.to_string();
        for expected in [
            "GET",
            route,
            "200",
            "decode JSON",
            category,
            "line",
            "column",
            "application/json",
            "decode-request-123",
        ] {
            assert!(
                displayed.contains(expected),
                "missing {expected}: {displayed}"
            );
        }
        for private in ["PRIVATE_", "987654321", "123456789101112"] {
            assert!(
                !displayed.contains(private),
                "successful response data leaked: {displayed}"
            );
            assert!(!format!("{error:?}").contains(private));
        }
        assert!(matches!(
            error,
            WalletKitError::NetworkError {
                status: Some(200),
                ..
            }
        ));
        mock.assert_async().await;
        drop(server);
    }

    #[test_case(503)]
    #[test_case(404)]
    #[tokio::test]
    async fn failed_error_body_read_retains_context(status: usize) {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("POST", "/api/v1/recovery-binding")
            .with_status(status)
            .with_header("x-request-id", "truncated-request-123")
            .with_chunked_body(|writer| {
                writer.write_all(b"incomplete")?;
                Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionReset,
                    "fixture interrupted body",
                ))
            })
            .create_async()
            .await;
        let client = PopBackendClient::new(server.url(), "test-agent".into());
        let error = call_recovery_endpoint(&client, "POST", "/api/v1/recovery-binding")
            .await
            .unwrap_err();
        let displayed = error.to_string();
        for expected in [
            "POST",
            "/api/v1/recovery-binding",
            "failed to read error body",
            "truncated-request-123",
        ] {
            assert!(
                displayed.contains(expected),
                "missing {expected}: {displayed}"
            );
        }
        match error {
            WalletKitError::NetworkError {
                status: Some(observed),
                ..
            } => assert_eq!(usize::from(observed), status),
            other => panic!("missing status on body-read failure: {other:?}"),
        }
        mock.assert_async().await;
        drop(server);
    }

    #[tokio::test]
    async fn bind_precondition_failure_keeps_semantic_error() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("POST", "/api/v1/recovery-binding")
            .with_status(412)
            .create_async()
            .await;
        let client = PopBackendClient::new(server.url(), "test-agent".into());
        let error = call_recovery_endpoint(&client, "POST", "/api/v1/recovery-binding")
            .await
            .unwrap_err();
        assert!(matches!(error, WalletKitError::NotEligibleForRecovery));
        mock.assert_async().await;
        drop(server);
    }
    #[test]
    fn diagnostic_endpoint_preserves_base_path_without_private_url_parts() {
        let client = PopBackendClient::new(
            "https://private-user:private-password@stage.invalid/proxy".into(),
            "test-agent".into(),
        );
        assert_eq!(
            client.diagnostic_endpoint("/api/v1/recovery-binding"),
            "https://stage.invalid/proxy/api/v1/recovery-binding"
        );
        let client = PopBackendClient::new("https://private-user:private-password@stage.invalid/proxy?PRIVATE_QUERY#PRIVATE_FRAGMENT".into(), "test-agent".into());
        assert_eq!(
            client.diagnostic_endpoint("/api/v1/challenge"),
            "https://stage.invalid/proxy"
        );
    }

    #[tokio::test]
    async fn rejection_reports_the_actual_prefixed_endpoint() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/proxy/api/v1/challenge")
            .with_status(503)
            .with_body("upstream unavailable")
            .create_async()
            .await;
        let client = PopBackendClient::new(
            format!("{}/proxy", server.url()),
            "test-agent".into(),
        );
        let error = client.get_challenge().await.unwrap_err();
        assert!(error.to_string().contains("/proxy/api/v1/challenge"));
        mock.assert_async().await;
        drop(server);
    }
    #[tokio::test]
    async fn failed_success_body_read_retains_the_transport_cause() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/api/v1/challenge")
            .with_status(200)
            .with_header("x-request-id", "success-read-request")
            .with_chunked_body(|writer| {
                writer.write_all(b"{\"challenge\":")?;
                Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionReset,
                    "fixture interrupted body",
                ))
            })
            .create_async()
            .await;
        let client = PopBackendClient::new(server.url(), "test-agent".into());
        let error = client.get_challenge().await.unwrap_err();
        let displayed = error.to_string();
        assert!(
            displayed.contains("connection"),
            "transport cause was discarded: {displayed}"
        );
        assert!(displayed.contains("failed to read response body"));
        assert!(displayed.contains("200"));
        assert!(displayed.contains("success-read-request"));
        mock.assert_async().await;
        drop(server);
    }
}
