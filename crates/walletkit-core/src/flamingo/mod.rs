//! Attested `Flamingo` matching in preparation for zero-knowledge proof generation.
//!
//! This module deliberately knows nothing about Orb PCP storage. Its caller supplies the live
//! image and the credential material obtained through the platform's Oxide/OrbKit adapter. The
//! module owns the WebSocket session, assignment, attestation verification, sealing, response
//! opening, and match-token verification.

mod errors;
mod types;

pub use errors::{
    FlamingoComparison, FlamingoError, FlamingoImageFailureReason, FlamingoImageRole,
    FlamingoInputFailureKind, FlamingoInputFailureReason, FlamingoMatchRejection,
    FlamingoResponseStage, FlamingoValidationTarget,
};
pub use types::{
    FlamingoDebugReport, FlamingoLiveCapture, FlamingoMatchOutcome,
    FlamingoMatchRequest, FlamingoMatchingFrame, VerifiedMatchToken,
};

use std::collections::HashMap;

use async_trait::async_trait;
use flamingo_verifier_client::{
    Config, Error as ClientError, FlamingoVerifierClient, FlamingoVerifierSession,
    PcrMeasurement, VerifiedMatchResult,
};
use flamingo_verifier_sealed_types::MatchInputs;
use reqwest::{
    header::{
        HeaderMap, HeaderName, HeaderValue, CONNECTION, COOKIE, HOST,
        SEC_WEBSOCKET_EXTENSIONS, SEC_WEBSOCKET_KEY, SEC_WEBSOCKET_PROTOCOL,
        SEC_WEBSOCKET_VERSION, UPGRADE,
    },
    Url,
};
use tokio::sync::OnceCell;

/// A simple wrapper around of `FlamingoVerifierClient`. Flamingo Verifier is a cloud TEE service for attested embedding generation and comparison.
#[derive(Debug, uniffi::Object)]
pub struct FlamingoMatcher {
    host_url: Url,
    config: Option<Config>,
    headers: HeaderMap,
    client: OnceCell<SessionClient>,
}

/// Headers the WebSocket handshake sets itself; a caller-supplied copy would be duplicated.
const HANDSHAKE_HEADERS: [HeaderName; 7] = [
    HOST,
    CONNECTION,
    UPGRADE,
    SEC_WEBSOCKET_KEY,
    SEC_WEBSOCKET_VERSION,
    SEC_WEBSOCKET_PROTOCOL,
    SEC_WEBSOCKET_EXTENSIONS,
];

#[async_trait]
trait MatchClient: Sync {
    type Session: Send;

    /// Opens a session whose assignment has already been verified.
    async fn connect(&self) -> Result<Self::Session, ClientError>;

    async fn request_match(
        &self,
        session: Self::Session,
        inputs: &MatchInputs,
    ) -> Result<VerifiedMatchResult, ClientError>;
}

/// The verifier client plus the headers sent on every WebSocket upgrade.
#[derive(Debug)]
struct SessionClient {
    client: FlamingoVerifierClient,
    headers: HeaderMap,
}

#[uniffi::export(async_runtime = "tokio")]
impl FlamingoMatcher {
    /// Creates an instance with default values, use `with_measurements` and `with_headers` for customization.
    ///
    /// # Errors
    ///
    /// Returns [`FlamingoError::Configuration`] if the URL is not a valid HTTP(S) URL.
    #[uniffi::constructor]
    pub fn new(host_url: &str) -> Result<Self, FlamingoError> {
        let host_url = Url::parse(host_url)
            .map_err(|error| FlamingoError::Configuration(error.to_string()))?;
        if !matches!(host_url.scheme(), "http" | "https")
            || host_url.host_str().is_none()
        {
            return Err(FlamingoError::Configuration(
                "host_url must be an absolute HTTP(S) URL".to_string(),
            ));
        }
        Ok(Self {
            host_url,
            config: None,
            headers: HeaderMap::new(),
            client: OnceCell::new(),
        })
    }

    /// Returns a new instance with trusted measurements keyed by PCR index.
    ///
    /// PCR0, PCR1, and PCR2 must be supplied from an approved enclave build. Additional entries
    /// are also pinned. It's the user's responsibility to ensure the measurements are from a trusted enclave and match the verifier's expectations.
    ///
    /// # Errors
    /// Returns [`FlamingoError::Configuration`] for missing PCR0/1/2, zero or malformed
    /// measurements.
    pub fn with_measurements(
        &self,
        measurements: HashMap<u32, Vec<u8>>,
    ) -> Result<Self, FlamingoError> {
        Ok(Self {
            host_url: self.host_url.clone(),
            config: Some(matcher_config(self.host_url.as_str(), measurements)?),
            headers: self.headers.clone(),
            client: OnceCell::new(),
        })
    }

    /// Returns a new instance that bypasses all PCR measurement checks.
    ///
    /// No measurements are required, and previously configured pins are discarded.
    /// Certificate chain, signature, freshness, and channel key binding remain verified.
    /// Calling [`Self::with_measurements`] on the returned instance restores strict verification.
    ///
    /// # Warning
    /// Accepts any enclave code with otherwise valid attestation, including Nitro debug
    /// enclaves. Use only for development, never in production.
    ///
    /// # Errors
    /// Returns [`FlamingoError::Configuration`] if the verifier configuration cannot be built.
    pub fn dangerously_skip_measurements(&self) -> Result<Self, FlamingoError> {
        let config = Config::dangerously_skip_measurements(self.host_url.as_str())
            .map_err(|error| FlamingoError::Configuration(error.to_string()))?;
        Ok(Self {
            host_url: self.host_url.clone(),
            config: Some(config),
            headers: self.headers.clone(),
            client: OnceCell::new(),
        })
    }

    /// Returns a new instance with these default headers, replacing any previously configured set.
    ///
    /// Use this to set authorization, client name, or other headers. They are sent on the
    /// WebSocket upgrade request of every match session.
    ///
    /// # Errors
    /// Returns [`FlamingoError::Configuration`] for invalid names/values, case-insensitive duplicate
    /// names, a `Cookie` header, or a header the WebSocket handshake sets itself (such as `Host`,
    /// `Upgrade`, or `Sec-WebSocket-*`).
    pub fn with_headers(
        &self,
        headers: HashMap<String, String>,
    ) -> Result<Self, FlamingoError> {
        Ok(Self {
            host_url: self.host_url.clone(),
            config: self.config.clone(),
            headers: parse_headers(headers)?,
            client: OnceCell::new(),
        })
    }

    /// Performs a attested 3-way embedding match and returns the outcome and optional worker diagnostics.
    ///
    /// - Opens a WebSocket session and verifies the enclave assignment delivered on it, including
    ///   PCRs unless explicitly bypassed.
    /// - Encrypts and sends the match inputs over the same session using the enclave's attested
    ///   public key.
    /// - Decrypts the result and, on success, verifies the token's signature and signing-key attestation.
    ///
    /// # Errors
    ///
    /// Returns [`FlamingoError::InvalidInput`] before making a network request when a caller value
    /// is unusable, or [`FlamingoError::Configuration`] if neither trusted measurements
    /// nor the explicit measurement bypass has been configured.
    /// Service, transport and verification failures are returned as typed [`FlamingoError`] variants.
    pub async fn perform_match(
        &self,
        request: FlamingoMatchRequest,
    ) -> Result<FlamingoMatchOutcome, FlamingoError> {
        perform_match(self.client().await?, request).await
    }
}

impl FlamingoMatcher {
    async fn client(&self) -> Result<&SessionClient, FlamingoError> {
        self.client
            .get_or_try_init(|| async {
                let config = self.config.clone().ok_or_else(|| {
                    FlamingoError::Configuration(
                        "trusted enclave measurements must be supplied with with_measurements"
                            .to_string(),
                    )
                })?;
                let client = FlamingoVerifierClient::new(config)
                    .map_err(|error| verifier_error(&error))?;
                Ok(SessionClient {
                    client,
                    headers: self.headers.clone(),
                })
            })
            .await
    }
}

#[async_trait]
impl MatchClient for SessionClient {
    type Session = FlamingoVerifierSession;

    async fn connect(&self) -> Result<Self::Session, ClientError> {
        let mut request = self.client.build_request()?;
        for (name, value) in &self.headers {
            // `parse_headers` only admits visible ASCII values, so this cannot fail.
            let value = value.to_str().map_err(|_| ClientError::InvalidConfig {
                attribute: "headers".to_string(),
                reason: "header values must be visible ASCII".to_string(),
            })?;
            request = request.with_header(name.as_str(), value);
        }
        self.client.connect_with(request).await
    }

    async fn request_match(
        &self,
        session: Self::Session,
        inputs: &MatchInputs,
    ) -> Result<VerifiedMatchResult, ClientError> {
        session.request_match(inputs).await
    }
}

fn parse_headers(headers: HashMap<String, String>) -> Result<HeaderMap, FlamingoError> {
    let mut parsed = HeaderMap::new();
    for (name, value) in headers {
        let name = HeaderName::from_bytes(name.as_bytes()).map_err(|_| {
            FlamingoError::Configuration("invalid HTTP header name".to_string())
        })?;
        if name == COOKIE {
            return Err(FlamingoError::Configuration(
                "Cookie is not supported on the match session".to_string(),
            ));
        }
        if HANDSHAKE_HEADERS.contains(&name) {
            return Err(FlamingoError::Configuration(format!(
                "{name} is set by the WebSocket handshake"
            )));
        }
        let mut value = HeaderValue::from_str(&value).map_err(|_| {
            FlamingoError::Configuration("invalid HTTP header value".to_string())
        })?;
        value.set_sensitive(true);
        if parsed.insert(name, value).is_some() {
            return Err(FlamingoError::Configuration(
                "duplicate HTTP header name (names are case-insensitive)".to_string(),
            ));
        }
    }
    Ok(parsed)
}

fn matcher_config(
    host_url: &str,
    measurements: HashMap<u32, Vec<u8>>,
) -> Result<Config, FlamingoError> {
    for index in 0..=2 {
        if !measurements.contains_key(&index) {
            return Err(FlamingoError::Configuration(format!(
                "PCR{index} must be supplied"
            )));
        }
    }
    let mut pcrs = Vec::with_capacity(measurements.len());
    for (index, measurement) in measurements {
        if measurement.len() != 48 {
            return Err(FlamingoError::Configuration(format!(
                "PCR{index} must be exactly 48 bytes"
            )));
        }
        if measurement.iter().all(|byte| *byte == 0) {
            return Err(FlamingoError::Configuration(format!(
                "PCR{index} must be nonzero; debug enclaves are not accepted"
            )));
        }
        pcrs.push(PcrMeasurement::new(index, measurement));
    }
    pcrs.sort_unstable_by_key(|pcr| pcr.index);
    Config::new(host_url, vec![pcrs])
        .map_err(|error| FlamingoError::Configuration(error.to_string()))
}

async fn perform_match<C: MatchClient>(
    client: &C,
    request: FlamingoMatchRequest,
) -> Result<FlamingoMatchOutcome, FlamingoError> {
    request.validate()?;
    let request = request.into_inputs();
    let mut reassigned = false;

    loop {
        // A session carries exactly one match, so a reassignment opens a fresh one.
        let session = client
            .connect()
            .await
            .map_err(|error| verifier_error(&error))?;

        match client.request_match(session, &request).await {
            Ok(response) => return Ok(response.into()),
            Err(ClientError::ReassignRequired) if !reassigned => reassigned = true,
            Err(error) => return Err(verifier_error(&error)),
        }
    }
}

fn verifier_error(error: &ClientError) -> FlamingoError {
    match error {
        ClientError::InvalidConfig { .. } | ClientError::MalformedConfig(_) => {
            FlamingoError::Configuration(error.to_string())
        }
        ClientError::ApiFrame { code, allow_retry } => FlamingoError::Service {
            code: code.clone(),
            allow_retry: *allow_retry,
        },
        ClientError::Timeout => FlamingoError::Timeout,
        ClientError::WebSocket(_) | ClientError::ConnectionClosed => {
            FlamingoError::Transport {
                details: error.to_string(),
            }
        }
        ClientError::MalformedAssignment => FlamingoError::InvalidResponse {
            stage: FlamingoResponseStage::Assignment,
        },
        ClientError::MalformedMessage => FlamingoError::InvalidResponse {
            stage: FlamingoResponseStage::HostMessage,
        },
        ClientError::MalformedResult => FlamingoError::InvalidResponse {
            stage: FlamingoResponseStage::MatchResult,
        },
        ClientError::Attestation(_) => FlamingoError::Attestation {
            details: error.to_string(),
        },
        ClientError::Channel(_) => FlamingoError::Channel {
            details: error.to_string(),
        },
        ClientError::InvalidSigningKey => FlamingoError::InvalidSigningKey,
        ClientError::StatementInvalid => FlamingoError::StatementInvalid,
        ClientError::ReassignRequired => FlamingoError::ReassignmentRequired,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{HashMap, VecDeque},
        sync::{
            atomic::{AtomicUsize, Ordering},
            Mutex,
        },
        time::Duration,
    };

    use futures_util::{SinkExt, StreamExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio_tungstenite::{
        accept_hdr_async,
        tungstenite::{handshake::server::Request, Message},
        WebSocketStream,
    };

    use flamingo_verifier_client::{
        Error as ClientError, VerifiedMatch, VerifiedMatchResult as MatchResult,
    };
    use flamingo_verifier_protocol::match_token::{MatchOperation, MatchToken};
    use flamingo_verifier_sealed_types::{
        AttestedStatement, DebugReport, FailureReason, MatchInputs,
    };

    use super::{
        perform_match, FlamingoError, FlamingoLiveCapture, FlamingoMatchOutcome,
        FlamingoMatchRejection, FlamingoMatchRequest, FlamingoMatcher, MatchClient,
    };

    struct FakeClient {
        assignments: AtomicUsize,
        results: Mutex<VecDeque<Result<MatchResult, ClientError>>>,
    }

    impl FakeClient {
        fn new(
            results: impl IntoIterator<Item = Result<MatchResult, ClientError>>,
        ) -> Self {
            Self {
                assignments: AtomicUsize::new(0),
                results: Mutex::new(results.into_iter().collect()),
            }
        }
    }

    #[async_trait::async_trait]
    impl MatchClient for FakeClient {
        type Session = usize;

        async fn connect(&self) -> Result<Self::Session, ClientError> {
            Ok(self.assignments.fetch_add(1, Ordering::Relaxed))
        }

        async fn request_match(
            &self,
            _session: Self::Session,
            _inputs: &MatchInputs,
        ) -> Result<MatchResult, ClientError> {
            self.results
                .lock()
                .expect("fake result lock should not be poisoned")
                .pop_front()
                .expect("test should provide one result per request")
        }
    }

    fn request() -> FlamingoMatchRequest {
        FlamingoMatchRequest::DeepFace {
            orb_credential: b"credential".to_vec(),
            live: FlamingoLiveCapture::Vanilla {
                image: b"live".to_vec(),
            },
            hashes_json: br#"{"thumbnail.png":"00"}"#.to_vec(),
            rtms_challenge: b"challenge".to_vec(),
            match_threshold: 0.7,
        }
    }

    fn measurements() -> HashMap<u32, Vec<u8>> {
        HashMap::from([(0, vec![1; 48]), (1, vec![2; 48]), (2, vec![3; 48])])
    }

    fn headers() -> HashMap<String, String> {
        HashMap::from([
            ("Authorization".to_string(), "Bearer test-token".to_string()),
            ("client-name".to_string(), "test-client".to_string()),
        ])
    }

    #[tokio::test]
    async fn gray_badge_preserves_typed_validation_feedback() {
        use flamingo_verifier_sealed_types::{ImageFailureReason, ImageRole};
        let client = FakeClient::new([Ok(MatchResult::Failed {
            reason: FailureReason::ImageRejected {
                image: ImageRole::LiveSelfie,
                reason: ImageFailureReason::EyesClosed,
                target: Some(flamingo_verifier_sealed_types::ValidationTarget::Image),
            },
            debug_report: DebugReport::NotProduced,
        })]);
        let outcome = perform_match(
            &client,
            FlamingoMatchRequest::GrayBadge {
                live: FlamingoLiveCapture::Vanilla { image: vec![1] },
                rtms_challenge: vec![2],
                match_threshold: 0.5,
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            outcome,
            FlamingoMatchOutcome::Rejected {
                reason: FlamingoMatchRejection::ImageRejected {
                    image: super::FlamingoImageRole::LiveSelfie,
                    reason: super::FlamingoImageFailureReason::EyesClosed,
                    target: Some(super::FlamingoValidationTarget::Image),
                },
                ..
            }
        ));
    }
    #[tokio::test]
    async fn gray_badge_preserves_infrastructure_rejection() {
        let client = FakeClient::new([Ok(MatchResult::Failed {
            reason: FailureReason::Internal,
            debug_report: DebugReport::NotProduced,
        })]);
        let outcome = perform_match(
            &client,
            FlamingoMatchRequest::GrayBadge {
                live: FlamingoLiveCapture::Vanilla { image: vec![1] },
                rtms_challenge: vec![2],
                match_threshold: 0.5,
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            outcome,
            FlamingoMatchOutcome::Rejected {
                reason: FlamingoMatchRejection::Internal,
                ..
            }
        ));
    }
    #[test]
    fn custom_measurements_preserve_required_and_additional_pcrs() {
        let mut pins = measurements();
        pins.insert(8, vec![4; 48]);
        let config =
            super::matcher_config("https://verifier.example.com", pins).unwrap();
        let json = serde_json::to_value(config).unwrap();
        assert_eq!(json["allowed_pcr_configs"].as_array().unwrap().len(), 1);
        assert_eq!(json["allowed_pcr_configs"][0].as_array().unwrap().len(), 4);
        for (position, (index, measurement)) in
            [(0, [1; 48]), (1, [2; 48]), (2, [3; 48]), (8, [4; 48])]
                .into_iter()
                .enumerate()
        {
            assert_eq!(json["allowed_pcr_configs"][0][position]["index"], index);
            assert_eq!(
                json["allowed_pcr_configs"][0][position]["value"],
                hex::encode(measurement)
            );
        }
    }

    #[test]
    fn rejects_zero_or_malformed_measurements() {
        let matcher = FlamingoMatcher::new("https://verifier.example.com").unwrap();
        for index in [0, 1, 2, 8] {
            for invalid in [vec![0; 48], vec![], vec![1; 47], vec![1; 49]] {
                let mut pins = measurements();
                pins.insert(index, invalid);
                assert!(matches!(
                    matcher.with_measurements(pins),
                    Err(FlamingoError::Configuration(_))
                ));
            }
        }
    }

    #[test]
    fn measurement_skip_needs_no_pins_and_preserves_headers() {
        let matcher = FlamingoMatcher::new("https://verifier.example.com")
            .unwrap()
            .with_headers(headers())
            .unwrap();
        let skip = matcher.dangerously_skip_measurements().unwrap();
        let json = serde_json::to_value(skip.config.as_ref().unwrap()).unwrap();
        assert_eq!(json["dangerously_skip_measurements"], true);
        assert_eq!(json["allowed_pcr_configs"], serde_json::json!([]));
        assert_eq!(skip.headers, matcher.headers);
        assert!(matcher.config.is_none());

        let skip_first = FlamingoMatcher::new("https://verifier.example.com")
            .unwrap()
            .dangerously_skip_measurements()
            .unwrap()
            .with_headers(headers())
            .unwrap();
        assert_eq!(
            serde_json::to_value(&skip.config).unwrap(),
            serde_json::to_value(&skip_first.config).unwrap()
        );
        assert_eq!(skip.headers, skip_first.headers);
    }

    #[tokio::test]
    async fn measurement_policy_changes_reset_client_and_restore_pins() {
        let pinned = FlamingoMatcher::new("https://verifier.example.com")
            .unwrap()
            .with_measurements(measurements())
            .unwrap();
        pinned.client().await.unwrap();
        let skip = pinned.dangerously_skip_measurements().unwrap();
        assert!(skip.client.get().is_none());
        skip.client().await.unwrap();
        assert_eq!(
            serde_json::to_value(&skip.config).unwrap()["allowed_pcr_configs"],
            serde_json::json!([])
        );
        assert!(skip.with_measurements(HashMap::new()).is_err());
        assert!(skip
            .with_measurements((0..=2).map(|index| (index, vec![0; 48])).collect())
            .is_err());

        let restored = skip.with_measurements(measurements()).unwrap();
        assert!(restored.client.get().is_none());
        restored.client().await.unwrap();
        assert_eq!(
            serde_json::to_value(&restored.config).unwrap(),
            serde_json::to_value(&pinned.config).unwrap()
        );
    }

    #[test]
    fn rejects_missing_required_measurements() {
        let matcher = FlamingoMatcher::new("https://verifier.example.com").unwrap();
        assert!(matches!(
            matcher.with_measurements(HashMap::new()),
            Err(FlamingoError::Configuration(_))
        ));
        for index in 0..3 {
            let mut pins = measurements();
            pins.remove(&index);
            let error = matcher.with_measurements(pins).unwrap_err();
            assert!(matches!(error, FlamingoError::Configuration(_)));
            assert!(error.to_string().contains(&format!("PCR{index}")));
        }
    }

    #[test]
    fn rejects_an_invalid_host_url() {
        for url in ["not a URL", "/relative", "ftp://verifier.example.com"] {
            assert!(matches!(
                FlamingoMatcher::new(url),
                Err(FlamingoError::Configuration(_))
            ));
        }
    }

    #[test]
    fn rejects_invalid_duplicate_cookie_and_handshake_headers_without_exposing_values()
    {
        let matcher = FlamingoMatcher::new("https://verifier.example.com").unwrap();
        for headers in [
            HashMap::from([("bad name".to_string(), "secret".to_string())]),
            HashMap::from([("authorization".to_string(), "secret\nvalue".to_string())]),
            HashMap::from([
                ("Authorization".to_string(), "secret".to_string()),
                ("authorization".to_string(), "secret".to_string()),
            ]),
            HashMap::from([("cOoKiE".to_string(), "secret".to_string())]),
            HashMap::from([("Host".to_string(), "secret".to_string())]),
            HashMap::from([("upgrade".to_string(), "secret".to_string())]),
            HashMap::from([("Sec-WebSocket-Key".to_string(), "secret".to_string())]),
        ] {
            let error = matcher.with_headers(headers).unwrap_err();
            assert!(matches!(error, FlamingoError::Configuration(_)));
            assert!(!format!("{error:?}").contains("secret"));
        }
    }

    #[tokio::test]
    async fn fluent_configuration_is_order_independent_and_preserves_originals() {
        let original = FlamingoMatcher::new("https://verifier.example.com").unwrap();
        let first = original
            .with_measurements(measurements())
            .unwrap()
            .with_headers(headers())
            .unwrap();
        let second = original
            .with_headers(headers())
            .unwrap()
            .with_measurements(measurements())
            .unwrap();
        assert_eq!(
            serde_json::to_value(&first.config).unwrap(),
            serde_json::to_value(&second.config).unwrap()
        );
        assert_eq!(first.headers, second.headers);
        assert!(original.config.is_none());
        assert!(original.headers.is_empty());
        assert!(first.client.get().is_none());
        assert!(second.client.get().is_none());

        let (left, right) = tokio::join!(first.client(), first.client());
        assert!(std::ptr::eq(left.unwrap(), right.unwrap()));
        assert!(!format!("{first:?}").contains("test-token"));

        let updated = first.with_headers(HashMap::new()).unwrap();
        assert!(updated.client.get().is_none());
        assert!(updated.headers.is_empty());
        assert!(!first.headers.is_empty());
        assert!(!std::ptr::eq(
            first.client().await.unwrap(),
            updated.client().await.unwrap()
        ));
    }

    /// Serves one WebSocket upgrade, recording the request, then runs `session` on the socket.
    // The handshake callback's error type is fixed by tungstenite.
    #[allow(clippy::result_large_err)]
    async fn serve_once<F, Fut>(
        session: F,
    ) -> (String, tokio::sync::oneshot::Receiver<Request>)
    where
        F: FnOnce(WebSocketStream<TcpStream>) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = ()> + Send,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (seen, request) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let socket =
                accept_hdr_async(stream, move |request: &Request, response| {
                    let _ = seen.send(request.clone());
                    Ok(response)
                })
                .await
                .unwrap();
            session(socket).await;
        });
        (format!("http://{address}"), request)
    }

    #[tokio::test]
    async fn missing_measurements_fail_before_any_request() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let matcher =
            FlamingoMatcher::new(&format!("http://{}", listener.local_addr().unwrap()))
                .unwrap()
                .with_headers(headers())
                .unwrap();
        assert!(matches!(
            matcher.perform_match(request()).await,
            Err(FlamingoError::Configuration(_))
        ));
        assert!(matcher.client.get().is_none());
        assert!(
            tokio::time::timeout(Duration::from_millis(50), listener.accept())
                .await
                .is_err(),
            "no connection may be opened without measurements"
        );
    }

    #[tokio::test]
    async fn upgrade_carries_configured_headers_to_the_prefixed_route() {
        let (base_url, seen) = serve_once(|socket| async move { drop(socket) }).await;
        let matcher = FlamingoMatcher::new(&format!("{base_url}/v1/flamingo/"))
            .unwrap()
            .with_measurements(measurements())
            .unwrap()
            .with_headers(headers())
            .unwrap();

        // The stub closes right after the upgrade, so the session fails before any assignment.
        assert!(matches!(
            matcher.perform_match(request()).await,
            Err(FlamingoError::Transport { .. })
        ));

        let upgrade = seen.await.unwrap();
        assert_eq!(upgrade.uri().path(), "/v1/flamingo/v1/matches");
        assert_eq!(upgrade.headers()["authorization"], "Bearer test-token");
        assert_eq!(upgrade.headers()["client-name"], "test-client");
        assert_eq!(upgrade.headers().get_all("host").iter().count(), 1);
    }

    #[tokio::test]
    async fn rejects_an_unverifiable_assignment_before_sending_images() {
        let (sent, frames) = tokio::sync::oneshot::channel();
        let (base_url, _) = serve_once(|mut socket| async move {
            let first = socket.next().await.unwrap().unwrap();
            assert_eq!(
                first,
                Message::Text(r#"{"type":"assignment_request"}"#.into())
            );
            let assignment =
                r#"{"type":"assignment","attestation":"hEBAQEA=","public_key":"a2V5"}"#;
            socket.send(Message::Text(assignment.into())).await.unwrap();
            let mut binary = 0;
            while let Some(Ok(frame)) = socket.next().await {
                binary += usize::from(frame.is_binary());
            }
            let _ = sent.send(binary);
        })
        .await;
        let matcher = FlamingoMatcher::new(&base_url)
            .unwrap()
            .with_measurements(measurements())
            .unwrap()
            .with_headers(headers())
            .unwrap();

        let error = matcher.perform_match(request()).await.unwrap_err();

        assert!(matches!(error, FlamingoError::Channel { .. }));
        drop(matcher);
        assert_eq!(frames.await.unwrap(), 0, "no image frame may be sent");
    }

    #[tokio::test]
    async fn returns_a_verified_token_after_the_client_verifies_success() {
        let client = FakeClient::new([Ok(MatchResult::Success {
            verified: Box::new(VerifiedMatch {
                statement: AttestedStatement {
                    token: MatchToken::from_bytes(b"signed-token".to_vec()),
                    signing_key_attestation: b"signing-key-attestation".to_vec(),
                },
                claims: flamingo_verifier_protocol::match_token::MatchClaims {
                    live_capture_hash: [1; 32],
                    operation: MatchOperation::DeepFace {
                        credential_claim: [2; 32],
                    },
                    challenger_image_hash: [3; 32],
                    match_coefficient: 0.9,
                },
            }),
            debug_report: DebugReport::NotProduced,
        })]);

        let outcome = perform_match(&client, request())
            .await
            .expect("match should succeed");

        let FlamingoMatchOutcome::Matched { token, .. } = outcome else {
            panic!("expected a matched outcome");
        };
        assert_eq!(token.match_coefficient().to_bits(), 0.9f32.to_bits());
        assert_eq!(token.as_bytes(), b"signed-token");
        assert_eq!(token.signing_key_attestation(), b"signing-key-attestation");
        assert_eq!(client.assignments.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn returns_a_typed_sealed_rejection() {
        let client = FakeClient::new([Ok(MatchResult::Failed {
            reason: FailureReason::ThumbnailHashMismatch,
            debug_report: DebugReport::NotProduced,
        })]);

        let outcome = perform_match(&client, request())
            .await
            .expect("a sealed rejection is an outcome");

        assert!(matches!(
            outcome,
            FlamingoMatchOutcome::Rejected {
                reason: FlamingoMatchRejection::ThumbnailHashMismatch,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn reassigns_and_reseals_exactly_once() {
        let client = FakeClient::new([
            Err(ClientError::ReassignRequired),
            Ok(MatchResult::Failed {
                reason: FailureReason::MatchBelowThreshold(
                    flamingo_verifier_sealed_types::ComparisonRole::SelfieChallenge,
                ),
                debug_report: DebugReport::NotProduced,
            }),
        ]);

        let outcome = perform_match(&client, request())
            .await
            .expect("fresh assignment should recover the match request");

        assert!(matches!(
            outcome,
            FlamingoMatchOutcome::Rejected {
                reason: FlamingoMatchRejection::MatchBelowThreshold { .. },
                ..
            }
        ));
        assert_eq!(client.assignments.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn does_not_retry_a_second_stale_assignment() {
        let client = FakeClient::new([
            Err(ClientError::ReassignRequired),
            Err(ClientError::ReassignRequired),
        ]);

        let error = perform_match(&client, request())
            .await
            .expect_err("a second stale assignment should be surfaced");

        assert!(matches!(error, FlamingoError::ReassignmentRequired));
        assert_eq!(client.assignments.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn invalid_fields_fail_before_assignment() {
        use flamingo_verifier_api_types::{MAX_HASHES_JSON_BYTES, MAX_IMAGE_BYTES};

        for deep_face in [false, true] {
            for (attribute, limit) in [
                ("live.image", MAX_IMAGE_BYTES),
                ("live.illuminated", MAX_IMAGE_BYTES),
                ("live.unilluminated", MAX_IMAGE_BYTES),
                ("rtms_challenge", MAX_IMAGE_BYTES),
                ("orb_credential", MAX_IMAGE_BYTES),
                ("hashes_json", MAX_HASHES_JSON_BYTES),
            ] {
                if !deep_face && matches!(attribute, "orb_credential" | "hashes_json") {
                    continue;
                }
                for length in [0, limit + 1] {
                    let bytes = |field| {
                        if field == attribute {
                            vec![1; length]
                        } else {
                            vec![1]
                        }
                    };
                    let live = if attribute.starts_with("live.")
                        && attribute != "live.image"
                    {
                        FlamingoLiveCapture::LightGuard {
                            illuminated: bytes("live.illuminated"),
                            unilluminated: bytes("live.unilluminated"),
                            matching_frame: super::FlamingoMatchingFrame::Illuminated,
                        }
                    } else {
                        FlamingoLiveCapture::Vanilla {
                            image: bytes("live.image"),
                        }
                    };
                    let request = if deep_face {
                        FlamingoMatchRequest::DeepFace {
                            live,
                            orb_credential: bytes("orb_credential"),
                            hashes_json: bytes("hashes_json"),
                            rtms_challenge: bytes("rtms_challenge"),
                            match_threshold: 0.5,
                        }
                    } else {
                        FlamingoMatchRequest::GrayBadge {
                            live,
                            rtms_challenge: bytes("rtms_challenge"),
                            match_threshold: 0.5,
                        }
                    };
                    let client = FakeClient::new([]);
                    let error = perform_match(&client, request).await.unwrap_err();
                    let FlamingoError::InvalidInput {
                        attribute: actual,
                        reason,
                        kind,
                        limit_bytes,
                    } = error
                    else {
                        panic!("expected an input error");
                    };
                    assert_eq!(actual, attribute);
                    assert_eq!(
                        kind,
                        if length == 0 {
                            super::FlamingoInputFailureKind::Empty
                        } else {
                            super::FlamingoInputFailureKind::TooLarge
                        }
                    );
                    assert_eq!(limit_bytes, (length != 0).then_some(limit as u64));
                    assert_eq!(
                        reason,
                        if length == 0 {
                            "must not be empty".to_string()
                        } else {
                            format!("must not exceed {limit} bytes")
                        }
                    );
                    assert_eq!(client.assignments.load(Ordering::Relaxed), 0);
                }
            }
        }
    }

    #[tokio::test]
    async fn validates_combined_image_budget_before_assignment() {
        use flamingo_verifier_api_types::{MAX_IMAGE_BYTES, MAX_TOTAL_IMAGE_BYTES};

        for deep_face in [false, true] {
            let mut request = if deep_face {
                FlamingoMatchRequest::DeepFace {
                    live: FlamingoLiveCapture::Vanilla {
                        image: vec![1; MAX_IMAGE_BYTES],
                    },
                    orb_credential: vec![1],
                    hashes_json: vec![1],
                    rtms_challenge: vec![
                        1;
                        MAX_TOTAL_IMAGE_BYTES - MAX_IMAGE_BYTES - 1
                    ],
                    match_threshold: 1.0,
                }
            } else {
                FlamingoMatchRequest::GrayBadge {
                    live: FlamingoLiveCapture::LightGuard {
                        illuminated: vec![1; MAX_IMAGE_BYTES],
                        unilluminated: vec![1],
                        matching_frame: super::FlamingoMatchingFrame::Unilluminated,
                    },
                    rtms_challenge: vec![
                        1;
                        MAX_TOTAL_IMAGE_BYTES - MAX_IMAGE_BYTES - 1
                    ],
                    match_threshold: 0.0,
                }
            };
            request.validate().expect("exact budget is valid");
            match &mut request {
                FlamingoMatchRequest::DeepFace { rtms_challenge, .. }
                | FlamingoMatchRequest::GrayBadge { rtms_challenge, .. } => {
                    rtms_challenge.push(1);
                }
            }
            let client = FakeClient::new([]);
            let error = perform_match(&client, request).await.unwrap_err();
            assert!(
                matches!(error, FlamingoError::InvalidInput { attribute, reason, .. }
                if attribute == "request" && reason == format!("combined image size must not exceed {MAX_TOTAL_IMAGE_BYTES} bytes"))
            );
            assert_eq!(client.assignments.load(Ordering::Relaxed), 0);
        }
    }

    #[tokio::test]
    async fn rejects_a_non_finite_threshold_before_assignment() {
        let client = FakeClient::new([]);
        let mut request = request();
        let FlamingoMatchRequest::DeepFace {
            match_threshold, ..
        } = &mut request
        else {
            unreachable!()
        };
        *match_threshold = f64::NAN;

        let error = perform_match(&client, request).await.expect_err(
            "NaN would bypass enclave comparisons and must be rejected locally",
        );

        assert!(matches!(
            error,
            FlamingoError::InvalidInput {
                attribute,
                ..
            } if attribute == "match_threshold"
        ));
        assert_eq!(client.assignments.load(Ordering::Relaxed), 0);
    }
    #[tokio::test]
    async fn reports_survive_success_and_rejection_for_both_operations() {
        use flamingo_verifier_sealed_types::ComparisonRole;
        for deep_face in [false, true] {
            for rejected in [false, true] {
                for debug_report in [
                    DebugReport::Available {
                        json: "{ \"raw\": [1, 2] }\n".to_owned(),
                    },
                    DebugReport::NotProduced,
                    DebugReport::OmittedTooLarge {
                        original_size_bytes: 200_000,
                    },
                ] {
                    let outcome = if rejected {
                        MatchResult::Failed {
                            reason: FailureReason::MatchBelowThreshold(
                                ComparisonRole::SelfieChallenge,
                            ),
                            debug_report: debug_report.clone(),
                        }
                    } else {
                        MatchResult::Success {
                            verified: Box::new(VerifiedMatch {
                                statement: AttestedStatement {
                                    token: MatchToken::from_bytes(b"token".to_vec()),
                                    signing_key_attestation: b"attestation".to_vec(),
                                },
                                claims: flamingo_verifier_protocol::match_token::MatchClaims {
                                    operation: if deep_face {
                                        MatchOperation::DeepFace { credential_claim: [1; 32] }
                                    } else { MatchOperation::GrayBadge },
                                    live_capture_hash: [2; 32], challenger_image_hash: [3; 32], match_coefficient: 0.9,
                                },
                            }),
                            debug_report: debug_report.clone(),
                        }
                    };
                    let client = FakeClient::new([Ok(outcome)]);
                    let request = if deep_face {
                        request()
                    } else {
                        FlamingoMatchRequest::GrayBadge {
                            live: FlamingoLiveCapture::Vanilla { image: vec![1] },
                            rtms_challenge: vec![2],
                            match_threshold: 0.7,
                        }
                    };
                    let response = perform_match(&client, request).await.unwrap();
                    let (report, is_rejected) = match response {
                        FlamingoMatchOutcome::Matched { debug_report, .. } => {
                            (debug_report, false)
                        }
                        FlamingoMatchOutcome::Rejected { debug_report, .. } => {
                            (debug_report, true)
                        }
                    };
                    assert_eq!(report, debug_report.into());
                    assert_eq!(is_rejected, rejected);
                    assert_eq!(client.assignments.load(Ordering::Relaxed), 1);
                }
            }
        }
    }

    #[tokio::test]
    async fn typed_service_and_verification_errors_do_not_add_retries() {
        for allow_retry in [false, true] {
            let client = FakeClient::new([Err(ClientError::ApiFrame {
                code: "enclave_not_ready".to_owned(),
                allow_retry,
            })]);
            let error = perform_match(&client, request()).await.unwrap_err();
            assert!(
                matches!(error, FlamingoError::Service { code, allow_retry: actual } if code == "enclave_not_ready" && actual == allow_retry)
            );
            assert_eq!(client.assignments.load(Ordering::Relaxed), 1);
        }
        for (error, expected) in [
            (ClientError::Timeout, FlamingoError::Timeout),
            (
                ClientError::ConnectionClosed,
                FlamingoError::Transport {
                    details: String::new(),
                },
            ),
            (
                ClientError::StatementInvalid,
                FlamingoError::StatementInvalid,
            ),
            (
                ClientError::InvalidSigningKey,
                FlamingoError::InvalidSigningKey,
            ),
            (
                ClientError::MalformedResult,
                FlamingoError::InvalidResponse {
                    stage: super::FlamingoResponseStage::MatchResult,
                },
            ),
        ] {
            let client = FakeClient::new([Err(error)]);
            let error = perform_match(&client, request()).await.unwrap_err();
            assert_eq!(
                std::mem::discriminant(&error),
                std::mem::discriminant(&expected)
            );
            assert_eq!(client.assignments.load(Ordering::Relaxed), 1);
        }
    }
}
