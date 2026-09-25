//! Attested `Flamingo` matching in preparation for zero-knowledge proof generation.
//!
//! This module deliberately knows nothing about Orb PCP storage. Its caller supplies the live
//! image and the credential material obtained through the platform's Oxide/OrbKit adapter. The
//! module owns assignment, attestation verification, sealing, transport, response opening, and
//! match-token verification.

mod errors;
mod types;

pub use errors::{
    FlamingoComparison, FlamingoError, FlamingoImageFailureReason, FlamingoImageRole,
    FlamingoMatchRejection,
};
pub use types::{
    FlamingoLiveCapture, FlamingoMatchOutcome, FlamingoMatchRequest,
    FlamingoMatchingFrame, VerifiedMatchToken,
};

use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;
use flamingo_verifier_client::{
    Config, Error as ClientError, FlamingoVerifierClient, PcrMeasurement,
    VerifiedAssignment, VerifiedMatchResult as MatchResult,
};
use flamingo_verifier_sealed_types::MatchInputs;
use reqwest::{
    header::{HeaderMap, HeaderName, HeaderValue, COOKIE},
    Url,
};
use tokio::sync::OnceCell;

/// A simple wrapper around of `FlamingoVerifierClient`. Flamingo Verifier is a cloud TEE service for attested embedding generation and comparison.
#[derive(Debug, uniffi::Object)]
pub struct FlamingoMatcher {
    host_url: Url,
    config: Option<Config>,
    headers: HeaderMap,
    client: OnceCell<FlamingoVerifierClient>,
}

#[async_trait]
trait MatchClient: Sync {
    type Assignment: Send + Sync;

    async fn request_assignment(&self) -> Result<Self::Assignment, ClientError>;

    async fn request_match(
        &self,
        assignment: &Self::Assignment,
        inputs: &MatchInputs,
    ) -> Result<MatchResult, ClientError>;
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
    /// measurements. Use [`Self::with_debug_measurements`] for development enclaves.
    pub fn with_measurements(
        &self,
        measurements: HashMap<u32, Vec<u8>>,
    ) -> Result<Self, FlamingoError> {
        Ok(Self {
            host_url: self.host_url.clone(),
            config: Some(matcher_config(self.host_url.as_str(), measurements, false)?),
            headers: self.headers.clone(),
            client: OnceCell::new(),
        })
    }

    /// Returns a new instance accepting explicitly supplied debug enclave measurements.
    ///
    /// Pass 48 zero bytes for each of PCR0, PCR1 and PCR2 to match a Nitro debug enclave.
    /// These values do not identify the enclave's code. Attestation signature, certificate,
    /// freshness and exact PCR matching checks still apply. For development only.
    ///
    /// # Errors
    /// Returns [`FlamingoError::Configuration`] for missing PCR0/1/2 or malformed measurements.
    pub fn with_debug_measurements(
        &self,
        measurements: HashMap<u32, Vec<u8>>,
    ) -> Result<Self, FlamingoError> {
        Ok(Self {
            host_url: self.host_url.clone(),
            config: Some(matcher_config(self.host_url.as_str(), measurements, true)?),
            headers: self.headers.clone(),
            client: OnceCell::new(),
        })
    }

    /// Returns a new instance with these default headers, replacing any previously configured set.
    ///
    /// Use this to set authorization, client name, or other headers. The `Cookie` header is not allowed; the client manages affinity cookies automatically.
    ///
    /// # Errors
    /// Returns [`FlamingoError::Configuration`] for invalid names/values, case-insensitive duplicate
    /// names, or a caller-supplied `Cookie` header (the client owns affinity cookies).
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

    /// Performs an attested 3-way embedding match.
    ///
    /// - Fetches the enclave assignment and verifies its attestation against the trusted PCRs.
    /// - Encrypts and sends the match inputs using the enclave's attested public key.
    /// - Decrypts the result and, on success, verifies the token's signature and signing-key attestation.
    ///
    /// # Errors
    ///
    /// Returns [`FlamingoError::InvalidInput`] before making a network request when a caller value
    /// is unusable, or [`FlamingoError::Configuration`] if trusted measurements are missing.
    /// Other failures are returned as [`FlamingoError::Verifier`].
    pub async fn perform_match(
        &self,
        request: FlamingoMatchRequest,
    ) -> Result<FlamingoMatchOutcome, FlamingoError> {
        perform_match(self.client().await?, request).await
    }
}

impl FlamingoMatcher {
    async fn client(&self) -> Result<&FlamingoVerifierClient, FlamingoError> {
        self.client
            .get_or_try_init(|| async {
                let config = self.config.clone().ok_or_else(|| {
                    FlamingoError::Configuration(
                        "trusted enclave measurements must be supplied with with_measurements"
                            .to_string(),
                    )
                })?;
                let http = reqwest::Client::builder().default_headers(self.headers.clone());
                FlamingoVerifierClient::with_http_client_builder(config, http)
                    .map_err(|error| FlamingoError::Verifier(error.to_string()))
            })
            .await
    }
}

#[async_trait]
impl MatchClient for FlamingoVerifierClient {
    type Assignment = VerifiedAssignment;

    async fn request_assignment(&self) -> Result<Self::Assignment, ClientError> {
        self.request_assignment().await
    }

    async fn request_match(
        &self,
        assignment: &Self::Assignment,
        inputs: &MatchInputs,
    ) -> Result<MatchResult, ClientError> {
        self.request_match(assignment, inputs).await
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
                "Cookie is managed by the client's affinity cookie store".to_string(),
            ));
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
    allow_debug_measurements: bool,
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
        if !allow_debug_measurements && measurement.iter().all(|byte| *byte == 0) {
            return Err(FlamingoError::Configuration(format!(
                "PCR{index} must be nonzero; debug enclaves are not accepted"
            )));
        }
        pcrs.push(PcrMeasurement::new(index, measurement));
    }
    pcrs.sort_unstable_by_key(|pcr| pcr.index);
    let config = if allow_debug_measurements {
        Config::new_with_debug_measurements(host_url, vec![pcrs])
    } else {
        Config::new(host_url, vec![pcrs])
    };
    config.map_err(|error| FlamingoError::Configuration(error.to_string()))
}

async fn perform_match<C: MatchClient>(
    client: &C,
    request: FlamingoMatchRequest,
) -> Result<FlamingoMatchOutcome, FlamingoError> {
    request.validate()?;
    let request = request.into_inputs();
    let mut reassigned = false;

    loop {
        let assignment = client
            .request_assignment()
            .await
            .map_err(|error| verifier_error(&error))?;

        match client.request_match(&assignment, &request).await {
            Ok(MatchResult::Success(statement)) => {
                return Ok(FlamingoMatchOutcome::Matched(Arc::new(
                    VerifiedMatchToken::from(*statement),
                )));
            }
            Ok(MatchResult::Failed(reason)) => {
                return Ok(FlamingoMatchOutcome::Rejected(reason.into()));
            }
            Err(ClientError::ReassignRequired) if !reassigned => reassigned = true,
            Err(error) => return Err(verifier_error(&error)),
        }
    }
}

fn verifier_error(error: &ClientError) -> FlamingoError {
    FlamingoError::Verifier(error.to_string())
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{HashMap, VecDeque},
        sync::{
            atomic::{AtomicUsize, Ordering},
            Mutex,
        },
    };

    use flamingo_verifier_client::{
        Error as ClientError, VerifiedMatch, VerifiedMatchResult as MatchResult,
    };
    use flamingo_verifier_protocol::match_token::{MatchOperation, MatchToken};
    use flamingo_verifier_sealed_types::{
        AttestedStatement, FailureReason, MatchInputs,
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
        type Assignment = usize;

        async fn request_assignment(&self) -> Result<Self::Assignment, ClientError> {
            Ok(self.assignments.fetch_add(1, Ordering::Relaxed))
        }

        async fn request_match(
            &self,
            _assignment: &Self::Assignment,
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
        let client =
            FakeClient::new([Ok(MatchResult::Failed(FailureReason::ImageRejected {
                image: ImageRole::LiveSelfie,
                reason: ImageFailureReason::EyesClosed,
            }))]);
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
            FlamingoMatchOutcome::Rejected(FlamingoMatchRejection::ImageRejected {
                image: super::FlamingoImageRole::LiveSelfie,
                reason: super::FlamingoImageFailureReason::EyesClosed,
            })
        ));
    }
    #[tokio::test]
    async fn gray_badge_preserves_infrastructure_rejection() {
        let client =
            FakeClient::new([Ok(MatchResult::Failed(FailureReason::Internal))]);
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
            FlamingoMatchOutcome::Rejected(FlamingoMatchRejection::Internal)
        ));
    }
    #[test]
    fn custom_measurements_preserve_required_and_additional_pcrs() {
        let mut pins = measurements();
        pins.insert(8, vec![4; 48]);
        let config =
            super::matcher_config("https://verifier.example.com", pins, false).unwrap();
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
    fn debug_measurements_are_explicit_and_preserve_headers_and_extra_pins() {
        let matcher = FlamingoMatcher::new("https://verifier.example.com")
            .unwrap()
            .with_headers(HashMap::from([(
                "Authorization".to_string(),
                "Bearer test".to_string(),
            )]))
            .unwrap();
        let mut pins: HashMap<_, _> =
            (0..=2).map(|index| (index, vec![0; 48])).collect();
        pins.insert(8, vec![4; 48]);
        assert!(matcher.with_measurements(pins.clone()).is_err());
        let debug = matcher.with_debug_measurements(pins).unwrap();
        assert!(debug.config.as_ref().unwrap().verifier().is_ok());
        let json = serde_json::to_value(debug.config.as_ref().unwrap()).unwrap();
        assert_eq!(json["allow_debug_measurements"], true);
        assert_eq!(json["allowed_pcr_configs"][0].as_array().unwrap().len(), 4);
        for index in 0..=2 {
            assert_eq!(
                json["allowed_pcr_configs"][0][index]["value"],
                "00".repeat(48)
            );
        }
        assert_eq!(json["allowed_pcr_configs"][0][3]["index"], 8);
        assert_eq!(json["allowed_pcr_configs"][0][3]["value"], "04".repeat(48));
        assert_eq!(debug.headers, matcher.headers);
        assert!(matcher.config.is_none());
        let production = debug.with_measurements(measurements()).unwrap();
        assert_eq!(
            serde_json::to_value(production.config.unwrap()).unwrap()
                ["allow_debug_measurements"],
            false
        );
    }

    #[test]
    fn debug_measurements_still_require_all_three_well_formed_pins() {
        let matcher = FlamingoMatcher::new("https://verifier.example.com").unwrap();
        assert!(matcher.with_debug_measurements(HashMap::new()).is_err());
        for index in 0..=2 {
            let mut pins = measurements();
            pins.remove(&index);
            assert!(matcher.with_debug_measurements(pins).is_err());
        }
        for index in [0, 1, 2, 8] {
            for invalid in [vec![], vec![0; 47], vec![0; 49]] {
                let mut pins = measurements();
                pins.insert(index, invalid);
                assert!(matcher.with_debug_measurements(pins).is_err());
            }
        }
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
    fn rejects_invalid_duplicate_and_cookie_headers_without_exposing_values() {
        let matcher = FlamingoMatcher::new("https://verifier.example.com").unwrap();
        for headers in [
            HashMap::from([("bad name".to_string(), "secret".to_string())]),
            HashMap::from([("authorization".to_string(), "secret\nvalue".to_string())]),
            HashMap::from([
                ("Authorization".to_string(), "secret".to_string()),
                ("authorization".to_string(), "secret".to_string()),
            ]),
            HashMap::from([("cOoKiE".to_string(), "secret".to_string())]),
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

    #[tokio::test]
    async fn missing_measurements_fail_before_any_request() {
        let mut server = mockito::Server::new_async().await;
        let assignment = server
            .mock("POST", "/v1/enclave-assignment")
            .expect(0)
            .create_async()
            .await;
        let matcher = FlamingoMatcher::new(&server.url())
            .unwrap()
            .with_headers(headers())
            .unwrap();
        assert!(matches!(
            matcher.perform_match(request()).await,
            Err(FlamingoError::Configuration(_))
        ));
        assert!(matcher.client.get().is_none());
        assignment.assert_async().await;
        drop(server);
    }

    #[tokio::test]
    async fn http_defaults_and_affinity_cookies_cover_both_routes() {
        let mut server = mockito::Server::new_async().await;
        let assignment = server
            .mock("POST", "/v1/flamingo/v1/enclave-assignment")
            .match_header("authorization", "Bearer test-token")
            .match_header("client-name", "test-client")
            .with_header("set-cookie", "AWSALB=assigned-pod; Path=/")
            .with_status(204)
            .expect(2)
            .create_async()
            .await;
        let match_route = server
            .mock("POST", "/v1/flamingo/v1/matches")
            .match_header("authorization", "Bearer test-token")
            .match_header("client-name", "test-client")
            .match_header("cookie", "AWSALB=assigned-pod")
            .with_status(409)
            .expect(2)
            .create_async()
            .await;
        let matcher = FlamingoMatcher::new(&format!("{}/v1/flamingo/", server.url()))
            .unwrap()
            .with_measurements(measurements())
            .unwrap()
            .with_headers(headers())
            .unwrap();
        let client = matcher.client().await.unwrap();
        // Exercise the configured HTTP transport without fabricating a trusted Nitro attestation.
        // The separate retry tests below cover the match orchestration.
        let (http, _) = client.build_assignment_request().build_split();
        for _ in 0..2 {
            assert_eq!(
                client
                    .build_assignment_request()
                    .send()
                    .await
                    .unwrap()
                    .status(),
                204
            );
            assert_eq!(
                http.post(format!("{}/v1/flamingo/v1/matches", server.url()))
                    .send()
                    .await
                    .unwrap()
                    .status(),
                409
            );
        }
        assignment.assert_async().await;
        match_route.assert_async().await;
        drop(server);
    }

    #[tokio::test]
    async fn rejects_a_legacy_assignment_before_sending_images() {
        let mut server = mockito::Server::new_async().await;
        let assignment = server
            .mock("POST", "/v1/enclave-assignment")
            .match_header("authorization", "Bearer test-token")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"attestation":"YXR0ZXN0YXRpb24="}"#)
            .expect(1)
            .create_async()
            .await;
        let image_upload = server
            .mock("POST", "/v1/matches")
            .expect(0)
            .create_async()
            .await;
        let matcher = FlamingoMatcher::new(&server.url())
            .unwrap()
            .with_measurements(measurements())
            .unwrap()
            .with_headers(headers())
            .unwrap();

        let error = matcher.perform_match(request()).await.unwrap_err();

        assert!(matches!(error, FlamingoError::Verifier(_)));
        assignment.assert_async().await;
        image_upload.assert_async().await;
        drop(server);
    }

    #[tokio::test]
    async fn returns_a_verified_token_after_the_client_verifies_success() {
        let client =
            FakeClient::new([Ok(MatchResult::Success(Box::new(VerifiedMatch {
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
            })))]);

        let outcome = perform_match(&client, request())
            .await
            .expect("match should succeed");

        let FlamingoMatchOutcome::Matched(token) = outcome else {
            panic!("expected a matched outcome");
        };
        assert_eq!(token.match_coefficient().to_bits(), 0.9f32.to_bits());
        assert_eq!(token.as_bytes(), b"signed-token");
        assert_eq!(token.signing_key_attestation(), b"signing-key-attestation");
        assert_eq!(client.assignments.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn returns_a_typed_sealed_rejection() {
        let client = FakeClient::new([Ok(MatchResult::Failed(
            FailureReason::ThumbnailHashMismatch,
        ))]);

        let outcome = perform_match(&client, request())
            .await
            .expect("a sealed rejection is an outcome");

        assert!(matches!(
            outcome,
            FlamingoMatchOutcome::Rejected(
                FlamingoMatchRejection::ThumbnailHashMismatch
            )
        ));
    }

    #[tokio::test]
    async fn reassigns_and_reseals_exactly_once() {
        let client = FakeClient::new([
            Err(ClientError::ReassignRequired),
            Ok(MatchResult::Failed(FailureReason::MatchBelowThreshold(
                flamingo_verifier_sealed_types::ComparisonRole::SelfieChallenge,
            ))),
        ]);

        let outcome = perform_match(&client, request())
            .await
            .expect("fresh assignment should recover the match request");

        assert!(matches!(
            outcome,
            FlamingoMatchOutcome::Rejected(
                FlamingoMatchRejection::MatchBelowThreshold { .. }
            )
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

        assert!(matches!(error, FlamingoError::Verifier(_)));
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
                    } = error
                    else {
                        panic!("expected an input error");
                    };
                    assert_eq!(actual, attribute);
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
                matches!(error, FlamingoError::InvalidInput { attribute, reason }
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
}
