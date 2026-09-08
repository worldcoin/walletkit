//! Attested `Flamingo` matching in preparation for zero-knowledge proof generation.
//!
//! This module deliberately knows nothing about Orb PCP storage. Its caller supplies the live
//! image and the credential material obtained through the platform's Oxide/OrbKit adapter. The
//! module owns assignment, attestation verification, sealing, transport, response opening, and
//! match-token verification.

use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;
use flamingo_verifier_client::{
    Config, Error as ClientError, FaceVerifierClient, PcrMeasurement,
    VerifiedAssignment,
};
use flamingo_verifier_sealed_types::{FailureReason, MatchInputs, MatchResult};
use reqwest::{
    header::{HeaderMap, HeaderName, HeaderValue, COOKIE},
    Url,
};
use thiserror::Error;
use tokio::sync::OnceCell;

/// `WalletKit`'s attested `Flamingo` match module.
///
/// Keep this value alive across requests so the underlying HTTP client can retain transport state.
/// No WalletKit-owned sealing key is persisted: each verified assignment supplies the enclave's
/// attested public key, and the client creates fresh HPKE sealing material for the request.
///
/// ```no_run
/// use std::collections::HashMap;
/// use walletkit_core::flamingo::{FlamingoError, FlamingoMatcher};
/// # fn example(host_url: &str, measurements: HashMap<u32, Vec<u8>>, headers: HashMap<String, String>) -> Result<FlamingoMatcher, FlamingoError> {
/// let matcher = FlamingoMatcher::new(host_url)?
///     .with_measurements(measurements)?
///     .with_headers(headers)?;
/// # Ok(matcher)
/// # }
/// ```
#[derive(Debug, uniffi::Object)]
pub struct FlamingoMatcher {
    host_url: Url,
    config: Option<Config>,
    headers: HeaderMap,
    client: OnceCell<FaceVerifierClient>,
}

/// Inputs for one attested `Flamingo` match.
///
/// `credential_image` and `hashes_json` must come from the same enrolled Orb PCP. In particular,
/// `hashes_json` must contain the exact archive bytes, not parsed and reserialized JSON.
#[derive(Debug, uniffi::Record)]
pub struct FlamingoMatchRequest {
    /// Raw liveness image bytes captured for this request.
    pub live_image: Vec<u8>,
    /// Raw `thumbnail.png` bytes decrypted from the enrolled Orb PCP.
    pub credential_image: Vec<u8>,
    /// Exact raw `hashes.json` bytes extracted from the enrolled Orb PCP.
    pub hashes_json: Vec<u8>,
    /// Optional second liveness frame for the `LightGuard` flow.
    pub light_guard_image: Option<Vec<u8>>,
    /// Raw challenge image bytes downloaded from the relying party.
    pub challenge_image: Vec<u8>,
    /// Minimum similarity required by the RP. Must be finite and between zero and one.
    pub match_threshold: f32,
}

/// A match token whose signing-key attestation and signature were verified.
///
/// Foreign callers receive an opaque handle. The token and signing-key attestation remain
/// together in Rust for proof generation and eventual relay of the attestation to the RP.
#[derive(Debug, uniffi::Object)]
pub struct VerifiedMatchToken {
    token: Vec<u8>,
    signing_key_attestation: Vec<u8>,
}

/// The outcome of the TEE match phase.
#[derive(Debug, uniffi::Enum)]
pub enum FlamingoMatchOutcome {
    /// The enclave issued a token and `WalletKit` verified it against an attested signing key.
    Matched(Arc<VerifiedMatchToken>),
    /// The response reported a rejection. An unsigned rejection does not authenticate its sender.
    Rejected(FlamingoMatchRejection),
}

/// A rejection reason reported in an encrypted match response.
///
/// The reason is unsigned; it is not proof that the attested enclave issued it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FlamingoMatchRejection {
    /// The sealed inputs were malformed.
    MalformedInputs,
    /// The PCP hashes file was invalid or did not contain the thumbnail commitment.
    InvalidHashesJson,
    /// The credential image did not match the PCP thumbnail commitment.
    ThumbnailHashMismatch,
    /// At least one comparison scored below the requested threshold.
    MatchBelowThreshold,
    /// The enclave could not obtain a usable comparison score from the images.
    ImageAnalysisFailed,
}

/// Failures while configuring or performing a match request.
#[derive(Debug, Error, uniffi::Error)]
pub enum FlamingoError {
    /// A caller-supplied value cannot form a valid match request.
    #[error("invalid {attribute}: {reason}")]
    InvalidInput {
        /// Name of the invalid field.
        attribute: String,
        /// Why the value was rejected.
        reason: String,
    },
    /// The verifier configuration was not valid.
    #[error("invalid Flamingo verifier configuration: {0}")]
    Configuration(String),
    /// Assignment, attestation, transport, channel opening, or token verification failed.
    #[error("Flamingo verifier request failed: {0}")]
    Verifier(String),
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
    /// Creates a matcher for a verifier base URL without opening an HTTP client.
    ///
    /// Supply trusted measurements through [`Self::with_measurements`] before matching.
    /// For the app gateway, the base URL includes the `/v1/flamingo` prefix.
    ///
    /// # Errors
    ///
    /// Returns [`FlamingoError::Configuration`] if the URL is not an absolute HTTP(S) URL.
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

    /// Returns a new matcher with trusted measurements keyed by PCR index.
    ///
    /// PCR0, PCR1, and PCR2 must be supplied from an approved enclave build. Additional entries
    /// are also pinned. Each value must contain the raw 48 measurement bytes.
    /// Retains configured headers. The original matcher and its in-flight requests are unchanged.
    /// The returned matcher creates its own HTTP client on its first match.
    ///
    /// # Errors
    /// Returns [`FlamingoError::Configuration`] if PCR0/1/2 is missing, or any measurement
    /// is not 48 bytes or is all zero.
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

    /// Returns a new matcher with these default headers, replacing any previously configured set.
    ///
    /// Headers apply to assignment, match, and reassignment requests. Measurements are retained.
    /// Use this method again when a bearer token changes, and retain the returned matcher.
    /// Request-specific headers, such as JSON content type, take precedence over defaults.
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

    /// Performs the attested TEE match phase.
    ///
    /// A stale assignment is retried exactly once with a fresh assignment and freshly sealed
    /// ciphertext. A reported rejection is returned without a retry. Only a successful match
    /// carries a token verified against an attested signing key.
    /// The first call creates the HTTP client; later calls reuse its connection pool and cookies.
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
    async fn client(&self) -> Result<&FaceVerifierClient, FlamingoError> {
        self.client
            .get_or_try_init(|| async {
                let config = self.config.clone().ok_or_else(|| {
                    FlamingoError::Configuration(
                        "trusted enclave measurements must be supplied with with_measurements"
                            .to_string(),
                    )
                })?;
                let http = reqwest::Client::builder().default_headers(self.headers.clone());
                FaceVerifierClient::with_http_client_builder(config, http)
                    .map_err(|error| FlamingoError::Verifier(error.to_string()))
            })
            .await
    }
}

impl FlamingoMatchRequest {
    fn validate(&self) -> Result<(), FlamingoError> {
        for (attribute, bytes) in [
            ("live_image", self.live_image.as_slice()),
            ("credential_image", self.credential_image.as_slice()),
            ("hashes_json", self.hashes_json.as_slice()),
        ] {
            if bytes.is_empty() {
                return Err(FlamingoError::InvalidInput {
                    attribute: attribute.to_string(),
                    reason: "must not be empty".to_string(),
                });
            }
        }

        if self.challenge_image.is_empty() {
            return Err(FlamingoError::InvalidInput {
                attribute: "challenge_image".to_string(),
                reason: "must not be empty".to_string(),
            });
        }

        if self.light_guard_image.as_ref().is_some_and(Vec::is_empty) {
            return Err(FlamingoError::InvalidInput {
                attribute: "light_guard_image".to_string(),
                reason: "must not be empty when provided".to_string(),
            });
        }

        if !self.match_threshold.is_finite()
            || !(0.0..=1.0).contains(&self.match_threshold)
        {
            return Err(FlamingoError::InvalidInput {
                attribute: "match_threshold".to_string(),
                reason: "must be finite and between 0 and 1 inclusive".to_string(),
            });
        }

        Ok(())
    }

    fn into_inputs(self) -> MatchInputs {
        MatchInputs {
            live_image: self.live_image,
            credential_image: self.credential_image,
            light_guard_image: self.light_guard_image,
            hashes_json: self.hashes_json,
            challenge_image: self.challenge_image,
            match_threshold: self.match_threshold,
        }
    }
}

impl VerifiedMatchToken {
    /// Borrows the encoded COSE/CBOR token for proof generation.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.token
    }

    /// Borrows the signing-key attestation to relay alongside the generated proof.
    #[must_use]
    pub fn signing_key_attestation(&self) -> &[u8] {
        &self.signing_key_attestation
    }
}

impl From<FailureReason> for FlamingoMatchRejection {
    fn from(value: FailureReason) -> Self {
        match value {
            FailureReason::MalformedInputs => Self::MalformedInputs,
            FailureReason::InvalidHashesJson => Self::InvalidHashesJson,
            FailureReason::ThumbnailHashMismatch => Self::ThumbnailHashMismatch,
            FailureReason::MatchBelowThreshold => Self::MatchBelowThreshold,
            FailureReason::ImageAnalysisFailed => Self::ImageAnalysisFailed,
        }
    }
}

#[async_trait]
impl MatchClient for FaceVerifierClient {
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
        let assignment = client
            .request_assignment()
            .await
            .map_err(|error| verifier_error(&error))?;

        match client.request_match(&assignment, &request).await {
            Ok(MatchResult::Success(statement)) => {
                return Ok(FlamingoMatchOutcome::Matched(Arc::new(
                    VerifiedMatchToken {
                        token: statement.token.into_bytes(),
                        signing_key_attestation: statement.signing_key_attestation,
                    },
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

    use flamingo_verifier_client::Error as ClientError;
    use flamingo_verifier_protocol::match_token::MatchToken;
    use flamingo_verifier_sealed_types::{
        AttestedStatement, FailureReason, MatchInputs, MatchResult,
    };

    use super::{
        perform_match, FlamingoError, FlamingoMatchOutcome, FlamingoMatchRejection,
        FlamingoMatchRequest, FlamingoMatcher, MatchClient,
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
        FlamingoMatchRequest {
            live_image: b"live".to_vec(),
            credential_image: b"credential".to_vec(),
            hashes_json: br#"{"thumbnail.png":"00"}"#.to_vec(),
            light_guard_image: None,
            challenge_image: b"challenge".to_vec(),
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
        let client = FakeClient::new([Ok(MatchResult::Success(AttestedStatement {
            token: MatchToken::from_bytes(b"signed-token".to_vec()),
            signing_key_attestation: b"signing-key-attestation".to_vec(),
        }))]);

        let outcome = perform_match(&client, request())
            .await
            .expect("match should succeed");

        let FlamingoMatchOutcome::Matched(token) = outcome else {
            panic!("expected a matched outcome");
        };
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
            Ok(MatchResult::Failed(FailureReason::MatchBelowThreshold)),
        ]);

        let outcome = perform_match(&client, request())
            .await
            .expect("fresh assignment should recover the match request");

        assert!(matches!(
            outcome,
            FlamingoMatchOutcome::Rejected(FlamingoMatchRejection::MatchBelowThreshold)
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
    async fn rejects_a_non_finite_threshold_before_assignment() {
        let client = FakeClient::new([]);
        let mut request = request();
        request.match_threshold = f32::NAN;

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
