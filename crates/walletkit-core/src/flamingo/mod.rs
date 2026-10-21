//! Attested `Flamingo` requests (WIP-201) in preparation for zero-knowledge proof generation.
//!
//! This module deliberately knows nothing about Orb PCP storage. Its caller supplies the Engine
//! entries, such as the Credential image obtained through the platform's Oxide/OrbKit adapter, the
//! live capture and the challenge. The module owns the Authenticator's side of WIP-201 §3.8.2:
//! it verifies the Verifier's channel attestation, chooses the first Engine configuration the
//! Relying Party offered whose release manifest a trusted [`FlamingoEngineProvider`] signed, seals
//! the request, and verifies the returned Flamingo Token. No entry is sent before every check
//! passes.
//!
//! Legacy connections use [`FlamingoMatcher::new`] with app-token headers.
//! Attested connections use [`FlamingoMatcher::new_attested`] with a host-supplied
//! [`RequestIntegrityProvider`]. Each connection attempt prepares a [`RequestIntegritySession`]
//! containing a token and its key-bound [`RequestDigestSigner`].
//! The host owns token acquisition, refresh, audience selection, and
//! hardware-key lifecycle; `WalletKit` owns request signing and the verifier connection.
//! Request authentication is separate from enclave attestation and token verification.
//!
//! The shared `attested-request` implementation signs the final WebSocket handshake method,
//! HTTP(S) scheme, authority, path, query, empty body, and prepared token. Every connection,
//! including reassignment, gets a fresh timestamp, nonce, and signature even when the token
//! is reused.
//!
//! Requests carry no Authenticator Assertion yet; the Flamingo Token has `has_aat = 0`.

mod engine;
mod errors;
mod integrity;
mod types;

pub use engine::{FlamingoEngineConfiguration, FlamingoEngineProvider};
pub use errors::{
    FlamingoComparison, FlamingoError, FlamingoImageFailureReason, FlamingoImageRole,
    FlamingoInputFailureKind, FlamingoInputFailureReason, FlamingoMatchRejection,
    FlamingoResponseStage, FlamingoValidationTarget,
};
pub use integrity::{
    RequestDigestSigner, RequestIntegrityError, RequestIntegrityPlatform,
    RequestIntegrityProvider, RequestIntegritySession,
};
pub use types::{
    FlamingoDebugReport, FlamingoEntry, FlamingoMatchOutcome, FlamingoMatchRequest,
    VerifiedFlamingoToken,
};

use std::{collections::HashMap, sync::Arc, time::Duration};

use async_trait::async_trait;
use flamingo_verifier_client::{
    Config, Error as ClientError, FlamingoVerifierClient, FlamingoVerifierSession,
    PcrMeasurement, VerifiedMatchResult,
};
use flamingo_verifier_sealed_types::Request;
use reqwest::{
    header::{
        HeaderMap, HeaderName, HeaderValue, CONNECTION, COOKIE, HOST,
        SEC_WEBSOCKET_EXTENSIONS, SEC_WEBSOCKET_KEY, SEC_WEBSOCKET_PROTOCOL,
        SEC_WEBSOCKET_VERSION, UPGRADE,
    },
    Url,
};
use tokio::sync::OnceCell;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

/// A client of the Flamingo Verifier, a cloud TEE service that compares images or embeddings and
/// signs a Flamingo Token over the comparison.
#[derive(uniffi::Object)]
pub struct FlamingoMatcher {
    host_url: Url,
    config: Option<Config>,
    engine_provider: Option<Arc<FlamingoEngineProvider>>,
    headers: HeaderMap,
    integrity_provider: Option<Arc<dyn RequestIntegrityProvider>>,
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
    async fn connect(
        &self,
        request_timeout: Duration,
    ) -> Result<Self::Session, FlamingoError>;

    /// The releases the Verifier advertises for the session's assignment; not attested.
    fn loaded_releases(session: &Self::Session) -> &[[u8; 32]];

    async fn request_match(
        &self,
        session: Self::Session,
        request: &Request,
    ) -> Result<VerifiedMatchResult, ClientError>;
}

/// The verifier client plus the headers sent on every WebSocket upgrade.
struct SessionClient {
    config: Config,
    headers: HeaderMap,
    integrity_provider: Option<Arc<dyn RequestIntegrityProvider>>,
}

impl std::fmt::Debug for FlamingoMatcher {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FlamingoMatcher")
            .finish_non_exhaustive()
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl FlamingoMatcher {
    /// Creates a legacy matcher; supply app-token authentication with [`Self::with_headers`].
    ///
    /// Configure enclave measurements with [`Self::with_measurements`] and the trusted Engine
    /// Provider with [`Self::with_engine_provider`].
    ///
    /// # Errors
    ///
    /// Returns [`FlamingoError::Configuration`] if the URL is not a valid HTTP(S) URL
    /// or contains credentials or a fragment.
    #[uniffi::constructor]
    pub fn new(host_url: &str) -> Result<Self, FlamingoError> {
        let host_url = Url::parse(host_url)
            .map_err(|error| FlamingoError::Configuration(error.to_string()))?;
        if !matches!(host_url.scheme(), "http" | "https")
            || host_url.host_str().is_none()
            || !host_url.username().is_empty()
            || host_url.password().is_some()
            || host_url.fragment().is_some()
        {
            return Err(FlamingoError::Configuration(
                "host_url must be an absolute HTTP(S) URL without credentials or a fragment".to_string(),
            ));
        }
        Ok(Self {
            host_url,
            config: None,
            engine_provider: None,
            headers: HeaderMap::new(),
            integrity_provider: None,
            client: OnceCell::new(),
        })
    }

    /// Creates a matcher that signs every connection with a host-provided integrity session.
    ///
    /// Select this mode before connecting. Authentication failures never fall back to legacy.
    /// Configure enclave measurements with [`Self::with_measurements`] and the trusted Engine
    /// Provider with [`Self::with_engine_provider`].
    ///
    /// # Errors
    /// Returns [`FlamingoError::Configuration`] unless the URL is HTTPS without credentials
    /// or a fragment. Tokens and signatures must only be sent over an encrypted transport.
    #[uniffi::constructor]
    pub fn new_attested(
        host_url: &str,
        integrity_provider: Arc<dyn RequestIntegrityProvider>,
    ) -> Result<Self, FlamingoError> {
        let mut matcher = Self::new(host_url)?;
        if matcher.host_url.scheme() != "https" {
            return Err(FlamingoError::Configuration(
                "attested host_url must use HTTPS".to_string(),
            ));
        }
        matcher.integrity_provider = Some(integrity_provider);
        Ok(matcher)
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
            config: Some(matcher_config(self.host_url.as_str(), measurements)?),
            ..self.unconnected()
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
            config: Some(config),
            ..self.unconnected()
        })
    }

    /// Returns a new instance that trusts the release manifests of `engine_provider`.
    ///
    /// Every request runs an Engine configuration whose release manifest this provider signed.
    #[must_use]
    pub fn with_engine_provider(
        &self,
        engine_provider: Arc<FlamingoEngineProvider>,
    ) -> Self {
        Self {
            engine_provider: Some(engine_provider),
            ..self.unconnected()
        }
    }

    /// Returns a new instance with these default headers, replacing any previously configured set.
    ///
    /// Use this to set authorization, client name, or other headers. They are sent on the
    /// WebSocket upgrade request of every match session.
    ///
    /// # Errors
    /// Returns [`FlamingoError::Configuration`] for invalid names/values, case-insensitive duplicate
    /// names, a `Cookie` header, or a header the WebSocket handshake sets itself (such as `Host`,
    /// `Upgrade`, or `Sec-WebSocket-*`). `Integrity-Token`, `Signature-Input`, and
    /// `Signature` are reserved for request integrity.
    pub fn with_headers(
        &self,
        headers: HashMap<String, String>,
    ) -> Result<Self, FlamingoError> {
        Ok(Self {
            headers: parse_headers(headers)?,
            ..self.unconnected()
        })
    }

    /// Sends a WIP-201 request to the Verifier and returns the outcome and optional Engine
    /// diagnostics.
    ///
    /// Prepares an integrity session and signs the WebSocket upgrade before the request flow:
    ///
    /// - Opens a WebSocket session and verifies the enclave assignment delivered on it, including
    ///   PCRs unless explicitly bypassed.
    /// - Chooses the first offered Engine configuration that the trusted Engine Provider signed,
    ///   that has at most 8 response slots, and that the Verifier has loaded.
    /// - Encrypts and sends the request over the same session using the enclave's attested
    ///   public key.
    /// - Decrypts the result and, on success, verifies the Flamingo Token's signature, its
    ///   signing-key attestation and that its claims match the request.
    ///
    /// If the Verifier asks for a fresh assignment, the request is sent once more over a new
    /// session, choosing its configuration again.
    ///
    /// # Errors
    ///
    /// Returns [`FlamingoError::InvalidInput`] before making a network request when a caller value
    /// is unusable, or [`FlamingoError::Configuration`] if no Engine Provider, or neither trusted
    /// measurements nor the explicit measurement bypass, has been configured.
    /// Returns [`FlamingoError::NoSupportedEngine`] without sending the request when no offered
    /// configuration is available on the assigned Verifier.
    /// Native authentication failures are returned as [`FlamingoError::RequestIntegrity`].
    /// Service, transport and verification failures are returned as typed [`FlamingoError`] variants.
    pub async fn perform_match(
        &self,
        request: FlamingoMatchRequest,
    ) -> Result<FlamingoMatchOutcome, FlamingoError> {
        let engine_provider = self.engine_provider.as_deref().ok_or_else(|| {
            FlamingoError::Configuration(
                "a trusted Engine Provider must be supplied with with_engine_provider"
                    .to_string(),
            )
        })?;
        perform_match(self.client().await?, engine_provider, request).await
    }
}

impl FlamingoMatcher {
    /// A copy of this configuration that has not opened a client yet.
    fn unconnected(&self) -> Self {
        Self {
            host_url: self.host_url.clone(),
            config: self.config.clone(),
            engine_provider: self.engine_provider.clone(),
            headers: self.headers.clone(),
            integrity_provider: self.integrity_provider.clone(),
            client: OnceCell::new(),
        }
    }

    async fn client(&self) -> Result<&SessionClient, FlamingoError> {
        self.client
            .get_or_try_init(|| async {
                let config = self.config.clone().ok_or_else(|| {
                    FlamingoError::Configuration(
                        "trusted enclave measurements must be supplied with with_measurements"
                            .to_string(),
                    )
                })?;
                Ok(SessionClient {
                    config,
                    headers: self.headers.clone(),
                    integrity_provider: self.integrity_provider.clone(),
                })
            })
            .await
    }
}

#[async_trait]
impl MatchClient for SessionClient {
    type Session = FlamingoVerifierSession;

    async fn connect(
        &self,
        request_timeout: Duration,
    ) -> Result<Self::Session, FlamingoError> {
        let client = FlamingoVerifierClient::new(
            self.config.clone().with_request_timeout(request_timeout),
        )
        .map_err(|error| verifier_error(&error))?;
        let mut request = client
            .build_request()
            .map_err(|error| verifier_error(&error))?;
        for (name, value) in &self.headers {
            let value = value.to_str().map_err(|_| {
                FlamingoError::Configuration(
                    "header values must be visible ASCII".to_string(),
                )
            })?;
            request = request.with_header(name.as_str(), value);
        }
        if let Some(provider) = &self.integrity_provider {
            let handshake = request.clone().into_client_request().map_err(|_| {
                FlamingoError::Configuration("invalid WebSocket handshake".to_string())
            })?;
            let signed = integrity::sign_request(provider.clone(), handshake)
                .await
                .map_err(FlamingoError::RequestIntegrity)?;
            for (name, value) in signed.headers() {
                request = request.with_header(name, value);
            }
        }
        client
            .connect_with(request)
            .await
            .map_err(|error| verifier_error(&error))
    }

    fn loaded_releases(session: &Self::Session) -> &[[u8; 32]] {
        session.assignment().release_hashes()
    }

    async fn request_match(
        &self,
        session: Self::Session,
        request: &Request,
    ) -> Result<VerifiedMatchResult, ClientError> {
        session.request_match(request).await
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
        if matches!(
            name.as_str(),
            "integrity-token" | "signature-input" | "signature"
        ) {
            return Err(FlamingoError::Configuration(format!(
                "{name} is reserved for request integrity"
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
    engine_provider: &FlamingoEngineProvider,
    request: FlamingoMatchRequest,
) -> Result<FlamingoMatchOutcome, FlamingoError> {
    let mut request = request.prepare()?;
    let request_timeout = engine_provider.request_timeout(&request.offer);
    let mut reassigned = false;

    loop {
        // A session carries exactly one request, so a reassignment opens a fresh one.
        let session = client.connect(request_timeout).await?;
        let engine =
            engine_provider.select(&request.offer, C::loaded_releases(&session))?;
        let bound = request.bind(&engine)?;

        match client.request_match(session, &bound).await {
            Ok(result) => {
                return Ok(FlamingoMatchOutcome::new(result, engine.configuration))
            }
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
        ClientError::ReleaseUnavailable => FlamingoError::NoSupportedEngine,
        ClientError::MalformedRequest => FlamingoError::invalid_shape(
            "request",
            "cannot be encoded within the WIP-201 bounds",
        ),
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
            Arc, Mutex,
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
    use flamingo_verifier_sealed_types::{
        AttestedStatement, DebugReport, FailureReason, Request as MatchRequest,
    };
    use world_id_flamingo::{FlamingoClaims, FlamingoToken};

    use super::engine::tests::{provider, ENGINE_HASH};
    use super::{
        perform_match, FlamingoEngineConfiguration, FlamingoEngineProvider,
        FlamingoEntry, FlamingoError, FlamingoMatchOutcome, FlamingoMatchRejection,
        FlamingoMatchRequest, FlamingoMatcher, MatchClient, RequestDigestSigner,
        RequestIntegrityError, RequestIntegrityPlatform, RequestIntegrityProvider,
        RequestIntegritySession,
    };
    use crate::FieldElement;

    struct TestIntegrityProvider {
        prepared: AtomicUsize,
        signer: Arc<TestDigestSigner>,
        failure: Option<RequestIntegrityError>,
    }

    struct TestDigestSigner(AtomicUsize);

    impl RequestDigestSigner for TestDigestSigner {
        fn sign_digest(
            &self,
            digest: Vec<u8>,
        ) -> Result<Vec<u8>, RequestIntegrityError> {
            assert_eq!(digest.len(), 32);
            self.0.fetch_add(1, Ordering::Relaxed);
            Ok(vec![1])
        }
    }

    #[async_trait::async_trait]
    impl RequestIntegrityProvider for TestIntegrityProvider {
        async fn prepare(
            &self,
        ) -> Result<RequestIntegritySession, RequestIntegrityError> {
            self.prepared.fetch_add(1, Ordering::Relaxed);
            if let Some(error) = self.failure {
                return Err(error);
            }
            Ok(RequestIntegritySession {
                token: "test-integrity-token".to_string(),
                platform: RequestIntegrityPlatform::Ios,
                signer: self.signer.clone(),
            })
        }
    }

    fn integrity_provider() -> Arc<TestIntegrityProvider> {
        Arc::new(TestIntegrityProvider {
            prepared: AtomicUsize::new(0),
            signer: Arc::new(TestDigestSigner(AtomicUsize::new(0))),
            failure: None,
        })
    }

    /// Attaches a signer to an HTTP loopback fixture without weakening the public constructor.
    fn loopback_attested_matcher(
        host_url: &str,
        provider: Arc<dyn RequestIntegrityProvider>,
    ) -> Result<FlamingoMatcher, FlamingoError> {
        let mut matcher = FlamingoMatcher::new(host_url)?;
        assert_eq!(matcher.host_url.host_str(), Some("127.0.0.1"));
        matcher.integrity_provider = Some(provider);
        Ok(matcher)
    }

    /// The `(pipeline, match_strictness, release_hash)` of a payload sent to the Verifier.
    type SentEngine = (u16, u8, [u8; 32]);

    struct FakeClient {
        assignments: AtomicUsize,
        loaded_releases: Vec<[u8; 32]>,
        reassigned_releases: Option<Vec<[u8; 32]>>,
        sent: Mutex<Vec<SentEngine>>,
        results: Mutex<VecDeque<Result<MatchResult, ClientError>>>,
    }

    impl FakeClient {
        fn new(
            results: impl IntoIterator<Item = Result<MatchResult, ClientError>>,
        ) -> Self {
            Self::with_loaded_releases(vec![provider().1], results)
        }

        fn with_loaded_releases(
            loaded_releases: Vec<[u8; 32]>,
            results: impl IntoIterator<Item = Result<MatchResult, ClientError>>,
        ) -> Self {
            Self {
                assignments: AtomicUsize::new(0),
                loaded_releases,
                reassigned_releases: None,
                sent: Mutex::new(Vec::new()),
                results: Mutex::new(results.into_iter().collect()),
            }
        }

        fn sent(&self) -> Vec<SentEngine> {
            self.sent.lock().unwrap().clone()
        }
    }

    #[async_trait::async_trait]
    impl MatchClient for FakeClient {
        type Session = Vec<[u8; 32]>;

        async fn connect(
            &self,
            _request_timeout: Duration,
        ) -> Result<Self::Session, FlamingoError> {
            let attempt = self.assignments.fetch_add(1, Ordering::Relaxed);
            Ok(if attempt > 0 {
                self.reassigned_releases
                    .as_ref()
                    .unwrap_or(&self.loaded_releases)
                    .clone()
            } else {
                self.loaded_releases.clone()
            })
        }

        fn loaded_releases(session: &Self::Session) -> &[[u8; 32]] {
            session
        }

        async fn request_match(
            &self,
            _session: Self::Session,
            request: &MatchRequest,
        ) -> Result<MatchResult, ClientError> {
            let payload = request.payload().unwrap();
            self.sent.lock().unwrap().push((
                payload.pipeline,
                payload.match_strictness,
                payload.release_hash,
            ));
            self.results
                .lock()
                .expect("fake result lock should not be poisoned")
                .pop_front()
                .expect("test should provide one result per request")
        }
    }

    /// A credential/live/challenge request offering an unknown release, then the test release.
    fn request_for(release_hash: [u8; 32]) -> FlamingoMatchRequest {
        let entry = |data: &[u8]| FlamingoEntry {
            data: data.to_vec(),
            meta: Vec::new(),
        };
        FlamingoMatchRequest {
            aud: Arc::new(FieldElement::from(1_928_118)),
            nonce: Arc::new(FieldElement::from(42)),
            offered_configurations: vec![
                FlamingoEngineConfiguration {
                    release_hash: vec![0x33; 32],
                    pipeline: 1,
                    match_strictness: 1,
                },
                FlamingoEngineConfiguration {
                    release_hash: release_hash.to_vec(),
                    pipeline: 1,
                    match_strictness: 2,
                },
            ],
            entries: vec![
                entry(b"credential image"),
                entry(b"live image"),
                entry(b"challenge image"),
            ],
            compare: vec![0, 1, 2],
            hints: Vec::new(),
        }
    }

    fn request() -> FlamingoMatchRequest {
        request_for(provider().1)
    }

    fn engines() -> FlamingoEngineProvider {
        provider().0
    }

    fn engine_provider() -> Arc<FlamingoEngineProvider> {
        Arc::new(engines())
    }

    fn verified(debug_report: DebugReport) -> MatchResult {
        let zero = world_id_flamingo_primitives::FieldElement::ZERO;
        MatchResult::Success {
            verified: Box::new(VerifiedMatch {
                statement: AttestedStatement {
                    token: FlamingoToken::from_bytes(b"signed-token".to_vec()),
                    signing_key_attestation: b"signing-key-attestation".to_vec(),
                },
                claims: FlamingoClaims {
                    compared_entry_hashes: [zero; 4],
                    aud: zero,
                    nonce: zero,
                    aat: None,
                    engine_config_hash: zero,
                },
            }),
            debug_report,
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
    async fn returns_typed_sealed_rejections() {
        use flamingo_verifier_sealed_types::{
            ImageFailureReason, ImageRole, ValidationTarget,
        };

        for (reason, expected) in [
            (
                FailureReason::ImageRejected {
                    image: ImageRole::LiveSelfie,
                    reason: ImageFailureReason::EyesClosed,
                    target: Some(ValidationTarget::Image),
                },
                FlamingoMatchRejection::ImageRejected {
                    image: super::FlamingoImageRole::LiveSelfie,
                    reason: super::FlamingoImageFailureReason::EyesClosed,
                    target: Some(super::FlamingoValidationTarget::Image),
                },
            ),
            (
                FailureReason::UnsupportedPipeline,
                FlamingoMatchRejection::UnsupportedPipeline,
            ),
            (
                FailureReason::UnsupportedRelease,
                FlamingoMatchRejection::UnsupportedRelease,
            ),
            (
                FailureReason::RequestTooLarge,
                FlamingoMatchRejection::RequestTooLarge,
            ),
            (FailureReason::Replayed, FlamingoMatchRejection::Replayed),
            (
                FailureReason::EngineTimeout,
                FlamingoMatchRejection::EngineTimeout,
            ),
            (
                FailureReason::AatRejected,
                FlamingoMatchRejection::AatRejected,
            ),
            (FailureReason::Internal, FlamingoMatchRejection::Internal),
        ] {
            let client = FakeClient::new([Ok(MatchResult::Failed {
                reason,
                debug_report: DebugReport::NotProduced,
            })]);

            let outcome = perform_match(&client, &engines(), request())
                .await
                .expect("a sealed rejection is an outcome");

            let FlamingoMatchOutcome::Rejected { reason, .. } = outcome else {
                panic!("expected a rejection");
            };
            assert_eq!(reason, expected);
        }
    }

    #[tokio::test]
    async fn does_not_retry_busy_or_ambiguous_transport_failures() {
        for error in [
            ClientError::ApiFrame {
                code: "busy".to_string(),
                allow_retry: true,
            },
            ClientError::Timeout,
            ClientError::ConnectionClosed,
        ] {
            let client = FakeClient::new([Err(error)]);
            assert!(perform_match(&client, &engines(), request()).await.is_err());
            assert_eq!(client.assignments.load(Ordering::Relaxed), 1);
            assert_eq!(client.sent().len(), 1);
        }
    }

    #[tokio::test]
    async fn oversized_request_never_reaches_the_match_transport() {
        use super::engine::tests::{jwk, manifest_with_limits, metadata};
        let (manifest, release) =
            manifest_with_limits(ENGINE_HASH, 4, "release-1", 800, 100);
        let provider = FlamingoEngineProvider::from_metadata(&metadata(
            &[(&manifest, "active")],
            &[jwk("release-1", "active")],
        ))
        .unwrap();
        let client = FakeClient::with_loaded_releases(vec![release], []);
        assert!(matches!(
            perform_match(&client, &provider, request_for(release)).await,
            Err(FlamingoError::InvalidInput {
                limit_bytes: Some(100),
                ..
            })
        ));
        assert!(client.sent().is_empty());
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
        let matcher = FlamingoMatcher::new_attested(
            "https://verifier.example.com",
            integrity_provider(),
        )
        .unwrap();
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
        let matcher = FlamingoMatcher::new_attested(
            "https://verifier.example.com",
            integrity_provider(),
        )
        .unwrap()
        .with_headers(headers())
        .unwrap();
        let skip = matcher.dangerously_skip_measurements().unwrap();
        let json = serde_json::to_value(skip.config.as_ref().unwrap()).unwrap();
        assert_eq!(json["dangerously_skip_measurements"], true);
        assert_eq!(json["allowed_pcr_configs"], serde_json::json!([]));
        assert_eq!(skip.headers, matcher.headers);
        assert!(matcher.config.is_none());

        let skip_first = FlamingoMatcher::new_attested(
            "https://verifier.example.com",
            integrity_provider(),
        )
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
        let pinned = FlamingoMatcher::new_attested(
            "https://verifier.example.com",
            integrity_provider(),
        )
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
        let matcher = FlamingoMatcher::new_attested(
            "https://verifier.example.com",
            integrity_provider(),
        )
        .unwrap();
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

    /// Attested credentials cannot be sent to HTTP endpoints, including loopback.
    #[test]
    fn attested_constructor_requires_https() {
        for url in [
            "http://verifier.example.com",
            "http://127.0.0.1",
            "http://[::1]",
        ] {
            assert!(matches!(
                FlamingoMatcher::new_attested(url, integrity_provider()),
                Err(FlamingoError::Configuration(_))
            ));
        }
    }

    /// The legacy route still receives app authentication and no integrity headers.
    #[tokio::test]
    async fn legacy_upgrade_preserves_app_token_without_integrity_headers() {
        let (base_url, seen) = serve_once(|socket| async move { drop(socket) }).await;
        let matcher = FlamingoMatcher::new(&base_url)
            .unwrap()
            .with_measurements(measurements())
            .unwrap()
            .with_engine_provider(engine_provider())
            .with_headers(headers())
            .unwrap();
        assert!(matches!(
            matcher.perform_match(request()).await,
            Err(FlamingoError::Transport { .. })
        ));
        let upgrade = seen.await.unwrap();
        assert_eq!(upgrade.headers()["authorization"], "Bearer test-token");
        for header in ["integrity-token", "signature-input", "signature"] {
            assert!(!upgrade.headers().contains_key(header));
        }
    }

    #[test]
    fn rejects_an_invalid_host_url() {
        for url in [
            "not a URL",
            "/relative",
            "ftp://verifier.example.com",
            "https://user:secret@verifier.example.com",
            "https://verifier.example.com/#fragment",
        ] {
            assert!(matches!(
                FlamingoMatcher::new_attested(url, integrity_provider()),
                Err(FlamingoError::Configuration(_))
            ));
        }
    }

    #[test]
    fn rejects_invalid_duplicate_cookie_and_handshake_headers_without_exposing_values()
    {
        let matcher = FlamingoMatcher::new_attested(
            "https://verifier.example.com",
            integrity_provider(),
        )
        .unwrap();
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
            HashMap::from([("iNtEgRiTy-ToKeN".to_string(), "secret".to_string())]),
            HashMap::from([("SIGNATURE-INPUT".to_string(), "secret".to_string())]),
            HashMap::from([("Signature".to_string(), "secret".to_string())]),
        ] {
            let error = matcher.with_headers(headers).unwrap_err();
            assert!(matches!(error, FlamingoError::Configuration(_)));
            assert!(!format!("{error:?}").contains("secret"));
        }
    }

    #[tokio::test]
    async fn fluent_configuration_is_order_independent_and_preserves_originals() {
        let original = FlamingoMatcher::new_attested(
            "https://verifier.example.com",
            integrity_provider(),
        )
        .unwrap();
        let engines = engine_provider();
        let first = original
            .with_measurements(measurements())
            .unwrap()
            .with_engine_provider(engines.clone())
            .with_headers(headers())
            .unwrap();
        let second = original
            .with_headers(headers())
            .unwrap()
            .with_engine_provider(engines.clone())
            .with_measurements(measurements())
            .unwrap();
        assert_eq!(
            serde_json::to_value(&first.config).unwrap(),
            serde_json::to_value(&second.config).unwrap()
        );
        assert_eq!(first.headers, second.headers);
        assert!(Arc::ptr_eq(
            first.engine_provider.as_ref().unwrap(),
            &engines
        ));
        assert!(Arc::ptr_eq(
            second.engine_provider.as_ref().unwrap(),
            &engines
        ));
        assert!(original.config.is_none());
        assert!(original.engine_provider.is_none());
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
    async fn missing_measurements_or_engine_provider_fail_before_any_request() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let matcher = loopback_attested_matcher(
            &format!("http://{}", listener.local_addr().unwrap()),
            integrity_provider(),
        )
        .unwrap()
        .with_headers(headers())
        .unwrap();
        for matcher in [
            matcher.with_engine_provider(engine_provider()),
            matcher.with_measurements(measurements()).unwrap(),
        ] {
            assert!(matches!(
                matcher.perform_match(request()).await,
                Err(FlamingoError::Configuration(_))
            ));
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(50), listener.accept())
                .await
                .is_err(),
            "no connection may be opened without measurements and an Engine Provider"
        );
    }

    #[tokio::test]
    async fn signs_each_connection_with_fresh_parameters() {
        let integrity = integrity_provider();
        let mut previous_input = None;
        for _ in 0..2 {
            let (base_url, seen) =
                serve_once(|socket| async move { drop(socket) }).await;
            let matcher = loopback_attested_matcher(&base_url, integrity.clone())
                .unwrap()
                .with_measurements(measurements())
                .unwrap()
                .with_engine_provider(engine_provider());
            assert!(matches!(
                matcher.perform_match(request()).await,
                Err(FlamingoError::Transport { .. })
            ));
            let upgrade = seen.await.unwrap();
            let signature_input = upgrade.headers()["signature-input"].clone();
            assert_ne!(previous_input.as_ref(), Some(&signature_input));
            previous_input = Some(signature_input);
            assert_eq!(upgrade.headers()["integrity-token"], "test-integrity-token");
            assert!(upgrade.headers().contains_key("signature"));
        }
        assert_eq!(integrity.prepared.load(Ordering::Relaxed), 2);
        assert_eq!(integrity.signer.0.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn integrity_failure_is_typed_and_does_not_invoke_signer() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let integrity = Arc::new(TestIntegrityProvider {
            prepared: AtomicUsize::new(0),
            signer: Arc::new(TestDigestSigner(AtomicUsize::new(0))),
            failure: Some(RequestIntegrityError::Unavailable),
        });
        let matcher = loopback_attested_matcher(
            &format!("http://{}", listener.local_addr().unwrap()),
            integrity.clone(),
        )
        .unwrap()
        .with_measurements(measurements())
        .unwrap()
        .with_engine_provider(engine_provider());
        assert!(matches!(
            matcher.perform_match(request()).await,
            Err(FlamingoError::RequestIntegrity(
                RequestIntegrityError::Unavailable
            ))
        ));
        assert_eq!(integrity.signer.0.load(Ordering::Relaxed), 0);
        assert!(
            tokio::time::timeout(Duration::from_millis(50), listener.accept())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn upgrade_carries_configured_headers_to_the_prefixed_route() {
        let (base_url, seen) = serve_once(|socket| async move { drop(socket) }).await;
        let matcher = loopback_attested_matcher(
            &format!("{base_url}/v1/flamingo/?region=eu%2Fwest&region=us"),
            integrity_provider(),
        )
        .unwrap()
        .with_measurements(measurements())
        .unwrap()
        .with_engine_provider(engine_provider())
        .with_headers(headers())
        .unwrap();

        // The stub closes right after the upgrade, so the session fails before any assignment.
        assert!(matches!(
            matcher.perform_match(request()).await,
            Err(FlamingoError::Transport { .. })
        ));

        let upgrade = seen.await.unwrap();
        assert_eq!(upgrade.uri().path(), "/v1/flamingo/v1/matches");
        assert_eq!(upgrade.uri().query(), Some("region=eu%2Fwest&region=us"));
        assert_eq!(upgrade.headers()["authorization"], "Bearer test-token");
        assert_eq!(upgrade.headers()["client-name"], "test-client");
        assert_eq!(upgrade.headers().get_all("host").iter().count(), 1);
        for name in ["integrity-token", "signature-input", "signature"] {
            assert_eq!(upgrade.headers().get_all(name).iter().count(), 1);
        }
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
            let assignment = format!(
                r#"{{"type":"assignment","attestation":"hEBAQEA=","public_key":"a2V5","release_hashes":["{}"]}}"#,
                hex::encode(ENGINE_HASH)
            );
            socket.send(Message::Text(assignment.into())).await.unwrap();
            let mut binary = 0;
            while let Some(Ok(frame)) = socket.next().await {
                binary += usize::from(frame.is_binary());
            }
            let _ = sent.send(binary);
        })
        .await;
        let matcher = loopback_attested_matcher(&base_url, integrity_provider())
            .unwrap()
            .with_measurements(measurements())
            .unwrap()
            .with_engine_provider(engine_provider())
            .with_headers(headers())
            .unwrap();

        let error = matcher.perform_match(request()).await.unwrap_err();

        assert!(matches!(error, FlamingoError::Channel { .. }));
        drop(matcher);
        assert_eq!(frames.await.unwrap(), 0, "no image frame may be sent");
    }

    #[tokio::test]
    async fn runs_the_first_offered_configuration_the_verifier_loaded() {
        let client = FakeClient::new([Ok(verified(DebugReport::NotProduced))]);
        let (_, release_hash) = provider();

        let outcome = perform_match(&client, &engines(), request())
            .await
            .expect("match should succeed");

        let FlamingoMatchOutcome::Matched {
            token,
            configuration,
            ..
        } = outcome
        else {
            panic!("expected a matched outcome");
        };
        assert_eq!(token.as_bytes(), b"signed-token");
        assert_eq!(token.signing_key_attestation(), b"signing-key-attestation");
        assert_eq!(configuration.release_hash, release_hash);
        assert_eq!(configuration.match_strictness, 2);
        assert_eq!(client.sent(), [(1, 2, provider().1)]);
    }

    #[tokio::test]
    async fn sends_nothing_when_the_verifier_loaded_no_offered_engine() {
        let client = FakeClient::with_loaded_releases(
            vec![[0x44; 32]],
            [Ok(verified(DebugReport::NotProduced))],
        );

        let error = perform_match(&client, &engines(), request())
            .await
            .expect_err("no offered engine is loaded");

        assert!(matches!(error, FlamingoError::NoSupportedEngine));
        assert_eq!(client.assignments.load(Ordering::Relaxed), 1);
        assert!(client.sent().is_empty(), "no entry may be sent");
    }

    #[tokio::test]
    async fn invalid_requests_fail_before_assignment() {
        let client = FakeClient::new([]);
        let mut request = request();
        request.compare = vec![0, 3];

        let error = perform_match(&client, &engines(), request)
            .await
            .expect_err("compare names a missing entry");

        assert!(matches!(error, FlamingoError::InvalidInput { .. }));
        assert_eq!(client.assignments.load(Ordering::Relaxed), 0);
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

        let outcome = perform_match(&client, &engines(), request())
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
        assert_eq!(client.sent().len(), 2);
    }

    #[tokio::test]
    async fn reassignment_selects_and_binds_the_new_release() {
        use super::engine::tests::{jwk, manifest, metadata};
        let (a, release_a) = manifest(ENGINE_HASH, 4, "release-1");
        let (b, release_b) = manifest(ENGINE_HASH, 2, "release-1");
        let provider = FlamingoEngineProvider::from_metadata(&metadata(
            &[(&a, "active"), (&b, "active")],
            &[jwk("release-1", "active")],
        ))
        .unwrap();
        let mut client = FakeClient::with_loaded_releases(
            vec![release_a],
            [
                Err(ClientError::ReassignRequired),
                Ok(verified(DebugReport::NotProduced)),
            ],
        );
        client.reassigned_releases = Some(vec![release_b]);
        let mut request = request_for(release_b);
        request.offered_configurations[0].release_hash = release_a.to_vec();
        let outcome = perform_match(&client, &provider, request).await.unwrap();
        assert_eq!(client.sent(), [(1, 1, release_a), (1, 2, release_b)]);
        assert!(
            matches!(outcome, FlamingoMatchOutcome::Matched { configuration, .. }
            if configuration.release_hash == release_b)
        );
    }

    #[tokio::test]
    async fn does_not_retry_a_second_stale_assignment() {
        let client = FakeClient::new([
            Err(ClientError::ReassignRequired),
            Err(ClientError::ReassignRequired),
        ]);

        let error = perform_match(&client, &engines(), request())
            .await
            .expect_err("a second stale assignment should be surfaced");

        assert!(matches!(error, FlamingoError::ReassignmentRequired));
        assert_eq!(client.assignments.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn reports_survive_success_and_rejection() {
        for debug_report in [
            DebugReport::Available {
                json: "{ \"raw\": [1, 2] }\n".to_owned(),
            },
            DebugReport::NotProduced,
            DebugReport::OmittedTooLarge {
                original_size_bytes: 200_000,
            },
        ] {
            for rejected in [false, true] {
                let result = if rejected {
                    MatchResult::Failed {
                        reason: FailureReason::Internal,
                        debug_report: debug_report.clone(),
                    }
                } else {
                    verified(debug_report.clone())
                };
                let client = FakeClient::new([Ok(result)]);

                let report = match perform_match(&client, &engines(), request())
                    .await
                    .unwrap()
                {
                    FlamingoMatchOutcome::Matched { debug_report, .. } => {
                        assert!(!rejected);
                        debug_report
                    }
                    FlamingoMatchOutcome::Rejected { debug_report, .. } => {
                        assert!(rejected);
                        debug_report
                    }
                };
                assert_eq!(report, debug_report.clone().into());
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
            let error = perform_match(&client, &engines(), request())
                .await
                .unwrap_err();
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
            let error = perform_match(&client, &engines(), request())
                .await
                .unwrap_err();
            assert_eq!(
                std::mem::discriminant(&error),
                std::mem::discriminant(&expected)
            );
            assert_eq!(client.assignments.load(Ordering::Relaxed), 1);
        }
    }
}
