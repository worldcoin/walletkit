//! Attested `Flamingo` matching in preparation for zero-knowledge proof generation.
//!
//! This module deliberately knows nothing about Orb PCP storage. Its caller supplies the live
//! image and the credential material obtained through the platform's Oxide/OrbKit adapter. The
//! module owns assignment, attestation verification, sealing, transport, response opening, and
//! match-token verification.

use std::{sync::Arc, time::SystemTime};

use async_trait::async_trait;
use attested_channel::{channel::CHANNEL_VERSION, nitro::PcrMeasurement};
use flamingo_verifier_client::{
    ClientError, Config, FaceVerifierClient, VerifiedAssignment,
};
use flamingo_verifier_protocol::messages::{FailureReason, MatchInputs, MatchResult};
use thiserror::Error;

// TODO: Replace all three PCRs with measurements from the approved enclave release.
// TODO: These should likely originate from one of the flamingo crates
const EXPECTED_ENCLAVE_PCR0: [u8; 48] = [0x42; 48];
const EXPECTED_ENCLAVE_PCR1: [u8; 48] = [0x43; 48];
const EXPECTED_ENCLAVE_PCR2: [u8; 48] = [0x44; 48];

/// `WalletKit`'s attested `Flamingo` match module.
///
/// Keep this value alive across requests so the underlying HTTP client can retain transport state.
/// No WalletKit-owned sealing key is persisted: each verified assignment supplies the enclave's
/// attested public key, and the client creates fresh HPKE sealing material for the request.
#[derive(Debug, uniffi::Object)]
pub struct FlamingoMatcher {
    client: FaceVerifierClient,
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

/// A match token whose sealed response, signing-key attestation, and signature were verified.
///
/// Foreign callers receive an opaque handle. The token and signing-key attestation remain
/// together in Rust for proof generation and eventual relay of the attestation to the RP.
#[derive(Debug, uniffi::Object)]
pub struct VerifiedMatchToken {
    token: Vec<u8>,
    signing_key_attestation: Vec<u8>,
}

/// The verified outcome of the TEE match phase.
#[derive(Debug, uniffi::Enum)]
pub enum FlamingoMatchOutcome {
    /// The enclave issued a token and `WalletKit` verified it against an attested signing key.
    Matched(Arc<VerifiedMatchToken>),
    /// The enclave opened the request but declined to issue a token.
    Rejected(FlamingoMatchRejection),
}

/// A sealed match rejection returned by the attested enclave.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FlamingoMatchRejection {
    /// The sealed inputs were malformed.
    MalformedInputs,
    /// The channel version was not supported by the enclave.
    UnsupportedVersion,
    /// The PCP hashes file was invalid or did not contain the thumbnail commitment.
    InvalidHashesJson,
    /// The credential image did not match the PCP thumbnail commitment.
    ThumbnailHashMismatch,
    /// At least one comparison scored below the requested threshold.
    MatchBelowThreshold,
    /// The enclave could not obtain a usable comparison score from the images.
    ImageAnalysisFailed,
}

/// Failures before `WalletKit` obtains an authoritative sealed match outcome.
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

    async fn request_assignment(
        &self,
        now: SystemTime,
    ) -> Result<Self::Assignment, ClientError>;

    async fn request_match(
        &self,
        assignment: &Self::Assignment,
        inputs: &MatchInputs,
        now: SystemTime,
    ) -> Result<MatchResult, ClientError>;
}

#[uniffi::export(async_runtime = "tokio")]
impl FlamingoMatcher {
    /// Builds a matcher for a TEE host using `WalletKit`'s pinned enclave measurements.
    ///
    /// PCR0, PCR1, and PCR2 are placeholders that must be replaced before real matches can succeed.
    /// Rust callers can supply custom pins through [`Self::with_measurements`].
    ///
    /// # Errors
    ///
    /// Returns [`FlamingoError::Configuration`] when the configuration is invalid, or
    /// [`FlamingoError::Verifier`] when the HTTP client cannot be constructed.
    #[uniffi::constructor]
    pub fn new(host_url: &str) -> Result<Self, FlamingoError> {
        Self::with_measurements(host_url, None)
    }

    /// Performs the attested TEE match phase.
    ///
    /// A stale assignment is retried exactly once with a fresh assignment and freshly sealed
    /// ciphertext. A sealed rejection is an authoritative outcome, not a transport failure.
    ///
    /// # Errors
    ///
    /// Returns [`FlamingoError::InvalidInput`] before making a network request when a caller value
    /// is unusable. Other failures are returned as [`FlamingoError::Verifier`].
    pub async fn perform_match(
        &self,
        request: FlamingoMatchRequest,
    ) -> Result<FlamingoMatchOutcome, FlamingoError> {
        perform_match(&self.client, request, SystemTime::now).await
    }
}

impl FlamingoMatcher {
    /// Returns the hardcoded PCR0/1/2 measurements used when no override is supplied.
    #[must_use]
    pub const fn default_measurements() -> [[u8; 48]; 3] {
        [
            EXPECTED_ENCLAVE_PCR0,
            EXPECTED_ENCLAVE_PCR1,
            EXPECTED_ENCLAVE_PCR2,
        ]
    }

    /// Builds a matcher with custom PCR0/1/2 measurements, or the hardcoded defaults.
    ///
    /// Supply measurements from a trusted enclave build. `None` uses the same pins as
    /// [`Self::new`]. All three measurements must be nonzero; debug enclaves are rejected.
    ///
    /// # Errors
    /// Returns an error if a measurement is zero or the host/client configuration is invalid.
    pub fn with_measurements(
        host_url: &str,
        measurements: Option<[[u8; 48]; 3]>,
    ) -> Result<Self, FlamingoError> {
        let config = matcher_config(host_url, measurements)?;
        let client = FaceVerifierClient::new(config)
            .map_err(|error| FlamingoError::Verifier(error.to_string()))?;
        Ok(Self { client })
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
            version: CHANNEL_VERSION,
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
            FailureReason::UnsupportedVersion => Self::UnsupportedVersion,
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

    async fn request_assignment(
        &self,
        now: SystemTime,
    ) -> Result<Self::Assignment, ClientError> {
        self.request_assignment(now).await
    }

    async fn request_match(
        &self,
        assignment: &Self::Assignment,
        inputs: &MatchInputs,
        now: SystemTime,
    ) -> Result<MatchResult, ClientError> {
        self.request_match(assignment, inputs, now).await
    }
}

fn matcher_config(
    host_url: &str,
    measurements: Option<[[u8; 48]; 3]>,
) -> Result<Config, FlamingoError> {
    let measurements =
        measurements.unwrap_or_else(FlamingoMatcher::default_measurements);
    for (index, measurement) in measurements.iter().enumerate() {
        if measurement.iter().all(|byte| *byte == 0) {
            return Err(FlamingoError::Configuration(format!(
                "PCR{index} must be nonzero; debug enclaves are not accepted"
            )));
        }
    }
    Config::new(
        host_url,
        vec![vec![
            PcrMeasurement::new(0, measurements[0]),
            PcrMeasurement::new(1, measurements[1]),
            PcrMeasurement::new(2, measurements[2]),
        ]],
    )
    .map_err(|error| FlamingoError::Configuration(error.to_string()))
}

async fn perform_match<C: MatchClient, F: Fn() -> SystemTime>(
    client: &C,
    request: FlamingoMatchRequest,
    now: F,
) -> Result<FlamingoMatchOutcome, FlamingoError> {
    request.validate()?;
    let request = request.into_inputs();
    let mut reassigned = false;

    loop {
        let assignment = client
            .request_assignment(now())
            .await
            .map_err(|error| verifier_error(&error))?;

        match client.request_match(&assignment, &request, now()).await {
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
        collections::VecDeque,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Mutex,
        },
        time::SystemTime,
    };

    use flamingo_verifier_client::ClientError;
    use flamingo_verifier_protocol::{
        match_token::MatchToken,
        messages::{AttestedStatement, FailureReason, MatchInputs, MatchResult},
    };

    use super::{
        perform_match, FlamingoError, FlamingoMatchOutcome, FlamingoMatchRejection,
        FlamingoMatchRequest, MatchClient,
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

        async fn request_assignment(
            &self,
            _now: SystemTime,
        ) -> Result<Self::Assignment, ClientError> {
            Ok(self.assignments.fetch_add(1, Ordering::Relaxed))
        }

        async fn request_match(
            &self,
            _assignment: &Self::Assignment,
            _inputs: &MatchInputs,
            _now: SystemTime,
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

    #[test]
    fn custom_measurements_replace_all_default_pins() {
        let measurements = [[1; 48], [2; 48], [3; 48]];
        let config =
            super::matcher_config("https://verifier.example.com", Some(measurements))
                .unwrap();
        let json = serde_json::to_value(config).unwrap();
        assert_eq!(json["allowed_pcr_configs"].as_array().unwrap().len(), 1);
        for (index, measurement) in measurements.iter().enumerate() {
            assert_eq!(json["allowed_pcr_configs"][0][index]["index"], index);
            assert_eq!(
                json["allowed_pcr_configs"][0][index]["value"],
                hex::encode(measurement)
            );
        }
        assert_eq!(json["allow_debug_measurements"], false);
    }

    #[test]
    fn rejects_zero_custom_measurements() {
        for index in 0..3 {
            let mut measurements = [[1; 48], [2; 48], [3; 48]];
            measurements[index] = [0; 48];
            assert!(matches!(
                super::FlamingoMatcher::with_measurements(
                    "https://verifier.example.com",
                    Some(measurements)
                ),
                Err(FlamingoError::Configuration(_))
            ));
        }
    }

    #[test]
    fn rejects_an_invalid_host_url() {
        assert!(matches!(
            super::FlamingoMatcher::new("not a URL"),
            Err(FlamingoError::Configuration(_))
        ));
    }

    #[tokio::test]
    async fn returns_a_verified_token_after_the_client_verifies_success() {
        let client = FakeClient::new([Ok(MatchResult::Success(AttestedStatement {
            token: MatchToken::from_bytes(b"signed-token".to_vec()),
            signing_key_attestation: b"signing-key-attestation".to_vec(),
        }))]);

        let outcome = perform_match(&client, request(), || SystemTime::UNIX_EPOCH)
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

        let outcome = perform_match(&client, request(), || SystemTime::UNIX_EPOCH)
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

        let outcome = perform_match(&client, request(), || SystemTime::UNIX_EPOCH)
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

        let error = perform_match(&client, request(), || SystemTime::UNIX_EPOCH)
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

        let error = perform_match(&client, request, || SystemTime::UNIX_EPOCH)
            .await
            .expect_err(
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
