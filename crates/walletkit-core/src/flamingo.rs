//! Attested `Flamingo` matching in preparation for zero-knowledge proof generation.
//!
//! This module deliberately knows nothing about Orb PCP storage. Its caller supplies the live
//! image and the credential material obtained through the platform's Oxide/OrbKit adapter. The
//! module owns assignment, attestation verification, sealing, transport, response opening, and
//! match-token verification.

use std::time::SystemTime;

use async_trait::async_trait;
use attested_channel::channel::CHANNEL_VERSION;
use flamingo_verifier_client::{
    ClientError, Config, FaceVerifierClient, VerifiedAssignment,
};
use flamingo_verifier_protocol::messages::{FailureReason, MatchInputs, MatchResult};
use thiserror::Error;
use zeroize::Zeroize;

/// Inputs for one attested `Flamingo` match.
///
/// `credential_image` and `hashes_json` must come from the same enrolled Orb PCP. In particular,
/// `hashes_json` must contain the exact archive bytes, not parsed and reserialized JSON.
#[derive(Debug)]
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

impl FlamingoMatchRequest {
    fn validate(&self) -> Result<(), FlamingoError> {
        for (attribute, bytes) in [
            ("live_image", self.live_image.as_slice()),
            ("credential_image", self.credential_image.as_slice()),
            ("hashes_json", self.hashes_json.as_slice()),
        ] {
            if bytes.is_empty() {
                return Err(FlamingoError::InvalidInput {
                    attribute,
                    reason: "must not be empty".to_string(),
                });
            }
        }

        if self.challenge_image.is_empty() {
            return Err(FlamingoError::InvalidInput {
                attribute: "challenge_image",
                reason: "must not be empty".to_string(),
            });
        }

        if self.light_guard_image.as_ref().is_some_and(Vec::is_empty) {
            return Err(FlamingoError::InvalidInput {
                attribute: "light_guard_image",
                reason: "must not be empty when provided".to_string(),
            });
        }

        if !self.match_threshold.is_finite()
            || !(0.0..=1.0).contains(&self.match_threshold)
        {
            return Err(FlamingoError::InvalidInput {
                attribute: "match_threshold",
                reason: "must be finite and between 0 and 1 inclusive".to_string(),
            });
        }

        Ok(())
    }

    fn into_sensitive_inputs(mut self) -> SensitiveMatchInputs {
        SensitiveMatchInputs {
            inputs: MatchInputs {
                version: CHANNEL_VERSION,
                live_image: std::mem::take(&mut self.live_image),
                credential_image: std::mem::take(&mut self.credential_image),
                light_guard_image: std::mem::take(&mut self.light_guard_image),
                hashes_json: std::mem::take(&mut self.hashes_json),
                challenge_image: std::mem::take(&mut self.challenge_image),
                match_threshold: self.match_threshold,
            },
        }
    }
}

impl Drop for FlamingoMatchRequest {
    fn drop(&mut self) {
        self.live_image.zeroize();
        self.credential_image.zeroize();
        self.hashes_json.zeroize();
        self.light_guard_image.zeroize();
        self.challenge_image.zeroize();
    }
}

/// A match token whose sealed response, signing-key attestation, and signature were verified.
///
/// This is the internal handoff to `Flamingo` proof generation. It is intentionally not a
/// `UniFFI` type: the foreign side should eventually receive only the generated `Flamingo` proof.
#[derive(Debug)]
pub struct VerifiedMatchToken(Vec<u8>);

impl VerifiedMatchToken {
    /// Borrows the encoded COSE/CBOR token for proof generation.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for VerifiedMatchToken {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// A sealed match rejection returned by the attested enclave.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

/// The verified outcome of the TEE match phase.
#[derive(Debug)]
pub enum FlamingoMatchOutcome {
    /// The enclave issued a token and `WalletKit` verified it against an attested signing key.
    Matched(VerifiedMatchToken),
    /// The enclave opened the request but declined to issue a token.
    Rejected(FlamingoMatchRejection),
}

/// Failures before `WalletKit` obtains an authoritative sealed match outcome.
#[derive(Debug, Error)]
pub enum FlamingoError {
    /// A caller-supplied value cannot form a valid match request.
    #[error("invalid {attribute}: {reason}")]
    InvalidInput {
        /// Name of the invalid field.
        attribute: &'static str,
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

/// `WalletKit`'s attested `Flamingo` match module.
///
/// Keep this value alive across requests so the underlying HTTP client can retain transport state.
/// No WalletKit-owned sealing key is persisted: each verified assignment supplies the enclave's
/// attested public key, and the client creates fresh HPKE sealing material for the request.
#[derive(Debug)]
pub struct FlamingoMatcher {
    client: FaceVerifierClient,
}

impl FlamingoMatcher {
    /// Builds a matcher from the embedding verifier's JSON configuration.
    ///
    /// The configuration pins the accepted Nitro PCR measurement sets and the TEE host URL.
    ///
    /// # Errors
    ///
    /// Returns [`FlamingoError::Configuration`] when the configuration is invalid, or
    /// [`FlamingoError::Verifier`] when the HTTP client cannot be constructed.
    pub fn from_config_json(config_json: &str) -> Result<Self, FlamingoError> {
        let config = Config::from_json(config_json)
            .map_err(|error| FlamingoError::Configuration(error.to_string()))?;
        let client = FaceVerifierClient::new(config)
            .map_err(|error| FlamingoError::Verifier(error.to_string()))?;

        Ok(Self { client })
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

struct SensitiveMatchInputs {
    inputs: MatchInputs,
}

impl Drop for SensitiveMatchInputs {
    fn drop(&mut self) {
        self.inputs.live_image.zeroize();
        self.inputs.credential_image.zeroize();
        self.inputs.light_guard_image.zeroize();
        self.inputs.hashes_json.zeroize();
        self.inputs.challenge_image.zeroize();
    }
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

#[async_trait]
impl MatchClient for FaceVerifierClient {
    type Assignment = VerifiedAssignment;

    async fn request_assignment(
        &self,
        now: SystemTime,
    ) -> Result<Self::Assignment, ClientError> {
        Self::request_assignment(self, now).await
    }

    async fn request_match(
        &self,
        assignment: &Self::Assignment,
        inputs: &MatchInputs,
        now: SystemTime,
    ) -> Result<MatchResult, ClientError> {
        Self::request_match(self, assignment, inputs, now).await
    }
}

async fn perform_match<C: MatchClient, F: Fn() -> SystemTime>(
    client: &C,
    request: FlamingoMatchRequest,
    now: F,
) -> Result<FlamingoMatchOutcome, FlamingoError> {
    request.validate()?;
    let request = request.into_sensitive_inputs();
    let mut reassigned = false;

    loop {
        let assignment = client
            .request_assignment(now())
            .await
            .map_err(|error| verifier_error(&error))?;

        match client
            .request_match(&assignment, &request.inputs, now())
            .await
        {
            Ok(MatchResult::Success(statement)) => {
                return Ok(FlamingoMatchOutcome::Matched(VerifiedMatchToken(
                    statement.token.into_bytes(),
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

    #[tokio::test]
    async fn returns_a_verified_token_after_the_client_verifies_success() {
        let client = FakeClient::new([Ok(MatchResult::Success(AttestedStatement {
            token: MatchToken::from_bytes(b"signed-token".to_vec()),
            signing_key_attestation: Vec::new(),
        }))]);

        let outcome = perform_match(&client, request(), || SystemTime::UNIX_EPOCH)
            .await
            .expect("match should succeed");

        let FlamingoMatchOutcome::Matched(token) = outcome else {
            panic!("expected a matched outcome");
        };
        assert_eq!(token.as_bytes(), b"signed-token");
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
                attribute: "match_threshold",
                ..
            }
        ));
        assert_eq!(client.assignments.load(Ordering::Relaxed), 0);
    }
}
