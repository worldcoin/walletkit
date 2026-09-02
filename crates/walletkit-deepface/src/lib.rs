#![cfg_attr(target_arch = "wasm32", allow(missing_docs))]
#![cfg(not(target_arch = "wasm32"))]

//! Attested `DeepFace` matching in preparation for zero-knowledge proof generation.
//!
//! This module deliberately knows nothing about Orb PCP storage. Its caller supplies the live
//! image and the credential material obtained through the platform's Oxide/OrbKit adapter. The
//! module owns assignment, attestation verification, sealing, transport, response opening, and
//! match-token verification.

use std::time::SystemTime;

use async_trait::async_trait;
use attested_channel::channel::CHANNEL_VERSION;
use deepface_client::{ClientError, Config, FaceVerifierClient, VerifiedAssignment};
use deepface_protocol::messages::{FailureReason, MatchInputs, MatchResult};
use thiserror::Error;
use zeroize::Zeroize;

/// Inputs for one attested `DeepFace` match.
///
/// `credential_image` and `hashes_json` must come from the same enrolled Orb PCP. In particular,
/// `hashes_json` must contain the exact archive bytes, not parsed and reserialized JSON.
#[derive(Debug)]
pub struct DeepFaceMatchRequest {
    /// Raw liveness image bytes captured for this request.
    pub live_image: Vec<u8>,
    /// Raw `thumbnail.png` bytes decrypted from the enrolled Orb PCP.
    pub credential_image: Vec<u8>,
    /// Exact raw `hashes.json` bytes extracted from the enrolled Orb PCP.
    pub hashes_json: Vec<u8>,
    /// Opaque identifier used by the TEE host to locate the RP's encrypted challenge image.
    pub challenge_image_id: String,
    /// AES-256-GCM key supplied by the RP for the challenge image.
    pub challenge_image_key: [u8; 32],
    /// AES-256-GCM nonce supplied by the RP for the challenge image.
    pub challenge_image_iv: [u8; 12],
    /// Minimum similarity required by the RP. Must be finite and between zero and one.
    pub match_threshold: f32,
}

impl DeepFaceMatchRequest {
    fn validate(&self) -> Result<(), DeepFaceError> {
        for (attribute, bytes) in [
            ("live_image", self.live_image.as_slice()),
            ("credential_image", self.credential_image.as_slice()),
            ("hashes_json", self.hashes_json.as_slice()),
        ] {
            if bytes.is_empty() {
                return Err(DeepFaceError::InvalidInput {
                    attribute,
                    reason: "must not be empty".to_string(),
                });
            }
        }

        if self.challenge_image_id.trim().is_empty() {
            return Err(DeepFaceError::InvalidInput {
                attribute: "challenge_image_id",
                reason: "must not be empty".to_string(),
            });
        }

        if !self.match_threshold.is_finite()
            || !(0.0..=1.0).contains(&self.match_threshold)
        {
            return Err(DeepFaceError::InvalidInput {
                attribute: "match_threshold",
                reason: "must be finite and between 0 and 1 inclusive".to_string(),
            });
        }

        Ok(())
    }

    fn into_sensitive_inputs(mut self) -> SensitiveMatchInputs {
        SensitiveMatchInputs {
            challenge_image_id: std::mem::take(&mut self.challenge_image_id),
            inputs: MatchInputs {
                version: CHANNEL_VERSION,
                live_image: std::mem::take(&mut self.live_image),
                credential_image: std::mem::take(&mut self.credential_image),
                hashes_json: std::mem::take(&mut self.hashes_json),
                challenge_image_key: std::mem::take(&mut self.challenge_image_key),
                challenge_image_iv: std::mem::take(&mut self.challenge_image_iv),
                match_threshold: self.match_threshold,
            },
        }
    }
}

impl Drop for DeepFaceMatchRequest {
    fn drop(&mut self) {
        self.live_image.zeroize();
        self.credential_image.zeroize();
        self.hashes_json.zeroize();
        self.challenge_image_key.zeroize();
        self.challenge_image_iv.zeroize();
    }
}

/// A match token whose sealed response, signing-key attestation, and signature were verified.
///
/// This is the internal handoff to `DeepFace` proof generation. It is intentionally not a
/// `UniFFI` type: the foreign side should eventually receive only the generated `DeepFace` proof.
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
pub enum DeepFaceMatchRejection {
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
    /// The RP's challenge image could not be authenticated with the supplied key and nonce.
    ChallengeDecryptFailed,
}

impl From<FailureReason> for DeepFaceMatchRejection {
    fn from(value: FailureReason) -> Self {
        match value {
            FailureReason::MalformedInputs => Self::MalformedInputs,
            FailureReason::UnsupportedVersion => Self::UnsupportedVersion,
            FailureReason::InvalidHashesJson => Self::InvalidHashesJson,
            FailureReason::ThumbnailHashMismatch => Self::ThumbnailHashMismatch,
            FailureReason::MatchBelowThreshold => Self::MatchBelowThreshold,
            FailureReason::ImageAnalysisFailed => Self::ImageAnalysisFailed,
            FailureReason::ChallengeDecryptFailed => Self::ChallengeDecryptFailed,
        }
    }
}

/// The verified outcome of the TEE match phase.
#[derive(Debug)]
pub enum DeepFaceMatchOutcome {
    /// The enclave issued a token and `WalletKit` verified it against an attested signing key.
    Matched(VerifiedMatchToken),
    /// The enclave opened the request but declined to issue a token.
    Rejected(DeepFaceMatchRejection),
}

/// Failures before `WalletKit` obtains an authoritative sealed match outcome.
#[derive(Debug, Error)]
pub enum DeepFaceError {
    /// A caller-supplied value cannot form a valid match request.
    #[error("invalid {attribute}: {reason}")]
    InvalidInput {
        /// Name of the invalid field.
        attribute: &'static str,
        /// Why the value was rejected.
        reason: String,
    },
    /// The verifier configuration was not valid.
    #[error("invalid DeepFace verifier configuration: {0}")]
    Configuration(String),
    /// Assignment, attestation, transport, channel opening, or token verification failed.
    #[error("DeepFace verifier request failed: {0}")]
    Verifier(String),
}

/// `WalletKit`'s attested `DeepFace` match module.
///
/// Keep this value alive across requests so the underlying HTTP client can retain transport state.
/// No WalletKit-owned sealing key is persisted: each verified assignment supplies the enclave's
/// attested public key, and the client creates fresh HPKE sealing material for the request.
#[derive(Debug)]
pub struct DeepFaceMatcher {
    client: FaceVerifierClient,
}

impl DeepFaceMatcher {
    /// Builds a matcher from the embedding verifier's JSON configuration.
    ///
    /// The configuration pins the accepted Nitro PCR measurement sets and the TEE host URL.
    ///
    /// # Errors
    ///
    /// Returns [`DeepFaceError::Configuration`] when the configuration is invalid, or
    /// [`DeepFaceError::Verifier`] when the HTTP client cannot be constructed.
    pub fn from_config_json(config_json: &str) -> Result<Self, DeepFaceError> {
        let config = Config::from_json(config_json)
            .map_err(|error| DeepFaceError::Configuration(error.to_string()))?;
        let client = FaceVerifierClient::new(config)
            .map_err(|error| DeepFaceError::Verifier(error.to_string()))?;

        Ok(Self { client })
    }

    /// Performs the attested TEE match phase.
    ///
    /// A stale assignment is retried exactly once with a fresh assignment and freshly sealed
    /// ciphertext. A sealed rejection is an authoritative outcome, not a transport failure.
    ///
    /// # Errors
    ///
    /// Returns [`DeepFaceError::InvalidInput`] before making a network request when a caller value
    /// is unusable. Other failures are returned as [`DeepFaceError::Verifier`].
    pub async fn perform_match(
        &self,
        request: DeepFaceMatchRequest,
    ) -> Result<DeepFaceMatchOutcome, DeepFaceError> {
        // TODO(DEEPFACE): consume `VerifiedMatchToken` in the DeepFace proof generator and expose
        // only the generated proof across the foreign-language seam.
        perform_match(&self.client, request, SystemTime::now).await
    }
}

struct SensitiveMatchInputs {
    challenge_image_id: String,
    inputs: MatchInputs,
}

impl Drop for SensitiveMatchInputs {
    fn drop(&mut self) {
        self.inputs.live_image.zeroize();
        self.inputs.credential_image.zeroize();
        self.inputs.hashes_json.zeroize();
        self.inputs.challenge_image_key.zeroize();
        self.inputs.challenge_image_iv.zeroize();
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
        challenge_image_id: &str,
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
        challenge_image_id: &str,
        now: SystemTime,
    ) -> Result<MatchResult, ClientError> {
        Self::request_match(self, assignment, inputs, challenge_image_id, now).await
    }
}

async fn perform_match<C: MatchClient, F: Fn() -> SystemTime>(
    client: &C,
    request: DeepFaceMatchRequest,
    now: F,
) -> Result<DeepFaceMatchOutcome, DeepFaceError> {
    request.validate()?;
    let request = request.into_sensitive_inputs();
    let mut reassigned = false;

    loop {
        let assignment = client
            .request_assignment(now())
            .await
            .map_err(|error| verifier_error(&error))?;

        match client
            .request_match(
                &assignment,
                &request.inputs,
                &request.challenge_image_id,
                now(),
            )
            .await
        {
            Ok(MatchResult::Success(token)) => {
                return Ok(DeepFaceMatchOutcome::Matched(VerifiedMatchToken(
                    token.into_bytes(),
                )));
            }
            Ok(MatchResult::Failed(reason)) => {
                return Ok(DeepFaceMatchOutcome::Rejected(reason.into()));
            }
            Err(ClientError::ReassignRequired) if !reassigned => reassigned = true,
            Err(error) => return Err(verifier_error(&error)),
        }
    }
}

fn verifier_error(error: &ClientError) -> DeepFaceError {
    DeepFaceError::Verifier(error.to_string())
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

    use deepface_client::ClientError;
    use deepface_protocol::{
        match_token::MatchToken,
        messages::{FailureReason, MatchInputs, MatchResult},
    };

    use super::{
        perform_match, DeepFaceError, DeepFaceMatchOutcome, DeepFaceMatchRejection,
        DeepFaceMatchRequest, MatchClient,
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
            _challenge_image_id: &str,
            _now: SystemTime,
        ) -> Result<MatchResult, ClientError> {
            self.results
                .lock()
                .expect("fake result lock should not be poisoned")
                .pop_front()
                .expect("test should provide one result per request")
        }
    }

    fn request() -> DeepFaceMatchRequest {
        DeepFaceMatchRequest {
            live_image: b"live".to_vec(),
            credential_image: b"credential".to_vec(),
            hashes_json: br#"{"thumbnail.png":"00"}"#.to_vec(),
            challenge_image_id: "challenge-id".to_string(),
            challenge_image_key: [7; 32],
            challenge_image_iv: [9; 12],
            match_threshold: 0.7,
        }
    }

    #[tokio::test]
    async fn returns_a_verified_token_after_the_client_verifies_success() {
        let client = FakeClient::new([Ok(MatchResult::Success(
            MatchToken::from_bytes(b"signed-token".to_vec()),
        ))]);

        let outcome = perform_match(&client, request(), || SystemTime::UNIX_EPOCH)
            .await
            .expect("match should succeed");

        let DeepFaceMatchOutcome::Matched(token) = outcome else {
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
            DeepFaceMatchOutcome::Rejected(
                DeepFaceMatchRejection::ThumbnailHashMismatch
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
            DeepFaceMatchOutcome::Rejected(DeepFaceMatchRejection::MatchBelowThreshold)
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

        assert!(matches!(error, DeepFaceError::Verifier(_)));
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
            DeepFaceError::InvalidInput {
                attribute: "match_threshold",
                ..
            }
        ));
        assert_eq!(client.assignments.load(Ordering::Relaxed), 0);
    }
}
