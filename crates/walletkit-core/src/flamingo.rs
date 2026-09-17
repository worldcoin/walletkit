//! Attested `Flamingo` matching in preparation for zero-knowledge proof generation.
//!
//! This module deliberately knows nothing about Orb PCP storage. Its caller supplies the live
//! image and the credential material obtained through the platform's Oxide/OrbKit adapter. The
//! module owns assignment, attestation verification, sealing, transport, response opening, and
//! match-token verification.

use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;
use flamingo_verifier_client::{
    Config, Error as ClientError, FlamingoVerifierClient, PcrMeasurement,
    VerifiedAssignment, VerifiedMatchResult as MatchResult,
};
use flamingo_verifier_protocol::match_token::MatchClaims;
use flamingo_verifier_sealed_types::{
    DeepFaceInputs, FailureReason, GrayBadgeInputs, LiveCapture, MatchInputs,
};
use reqwest::{
    Url,
    header::{COOKIE, HeaderMap, HeaderName, HeaderValue},
};
use thiserror::Error;
use tokio::sync::OnceCell;

/// A simple wrapper around of `FlamingoVerifierClient`. Flamingo Verifier is a cloud TEE service for attested embedding generation and comparison.
#[derive(Debug, uniffi::Object)]
pub struct FlamingoMatcher {
    host_url: Url,
    config: Option<Config>,
    headers: HeaderMap,
    client: OnceCell<FlamingoVerifierClient>,
}

/// Explicit operation-specific inputs. Image buffers move into the client without cloning.
#[derive(uniffi::Enum)]
pub enum FlamingoMatchRequest {
    /// Three-way matching with the exact original Orb PCP hashes.json.
    DeepFace {
        /// Exact encoded Orb thumbnail bytes.
        orb_credential: Vec<u8>,
        /// Explicit live capture variant.
        live: FlamingoLiveCapture,
        /// Exact encoded RTMS challenge bytes.
        rtms_challenge: Vec<u8>,
        /// Original PCP hashes.json bytes.
        hashes_json: Vec<u8>,
        /// Minimum raw cosine similarity in [-1, 1].
        match_threshold: f64,
    },
    /// Live/challenge matching without credential fields.
    GrayBadge {
        /// Explicit live capture variant.
        live: FlamingoLiveCapture,
        /// Exact encoded RTMS challenge bytes.
        rtms_challenge: Vec<u8>,
        /// Minimum raw cosine similarity in [-1, 1].
        match_threshold: f64,
    },
}

/// A single image or an explicitly selected `LightGuard` pair.
#[derive(uniffi::Enum)]
pub enum FlamingoLiveCapture {
    /// Vanilla selfie bytes.
    Vanilla {
        /// Encoded vanilla selfie bytes.
        image: Vec<u8>,
    },
    /// Both `LightGuard` frames; rejected explicitly by backends without `LightGuard`.
    LightGuard {
        /// Illuminated frame bytes.
        illuminated: Vec<u8>,
        /// Unilluminated frame bytes.
        unilluminated: Vec<u8>,
        /// Frame used for matching.
        matching_frame: FlamingoMatchingFrame,
    },
}

/// Which `LightGuard` frame provides the matching embedding.
#[derive(Debug, Clone, Copy, uniffi::Enum)]
pub enum FlamingoMatchingFrame {
    /// Use the illuminated frame.
    Illuminated,
    /// Use the unilluminated frame.
    Unilluminated,
}

/// Already verified raw cosine scores. No second signature verification is needed.
#[derive(Debug, Clone, uniffi::Enum)]
pub enum FlamingoScores {
    /// Three-way Orb/live/challenge scores.
    DeepFace {
        /// Orb versus selfie raw cosine.
        similarity_orb_selfie: f64,
        /// Orb versus challenge raw cosine.
        similarity_orb_challenge: f64,
        /// Selfie versus challenge raw cosine.
        similarity_selfie_challenge: f64,
    },
    /// Live/challenge score.
    GrayBadge {
        /// Selfie versus challenge raw cosine.
        similarity_selfie_challenge: f64,
    },
}

/// A match token whose signing-key attestation and signature were verified.
///
/// Foreign callers receive an opaque handle. The token and signing-key attestation remain
/// together in Rust for proof generation and eventual relay of the attestation to the RP.
#[derive(Debug, uniffi::Object)]
pub struct VerifiedMatchToken {
    token: Vec<u8>,
    claims: MatchClaims,
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

/// A rejection reported inside encryption; not a signed statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FlamingoMatchRejection {
    /// Malformed encrypted request.
    MalformedInputs,
    /// Invalid PCP hashes file.
    InvalidHashesJson,
    /// Orb image did not match its PCP commitment.
    ThumbnailHashMismatch,
    /// Threshold was not a finite raw cosine value.
    InvalidThreshold,
    /// An image was empty.
    EmptyImage,
    /// An image or total input exceeded the limit.
    InputTooLarge,
    /// The backend does not implement this capture variant.
    UnsupportedCapture,
    /// A comparison did not meet the threshold.
    MatchBelowThreshold {
        /// The comparison that failed.
        comparison: FlamingoComparison,
    },
    /// A named image could not pass analysis.
    ImageAnalysisFailed {
        /// Image bytes or semantic image role.
        image: FlamingoImageRole,
        /// Approved validation reason.
        reason: FlamingoAnalysisFailure,
    },
    /// A named comparison failed.
    MatchingFailed {
        /// The comparison that failed.
        comparison: FlamingoComparison,
    },
    /// An infrastructure failure, not a biological rejection.
    Internal,
}
/// Comparison names match the worker protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FlamingoComparison {
    /// Orb credential versus live selfie.
    OrbSelfie,
    /// Orb credential versus RTMS challenge.
    OrbChallenge,
    /// Live selfie versus RTMS challenge.
    SelfieChallenge,
}
/// Image roles match the worker protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FlamingoImageRole {
    /// Orb credential image.
    OrbCredential,
    /// Live capture.
    LiveSelfie,
    /// RTMS challenge image.
    RtmsChallenge,
}
/// Approved analysis reasons, without raw engine diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FlamingoAnalysisFailure {
    /// Image decoding or dimension validation failed.
    InvalidImage,
    /// No face was detected.
    NoFaceDetected,
    /// A typed image validation rejected the input.
    ValidationFailed {
        /// Approved validation reason.
        reason: FlamingoValidationReason,
        /// Image, frame or pair that failed.
        target: FlamingoValidationTarget,
    },
    /// Embedding generation failed.
    TemplateFailed,
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
    /// Returns [`FlamingoError::Configuration`] if no measurement is set.
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

impl FlamingoMatchRequest {
    fn into_inputs(self) -> MatchInputs {
        match self {
            Self::DeepFace {
                orb_credential,
                live,
                rtms_challenge,
                hashes_json,
                match_threshold,
            } => MatchInputs::DeepFace(DeepFaceInputs {
                orb_credential: orb_credential.into(),
                live: live.into(),
                rtms_challenge: rtms_challenge.into(),
                hashes_json: hashes_json.into(),
                match_threshold,
            }),
            Self::GrayBadge {
                live,
                rtms_challenge,
                match_threshold,
            } => MatchInputs::GrayBadge(GrayBadgeInputs {
                live: live.into(),
                rtms_challenge: rtms_challenge.into(),
                match_threshold,
            }),
        }
    }
}
impl From<FlamingoLiveCapture> for LiveCapture {
    fn from(value: FlamingoLiveCapture) -> Self {
        match value {
            FlamingoLiveCapture::Vanilla { image } => Self::Vanilla(image.into()),
            FlamingoLiveCapture::LightGuard { illuminated, unilluminated, matching_frame } => Self::LightGuard {
                illuminated: illuminated.into(), unilluminated: unilluminated.into(),
                matching_frame: match matching_frame {
                    FlamingoMatchingFrame::Illuminated => flamingo_verifier_sealed_types::LightGuardMatchingFrame::Illuminated,
                    FlamingoMatchingFrame::Unilluminated => flamingo_verifier_sealed_types::LightGuardMatchingFrame::Unilluminated,
                },
            },
        }
    }
}

#[uniffi::export]
impl VerifiedMatchToken {
    /// Read scores already verified by the Flamingo client.
    #[must_use]
    pub const fn scores(&self) -> FlamingoScores {
        match &self.claims {
            MatchClaims::DeepFace { scores, .. } => FlamingoScores::DeepFace {
                similarity_orb_selfie: scores.similarity_orb_selfie,
                similarity_orb_challenge: scores.similarity_orb_challenge,
                similarity_selfie_challenge: scores.similarity_selfie_challenge,
            },
            MatchClaims::GrayBadge { scores, .. } => FlamingoScores::GrayBadge {
                similarity_selfie_challenge: scores.similarity_selfie_challenge,
            },
        }
    }
    /// Threshold authenticated by the token.
    #[must_use]
    pub const fn match_threshold(&self) -> f64 {
        self.claims.context().match_threshold
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
            FailureReason::InvalidThreshold => Self::InvalidThreshold,
            FailureReason::EmptyImage => Self::EmptyImage,
            FailureReason::InputTooLarge => Self::InputTooLarge,
            FailureReason::UnsupportedCapture => Self::UnsupportedCapture,
            FailureReason::Internal => Self::Internal,
            FailureReason::MatchBelowThreshold(comparison) => {
                Self::MatchBelowThreshold {
                    comparison: comparison.into(),
                }
            }
            FailureReason::MatchingFailed(comparison) => Self::MatchingFailed {
                comparison: comparison.into(),
            },
            FailureReason::ImageAnalysisFailed { image, reason } => {
                Self::ImageAnalysisFailed {
                    image: image.into(),
                    reason: reason.into(),
                }
            }
        }
    }
}
macro_rules! map_variants {
    ($source:ident, $target:ident, $($variant:ident),+) => {
        impl From<flamingo_verifier_sealed_types::$source> for $target {
            fn from(value: flamingo_verifier_sealed_types::$source) -> Self {
                match value { $(flamingo_verifier_sealed_types::$source::$variant => Self::$variant),+ }
            }
        }
    };
}
map_variants!(
    ComparisonRole,
    FlamingoComparison,
    OrbSelfie,
    OrbChallenge,
    SelfieChallenge
);
map_variants!(
    ImageRole,
    FlamingoImageRole,
    OrbCredential,
    LiveSelfie,
    RtmsChallenge
);
impl From<flamingo_verifier_sealed_types::AnalysisFailure> for FlamingoAnalysisFailure {
    fn from(value: flamingo_verifier_sealed_types::AnalysisFailure) -> Self {
        use flamingo_verifier_sealed_types::AnalysisFailure;
        match value {
            AnalysisFailure::InvalidImage => Self::InvalidImage,
            AnalysisFailure::NoFaceDetected => Self::NoFaceDetected,
            AnalysisFailure::TemplateFailed => Self::TemplateFailed,
            AnalysisFailure::ValidationFailed(failure) => Self::ValidationFailed {
                reason: failure.reason.into(),
                target: failure.target.into(),
            },
        }
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
    let request = request.into_inputs();
    request
        .validate()
        .map_err(|reason| FlamingoError::InvalidInput {
            attribute: if reason == FailureReason::InvalidThreshold {
                "match_threshold"
            } else {
                "request"
            }
            .to_string(),
            reason: format!("{reason:?}"),
        })?;
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
                        token: statement.statement.token.into_bytes(),
                        signing_key_attestation: statement
                            .statement
                            .signing_key_attestation,
                        claims: statement.claims,
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

/// Approved face validation `ValidationReason`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FlamingoValidationReason {
    /// Too many faces.
    TooManyFaces,
    /// Image too dark.
    ImageTooDark,
    /// Image too bright.
    ImageTooBright,
    /// Illumination variance.
    IlluminationVariance,
    /// Face too small.
    FaceTooSmall,
    /// Face too big.
    FaceTooBig,
    /// Face resolution too low.
    FaceResolutionTooLow,
    /// Face too high.
    FaceTooHigh,
    /// Face too low.
    FaceTooLow,
    /// Face too far left.
    FaceTooFarLeft,
    /// Face too far right.
    FaceTooFarRight,
    /// Head pose yaw.
    HeadPoseYaw,
    /// Head pose pitch too high.
    HeadPosePitchTooHigh,
    /// Head pose pitch too low.
    HeadPosePitchTooLow,
    /// Head pose roll.
    HeadPoseRoll,
    /// Low quality.
    LowQuality,
    /// Sunglasses occlusion detected.
    SunglassesOcclusionDetected,
    /// Glasses occlusion detected.
    GlassesOcclusionDetected,
    /// Mask occlusion detected.
    MaskOcclusionDetected,
    /// Other occlusion detected.
    OtherOcclusionDetected,
    /// Hair occlusion detected.
    HairOcclusionDetected,
    /// Fas occlusion detected.
    FasOcclusionDetected,
    /// Spoof detected.
    SpoofDetected,
    /// Depth spoof detected.
    DepthSpoofDetected,
    /// Thermal spoof detected.
    ThermalSpoofDetected,
    /// Age below threshold.
    AgeBelowThreshold,
    /// No face detected.
    NoFaceDetected,
    /// Eyes closed.
    EyesClosed,
    /// Non neutral expression.
    NonNeutralExpression,
    /// Landmarks alignment.
    LandmarksAlignment,
    /// Face overexposed.
    FaceOverexposed,
    /// Face underexposed.
    FaceUnderexposed,
    /// Segmentation occlusion proportion.
    SegmentationOcclusionProportion,
    /// Bright artifacts.
    BrightArtifacts,
    /// Light guard score too low.
    LightGuardScoreTooLow,
    /// Low contrast.
    LowContrast,
    /// Mesh expression score.
    MeshExpressionScore,
    /// High color distortion.
    HighColorDistortion,
    /// Uneven lighting.
    UnevenLighting,
    /// Blurry face.
    BlurryFace,
    /// Noisy thermal image.
    NoisyThermalImage,
}
map_variants!(
    ValidationReason,
    FlamingoValidationReason,
    TooManyFaces,
    ImageTooDark,
    ImageTooBright,
    IlluminationVariance,
    FaceTooSmall,
    FaceTooBig,
    FaceResolutionTooLow,
    FaceTooHigh,
    FaceTooLow,
    FaceTooFarLeft,
    FaceTooFarRight,
    HeadPoseYaw,
    HeadPosePitchTooHigh,
    HeadPosePitchTooLow,
    HeadPoseRoll,
    LowQuality,
    SunglassesOcclusionDetected,
    GlassesOcclusionDetected,
    MaskOcclusionDetected,
    OtherOcclusionDetected,
    HairOcclusionDetected,
    FasOcclusionDetected,
    SpoofDetected,
    DepthSpoofDetected,
    ThermalSpoofDetected,
    AgeBelowThreshold,
    NoFaceDetected,
    EyesClosed,
    NonNeutralExpression,
    LandmarksAlignment,
    FaceOverexposed,
    FaceUnderexposed,
    SegmentationOcclusionProportion,
    BrightArtifacts,
    LightGuardScoreTooLow,
    LowContrast,
    MeshExpressionScore,
    HighColorDistortion,
    UnevenLighting,
    BlurryFace,
    NoisyThermalImage
);

/// Approved face validation `ValidationTarget`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FlamingoValidationTarget {
    /// Image location.
    Image,
    /// `IlluminatedFrame` location.
    IlluminatedFrame,
    /// `UnilluminatedFrame` location.
    UnilluminatedFrame,
    /// `LightGuardPair` location.
    LightGuardPair,
}
map_variants!(
    ValidationTarget,
    FlamingoValidationTarget,
    Image,
    IlluminatedFrame,
    UnilluminatedFrame,
    LightGuardPair
);

#[cfg(test)]
mod tests {
    use std::{
        collections::{HashMap, VecDeque},
        sync::{
            Mutex,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use flamingo_verifier_client::{
        Error as ClientError, VerifiedMatch, VerifiedMatchResult as MatchResult,
    };
    use flamingo_verifier_protocol::match_token::MatchToken;
    use flamingo_verifier_sealed_types::{
        AttestedStatement, FailureReason, MatchInputs,
    };

    use super::{
        FlamingoError, FlamingoLiveCapture, FlamingoMatchOutcome,
        FlamingoMatchRejection, FlamingoMatchRequest, FlamingoMatcher, MatchClient,
        perform_match,
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

    #[test]
    fn gray_badge_has_no_pcp_and_moves_image_buffers() {
        let image = vec![1; 1024];
        let pointer = image.as_ptr();
        let request = FlamingoMatchRequest::GrayBadge {
            live: FlamingoLiveCapture::Vanilla { image },
            rtms_challenge: vec![2; 512],
            match_threshold: -0.5,
        }
        .into_inputs();
        request.validate().unwrap();
        let encoded = request.to_cbor().unwrap();
        assert!(matches!(
            MatchInputs::from_cbor(&encoded),
            Ok(MatchInputs::GrayBadge(_))
        ));
        let MatchInputs::GrayBadge(inputs) = request else {
            unreachable!()
        };
        let flamingo_verifier_sealed_types::LiveCapture::Vanilla(image) = inputs.live
        else {
            unreachable!()
        };
        assert_eq!(image.as_ptr(), pointer);
    }
    #[tokio::test]
    async fn gray_badge_preserves_typed_validation_feedback() {
        use flamingo_verifier_sealed_types::{
            AnalysisFailure, ImageRole, ValidationFailure, ValidationReason,
            ValidationTarget,
        };
        let client = FakeClient::new([Ok(MatchResult::Failed(
            FailureReason::ImageAnalysisFailed {
                image: ImageRole::LiveSelfie,
                reason: AnalysisFailure::ValidationFailed(ValidationFailure {
                    reason: ValidationReason::EyesClosed,
                    target: ValidationTarget::Image,
                }),
            },
        ))]);
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
            FlamingoMatchOutcome::Rejected(
                FlamingoMatchRejection::ImageAnalysisFailed {
                    image: super::FlamingoImageRole::LiveSelfie,
                    reason: super::FlamingoAnalysisFailure::ValidationFailed {
                        reason: super::FlamingoValidationReason::EyesClosed,
                        target: super::FlamingoValidationTarget::Image
                    },
                }
            )
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
        let client = FakeClient::new([Ok(MatchResult::Success(Box::new(VerifiedMatch { statement: AttestedStatement {
            token: MatchToken::from_bytes(b"signed-token".to_vec()),
            signing_key_attestation: b"signing-key-attestation".to_vec(),
        }, claims: flamingo_verifier_protocol::match_token::MatchClaims::GrayBadge {
            context: flamingo_verifier_protocol::match_token::MatchContext {
                live: flamingo_verifier_protocol::match_token::CaptureCommitment::Vanilla([0;32]), rtms_challenge: [0;32], match_threshold: 0.7,
            }, scores: flamingo_verifier_protocol::match_token::GrayBadgeScores { similarity_selfie_challenge: 0.9 },
        } })))]);

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
