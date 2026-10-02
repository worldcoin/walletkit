use flamingo_verifier_sealed_types::{
    ComparisonRole, FailureReason, ImageFailureReason, ImageRole, InputFailureReason,
    ValidationTarget,
};
use thiserror::Error;

use super::RequestIntegrityError;

/// A rejection reported inside encryption; not a signed statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FlamingoMatchRejection {
    /// Malformed encrypted request.
    MalformedInputs,
    /// Invalid PCP hashes file.
    InvalidHashesJson,
    /// Orb image did not match its PCP commitment.
    ThumbnailHashMismatch,
    /// Threshold was not a finite normalized cosine value.
    InvalidThreshold,
    /// Exact malformed-input reason and the location/limit supplied by the service.
    InputRejected {
        /// Failed constraint.
        reason: FlamingoInputFailureReason,
        /// Semantic image role, if supplied.
        image: Option<FlamingoImageRole>,
        /// Size limit, when supplied.
        limit_bytes: Option<u64>,
    },
    /// A comparison did not meet the threshold.
    MatchBelowThreshold {
        /// The comparison that failed.
        comparison: FlamingoComparison,
    },
    /// A named image could not pass analysis.
    ImageRejected {
        /// Image bytes or semantic image role.
        image: FlamingoImageRole,
        /// Approved validation reason.
        reason: FlamingoImageFailureReason,
        /// Frame/pair target, if the failure came from validation.
        target: Option<FlamingoValidationTarget>,
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
        /// Stable constraint code; applications need not parse the message.
        kind: FlamingoInputFailureKind,
        /// Byte limit when applicable.
        limit_bytes: Option<u64>,
    },
    /// The verifier configuration was not valid.
    #[error("invalid Flamingo verifier configuration: {0}")]
    Configuration(String),
    /// Preparing the integrity token or signing the request failed.
    #[error("Flamingo request integrity failed: {0}")]
    RequestIntegrity(RequestIntegrityError),
    /// The host returned a machine-readable service error.
    #[error("Flamingo service error ({code})")]
    Service {
        /// Exact host code.
        code: String,
        /// Host retry hint, not an automatic retry policy.
        allow_retry: bool,
    },
    /// Configured exchange deadline expired.
    #[error("Flamingo request timed out")]
    Timeout,
    /// Connection closed, handshake or network I/O failed.
    #[error("Flamingo transport failed: {details}")]
    Transport {
        /// Supplementary diagnostic text.
        details: String,
    },
    /// Assignment, host message or decrypted result was malformed.
    #[error("invalid Flamingo response at {stage:?}")]
    InvalidResponse {
        /// Protocol stage.
        stage: FlamingoResponseStage,
    },
    /// Signing-key attestation did not verify.
    #[error("Flamingo attestation failed: {details}")]
    Attestation {
        /// Supplementary diagnostic text.
        details: String,
    },
    /// Channel attestation, binding, sealing or opening failed.
    #[error("Flamingo channel failed: {details}")]
    Channel {
        /// Supplementary diagnostic text.
        details: String,
    },
    /// Attested signing key was invalid.
    #[error("invalid Flamingo signing key")]
    InvalidSigningKey,
    /// Token signature or request commitments did not verify.
    #[error("invalid Flamingo match statement")]
    StatementInvalid,
    /// The one internal reassignment retry was exhausted.
    #[error("Flamingo reassignment retry exhausted")]
    ReassignmentRequired,
}

impl From<FailureReason> for FlamingoMatchRejection {
    fn from(value: FailureReason) -> Self {
        match value {
            FailureReason::MalformedInputs => Self::MalformedInputs,
            FailureReason::InvalidHashesJson => Self::InvalidHashesJson,
            FailureReason::ThumbnailHashMismatch => Self::ThumbnailHashMismatch,
            FailureReason::InvalidThreshold => Self::InvalidThreshold,
            FailureReason::InputRejected {
                reason,
                image,
                limit_bytes,
            } => Self::InputRejected {
                reason: reason.into(),
                image: image.map(Into::into),
                limit_bytes,
            },
            FailureReason::Internal => Self::Internal,
            FailureReason::MatchBelowThreshold(comparison) => {
                Self::MatchBelowThreshold {
                    comparison: comparison.into(),
                }
            }
            FailureReason::MatchingFailed(comparison) => Self::MatchingFailed {
                comparison: comparison.into(),
            },
            FailureReason::ImageRejected {
                image,
                reason,
                target,
            } => Self::ImageRejected {
                image: image.into(),
                reason: reason.into(),
                target: target.map(Into::into),
            },
        }
    }
}
impl From<ComparisonRole> for FlamingoComparison {
    fn from(value: ComparisonRole) -> Self {
        match value {
            ComparisonRole::OrbSelfie => Self::OrbSelfie,
            ComparisonRole::OrbChallenge => Self::OrbChallenge,
            ComparisonRole::SelfieChallenge => Self::SelfieChallenge,
        }
    }
}
impl From<ImageRole> for FlamingoImageRole {
    fn from(value: ImageRole) -> Self {
        match value {
            ImageRole::OrbCredential => Self::OrbCredential,
            ImageRole::LiveSelfie => Self::LiveSelfie,
            ImageRole::RtmsChallenge => Self::RtmsChallenge,
        }
    }
}
/// Image rejection reasons, without raw engine diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FlamingoImageFailureReason {
    /// Image decoding or dimension validation failed.
    InvalidImage,
    /// Embedding generation failed.
    TemplateFailed,
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
impl From<ImageFailureReason> for FlamingoImageFailureReason {
    fn from(value: ImageFailureReason) -> Self {
        match value {
            ImageFailureReason::InvalidImage => Self::InvalidImage,
            ImageFailureReason::TemplateFailed => Self::TemplateFailed,
            ImageFailureReason::TooManyFaces => Self::TooManyFaces,
            ImageFailureReason::ImageTooDark => Self::ImageTooDark,
            ImageFailureReason::ImageTooBright => Self::ImageTooBright,
            ImageFailureReason::IlluminationVariance => Self::IlluminationVariance,
            ImageFailureReason::FaceTooSmall => Self::FaceTooSmall,
            ImageFailureReason::FaceTooBig => Self::FaceTooBig,
            ImageFailureReason::FaceResolutionTooLow => Self::FaceResolutionTooLow,
            ImageFailureReason::FaceTooHigh => Self::FaceTooHigh,
            ImageFailureReason::FaceTooLow => Self::FaceTooLow,
            ImageFailureReason::FaceTooFarLeft => Self::FaceTooFarLeft,
            ImageFailureReason::FaceTooFarRight => Self::FaceTooFarRight,
            ImageFailureReason::HeadPoseYaw => Self::HeadPoseYaw,
            ImageFailureReason::HeadPosePitchTooHigh => Self::HeadPosePitchTooHigh,
            ImageFailureReason::HeadPosePitchTooLow => Self::HeadPosePitchTooLow,
            ImageFailureReason::HeadPoseRoll => Self::HeadPoseRoll,
            ImageFailureReason::LowQuality => Self::LowQuality,
            ImageFailureReason::SunglassesOcclusionDetected => {
                Self::SunglassesOcclusionDetected
            }
            ImageFailureReason::GlassesOcclusionDetected => {
                Self::GlassesOcclusionDetected
            }
            ImageFailureReason::MaskOcclusionDetected => Self::MaskOcclusionDetected,
            ImageFailureReason::OtherOcclusionDetected => Self::OtherOcclusionDetected,
            ImageFailureReason::HairOcclusionDetected => Self::HairOcclusionDetected,
            ImageFailureReason::FasOcclusionDetected => Self::FasOcclusionDetected,
            ImageFailureReason::SpoofDetected => Self::SpoofDetected,
            ImageFailureReason::DepthSpoofDetected => Self::DepthSpoofDetected,
            ImageFailureReason::ThermalSpoofDetected => Self::ThermalSpoofDetected,
            ImageFailureReason::AgeBelowThreshold => Self::AgeBelowThreshold,
            ImageFailureReason::NoFaceDetected => Self::NoFaceDetected,
            ImageFailureReason::EyesClosed => Self::EyesClosed,
            ImageFailureReason::NonNeutralExpression => Self::NonNeutralExpression,
            ImageFailureReason::LandmarksAlignment => Self::LandmarksAlignment,
            ImageFailureReason::FaceOverexposed => Self::FaceOverexposed,
            ImageFailureReason::FaceUnderexposed => Self::FaceUnderexposed,
            ImageFailureReason::SegmentationOcclusionProportion => {
                Self::SegmentationOcclusionProportion
            }
            ImageFailureReason::BrightArtifacts => Self::BrightArtifacts,
            ImageFailureReason::LightGuardScoreTooLow => Self::LightGuardScoreTooLow,
            ImageFailureReason::LowContrast => Self::LowContrast,
            ImageFailureReason::MeshExpressionScore => Self::MeshExpressionScore,
            ImageFailureReason::HighColorDistortion => Self::HighColorDistortion,
            ImageFailureReason::UnevenLighting => Self::UnevenLighting,
            ImageFailureReason::BlurryFace => Self::BlurryFace,
            ImageFailureReason::NoisyThermalImage => Self::NoisyThermalImage,
        }
    }
}

/// Capture validation targets exported to mobile callers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FlamingoValidationTarget {
    /// A single image.
    Image,
    /// The illuminated frame.
    IlluminatedFrame,
    /// The unilluminated frame.
    UnilluminatedFrame,
    /// The complete challenge-response pair.
    LightGuardPair,
}
impl From<ValidationTarget> for FlamingoValidationTarget {
    fn from(value: ValidationTarget) -> Self {
        match value {
            ValidationTarget::Image => Self::Image,
            ValidationTarget::IlluminatedFrame => Self::IlluminatedFrame,
            ValidationTarget::UnilluminatedFrame => Self::UnilluminatedFrame,
            ValidationTarget::LightGuardPair => Self::LightGuardPair,
        }
    }
}

/// Worker input constraints exported to mobile callers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FlamingoInputFailureReason {
    /// A required image is missing.
    MissingImage,
    /// A capture source is missing.
    MissingSource,
    /// The selected matching frame is invalid.
    InvalidMatchingFrame,
    /// An image buffer is empty.
    EmptyImage,
    /// One image exceeded its size limit.
    ImageTooLarge,
    /// All image bytes exceeded the combined limit.
    TotalImagesTooLarge,
}
impl From<InputFailureReason> for FlamingoInputFailureReason {
    fn from(value: InputFailureReason) -> Self {
        match value {
            InputFailureReason::MissingImage => Self::MissingImage,
            InputFailureReason::MissingSource => Self::MissingSource,
            InputFailureReason::InvalidMatchingFrame => Self::InvalidMatchingFrame,
            InputFailureReason::EmptyImage => Self::EmptyImage,
            InputFailureReason::ImageTooLarge => Self::ImageTooLarge,
            InputFailureReason::TotalImagesTooLarge => Self::TotalImagesTooLarge,
        }
    }
}

/// Local input constraints exported to mobile callers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FlamingoInputFailureKind {
    /// The field is empty.
    Empty,
    /// The field exceeded its size limit.
    TooLarge,
    /// The images exceeded the combined limit.
    TotalTooLarge,
    /// The threshold is nonfinite or outside `[0, 1]`.
    InvalidThreshold,
}

/// Response stages exported to mobile callers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FlamingoResponseStage {
    /// The assignment document or public key.
    Assignment,
    /// A host protocol message.
    HostMessage,
    /// The decrypted match response.
    MatchResult,
}
