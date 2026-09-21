use flamingo_verifier_sealed_types::{
    ComparisonRole, FailureReason, ImageFailureReason, ImageRole,
};
use thiserror::Error;

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
    /// An image was empty.
    EmptyImage,
    /// An image or total input exceeded the limit.
    InputTooLarge,
    /// The backend does not implement this capture variant.
    UnsupportedCapture,
    /// The backend does not implement this operation.
    UnsupportedOperation,
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
    },
    /// The verifier configuration was not valid.
    #[error("invalid Flamingo verifier configuration: {0}")]
    Configuration(String),
    /// Assignment, attestation, transport, channel opening, or token verification failed.
    #[error("Flamingo verifier request failed: {0}")]
    Verifier(String),
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
            FailureReason::UnsupportedOperation => Self::UnsupportedOperation,
            FailureReason::Internal => Self::Internal,
            FailureReason::MatchBelowThreshold(comparison) => {
                Self::MatchBelowThreshold {
                    comparison: comparison.into(),
                }
            }
            FailureReason::MatchingFailed(comparison) => Self::MatchingFailed {
                comparison: comparison.into(),
            },
            FailureReason::ImageRejected { image, reason } => Self::ImageRejected {
                image: image.into(),
                reason: reason.into(),
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
