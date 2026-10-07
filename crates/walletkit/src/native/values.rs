//! Binary encodings of `WalletKit` domain values. The numbers here are the wire format:
//! enumeration ordinals and variant indices must never be reused or renumbered.

use super::{
    codec::{Decode, Element, Encode, Reader, Writer},
    error::{NativeError, Result},
};
use walletkit_core::{
    authenticator::{
        GatewayRequestStatus, RecoveryData, RecoveryUpdateSignature, RegistrationStatus,
    },
    error::WalletKitError,
    flamingo::{
        FlamingoComparison, FlamingoDebugReport, FlamingoError,
        FlamingoImageFailureReason, FlamingoImageRole, FlamingoInputFailureKind,
        FlamingoInputFailureReason, FlamingoLiveCapture, FlamingoMatchOutcome,
        FlamingoMatchRejection, FlamingoMatchRequest, FlamingoMatchingFrame,
        FlamingoResponseStage, FlamingoValidationTarget, RequestIntegrityError,
        RequestIntegrityPlatform,
    },
    logger::LogLevel,
    proof_request_credential_constraints_check::{
        CredentialConstraintsCheckError, CredentialConstraintsCheckItem,
        CredentialConstraintsCheckResult,
    },
    storage::{
        types::{
            ActivityEntry, ActivityFailureReason, ActivityOutcome, CredentialRecord,
            ProtocolVersion,
        },
        StorageError,
    },
    Environment, Region,
};

/// Builds a `Uint256` from 32 big-endian bytes.
pub const fn uint256(bytes: [u8; 32]) -> walletkit_core::Uint256 {
    walletkit_core::Uint256(ruint::aliases::U256::from_be_bytes(bytes))
}

/// A fieldless enumeration crossing as its ordinal: a JNI `int`, a C integer, or a `u8`
/// in the binary encoding.
pub trait Ordinal: Sized {
    /// The frozen ordinal of `self`.
    fn ordinal(&self) -> u8;
    /// The value for `ordinal`, if any.
    fn from_ordinal(ordinal: i64) -> Option<Self>;
}

macro_rules! ordinals {
    ($($(#[$meta:meta])* $ty:ty { $($index:literal => $variant:ident),* $(,)? })*) => {$(
        $(#[$meta])*
        impl Ordinal for $ty {
            fn ordinal(&self) -> u8 {
                match self {
                    $(Self::$variant => $index,)*
                }
            }

            fn from_ordinal(ordinal: i64) -> Option<Self> {
                match ordinal {
                    $($index => Some(Self::$variant),)*
                    _ => None,
                }
            }
        }

        $(#[$meta])*
        impl Encode for $ty {
            fn encode(self, writer: &mut Writer) -> Result<()> {
                writer.u8(self.ordinal());
                Ok(())
            }
        }

        $(#[$meta])*
        impl Decode for $ty {
            fn decode(reader: &mut Reader<'_>) -> Result<Self> {
                Self::from_ordinal(reader.tag()?.into()).ok_or_else(NativeError::invalid_input)
            }
        }
    )*};
}

ordinals! {
    LogLevel { 0 => Trace, 1 => Debug, 2 => Info, 3 => Warn, 4 => Error }
    Environment { 0 => Staging, 1 => Production }
    Region { 0 => Us, 1 => Eu, 2 => Ap }
    #[cfg(feature = "v3")]
    walletkit_core::v3::CredentialType { 0 => Orb, 1 => Document, 2 => SecureDocument, 3 => Device }
    ProtocolVersion { 0 => V3, 1 => V4 }
    ActivityOutcome { 0 => Completed, 1 => Declined, 2 => Cancelled, 3 => Failed, 4 => Incomplete }
    ActivityFailureReason {
        0 => NetworkError, 1 => Timeout, 2 => DeviceAuthenticationFailed,
        3 => ProofGenerationFailed, 4 => RelyingPartyRejected,
    }
    FlamingoMatchingFrame { 0 => Illuminated, 1 => Unilluminated }
    FlamingoComparison { 0 => OrbSelfie, 1 => OrbChallenge, 2 => SelfieChallenge }
    FlamingoImageRole { 0 => OrbCredential, 1 => LiveSelfie, 2 => RtmsChallenge }
    FlamingoImageFailureReason {
        0 => InvalidImage, 1 => TemplateFailed, 2 => TooManyFaces, 3 => ImageTooDark,
        4 => ImageTooBright, 5 => IlluminationVariance, 6 => FaceTooSmall, 7 => FaceTooBig,
        8 => FaceResolutionTooLow, 9 => FaceTooHigh, 10 => FaceTooLow, 11 => FaceTooFarLeft,
        12 => FaceTooFarRight, 13 => HeadPoseYaw, 14 => HeadPosePitchTooHigh,
        15 => HeadPosePitchTooLow, 16 => HeadPoseRoll, 17 => LowQuality,
        18 => SunglassesOcclusionDetected, 19 => GlassesOcclusionDetected,
        20 => MaskOcclusionDetected, 21 => OtherOcclusionDetected,
        22 => HairOcclusionDetected, 23 => FasOcclusionDetected, 24 => SpoofDetected,
        25 => DepthSpoofDetected, 26 => ThermalSpoofDetected, 27 => AgeBelowThreshold,
        28 => NoFaceDetected, 29 => EyesClosed, 30 => NonNeutralExpression,
        31 => LandmarksAlignment, 32 => FaceOverexposed, 33 => FaceUnderexposed,
        34 => SegmentationOcclusionProportion, 35 => BrightArtifacts,
        36 => LightGuardScoreTooLow, 37 => LowContrast, 38 => MeshExpressionScore,
        39 => HighColorDistortion, 40 => UnevenLighting, 41 => BlurryFace,
        42 => NoisyThermalImage,
    }
    FlamingoValidationTarget {
        0 => Image, 1 => IlluminatedFrame, 2 => UnilluminatedFrame, 3 => LightGuardPair,
    }
    FlamingoInputFailureReason {
        0 => MissingImage, 1 => MissingSource, 2 => InvalidMatchingFrame, 3 => EmptyImage,
        4 => ImageTooLarge, 5 => TotalImagesTooLarge,
    }
    FlamingoInputFailureKind { 0 => Empty, 1 => TooLarge, 2 => TotalTooLarge, 3 => InvalidThreshold }
    FlamingoResponseStage { 0 => Assignment, 1 => HostMessage, 2 => MatchResult }
    RequestIntegrityPlatform { 0 => Ios, 1 => Android }
    RequestIntegrityError {
        0 => Unavailable, 1 => InvalidSession, 2 => SigningFailed, 3 => CallbackFailed,
        4 => TimedOut,
    }
}

impl Element for CredentialConstraintsCheckItem {}
impl Element for CredentialRecord {}
impl Element for ActivityEntry {}

impl Encode for CredentialConstraintsCheckResult {
    fn encode(self, writer: &mut Writer) -> Result<()> {
        writer.bool(self.is_satisfied);
        self.check_results.encode(writer)
    }
}

impl Encode for CredentialConstraintsCheckItem {
    fn encode(self, writer: &mut Writer) -> Result<()> {
        writer.string(&self.identifier)?;
        writer.u64(self.issuer_schema_id);
        writer.bool(self.has_credential);
        Ok(())
    }
}

impl Encode for CredentialRecord {
    fn encode(self, writer: &mut Writer) -> Result<()> {
        writer.u64(self.credential_id);
        writer.u64(self.issuer_schema_id);
        writer.u64(self.genesis_issued_at);
        writer.u64(self.expires_at);
        writer.bool(self.is_expired);
        Ok(())
    }
}

impl Encode for ActivityEntry {
    fn encode(self, writer: &mut Writer) -> Result<()> {
        self.id.encode(writer)?;
        writer.u64(self.rp_id);
        writer.string(&self.app_identifier)?;
        writer.string(&self.client_id)?;
        self.protocol.encode(writer)?;
        self.timestamp.encode(writer)?;
        self.outcome.encode(writer)?;
        self.issuer_schema_ids.encode(writer)?;
        self.failure_reason.encode(writer)
    }
}

impl Decode for ActivityEntry {
    fn decode(reader: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            id: Decode::decode(reader)?,
            rp_id: reader.u64()?,
            app_identifier: reader.string()?,
            client_id: reader.string()?,
            protocol: Decode::decode(reader)?,
            timestamp: Decode::decode(reader)?,
            outcome: Decode::decode(reader)?,
            issuer_schema_ids: Decode::decode(reader)?,
            failure_reason: Decode::decode(reader)?,
        })
    }
}

#[cfg(feature = "issuers")]
impl Encode for walletkit_core::issuers::RecoveryBinding {
    fn encode(self, writer: &mut Writer) -> Result<()> {
        self.recovery_agent.encode(writer)?;
        self.pending_recovery_agent.encode(writer)?;
        self.execute_after.encode(writer)
    }
}

impl Encode for RecoveryUpdateSignature {
    fn encode(self, writer: &mut Writer) -> Result<()> {
        writer.bytes(&self.signature)?;
        self.nonce.encode(writer)
    }
}

impl Encode for RecoveryData {
    fn encode(self, writer: &mut Writer) -> Result<()> {
        writer.string(&self.authenticator_address)?;
        writer.string(&self.authenticator_pubkey)?;
        writer.string(&self.offchain_signer_commitment)
    }
}

impl Encode for RegistrationStatus {
    fn encode(self, writer: &mut Writer) -> Result<()> {
        match self {
            Self::Queued => writer.u8(0),
            Self::Batching => writer.u8(1),
            Self::Submitted => writer.u8(2),
            Self::Finalized => writer.u8(3),
            Self::Failed { error, error_code } => {
                writer.u8(4);
                writer.string(&error)?;
                error_code.encode(writer)?;
            }
        }
        Ok(())
    }
}

impl Encode for GatewayRequestStatus {
    fn encode(self, writer: &mut Writer) -> Result<()> {
        match self {
            Self::Queued => writer.u8(0),
            Self::Batching => writer.u8(1),
            Self::Submitted { tx_hash } => {
                writer.u8(2);
                writer.string(&tx_hash)?;
            }
            Self::Finalized { tx_hash } => {
                writer.u8(3);
                writer.string(&tx_hash)?;
            }
            Self::Failed { error, error_code } => {
                writer.u8(4);
                writer.string(&error)?;
                error_code.encode(writer)?;
            }
        }
        Ok(())
    }
}

impl Decode for FlamingoMatchRequest {
    fn decode(reader: &mut Reader<'_>) -> Result<Self> {
        match reader.tag()? {
            0 => Ok(Self::DeepFace {
                orb_credential: Decode::decode(reader)?,
                live: Decode::decode(reader)?,
                rtms_challenge: Decode::decode(reader)?,
                hashes_json: Decode::decode(reader)?,
                match_threshold: Decode::decode(reader)?,
            }),
            1 => Ok(Self::GrayBadge {
                live: Decode::decode(reader)?,
                rtms_challenge: Decode::decode(reader)?,
                match_threshold: Decode::decode(reader)?,
            }),
            _ => Err(NativeError::invalid_input()),
        }
    }
}

impl Decode for FlamingoLiveCapture {
    fn decode(reader: &mut Reader<'_>) -> Result<Self> {
        match reader.tag()? {
            0 => Ok(Self::Vanilla {
                image: Decode::decode(reader)?,
            }),
            1 => Ok(Self::LightGuard {
                illuminated: Decode::decode(reader)?,
                unilluminated: Decode::decode(reader)?,
                matching_frame: Decode::decode(reader)?,
            }),
            _ => Err(NativeError::invalid_input()),
        }
    }
}

impl Encode for FlamingoMatchOutcome {
    fn encode(self, writer: &mut Writer) -> Result<()> {
        match self {
            Self::Matched {
                token,
                debug_report,
            } => {
                writer.u8(0);
                writer.handle(token)?;
                debug_report.encode(writer)
            }
            Self::Rejected {
                reason,
                debug_report,
            } => {
                writer.u8(1);
                reason.encode(writer)?;
                debug_report.encode(writer)
            }
        }
    }
}

impl Encode for FlamingoDebugReport {
    fn encode(self, writer: &mut Writer) -> Result<()> {
        match self {
            Self::Available { json } => {
                writer.u8(0);
                writer.string(&json)?;
            }
            Self::NotProduced => writer.u8(1),
            Self::OmittedTooLarge {
                original_size_bytes,
            } => {
                writer.u8(2);
                writer.u64(original_size_bytes);
            }
        }
        Ok(())
    }
}

impl Encode for FlamingoMatchRejection {
    fn encode(self, writer: &mut Writer) -> Result<()> {
        match self {
            Self::MalformedInputs => writer.u8(0),
            Self::InvalidHashesJson => writer.u8(1),
            Self::ThumbnailHashMismatch => writer.u8(2),
            Self::InvalidThreshold => writer.u8(3),
            Self::InputRejected {
                reason,
                image,
                limit_bytes,
            } => {
                writer.u8(4);
                reason.encode(writer)?;
                image.encode(writer)?;
                limit_bytes.encode(writer)?;
            }
            Self::MatchBelowThreshold { comparison } => {
                writer.u8(5);
                comparison.encode(writer)?;
            }
            Self::ImageRejected {
                image,
                reason,
                target,
            } => {
                writer.u8(6);
                image.encode(writer)?;
                reason.encode(writer)?;
                target.encode(writer)?;
            }
            Self::MatchingFailed { comparison } => {
                writer.u8(7);
                comparison.encode(writer)?;
            }
            Self::Internal => writer.u8(8),
        }
        Ok(())
    }
}

impl Encode for WalletKitError {
    #[allow(
        clippy::too_many_lines,
        reason = "One arm per variant keeps the frozen indices auditable together."
    )]
    fn encode(self, writer: &mut Writer) -> Result<()> {
        match self {
            Self::Storage(error) => {
                writer.u8(0);
                error.encode(writer)?;
            }
            Self::InvalidInput { attribute, reason } => {
                writer.u8(1);
                writer.string(&attribute)?;
                writer.string(&reason)?;
            }
            Self::InvalidNumber => writer.u8(2),
            Self::SerializationError { error } => {
                writer.u8(3);
                writer.string(&error)?;
            }
            Self::NetworkError { url, error, status } => {
                writer.u8(4);
                writer.string(&url)?;
                writer.string(&error)?;
                status.encode(writer)?;
            }
            Self::Reqwest { error } => {
                writer.u8(5);
                writer.string(&error)?;
            }
            Self::ProofGeneration { error } => {
                writer.u8(6);
                writer.string(&error)?;
            }
            Self::SemaphoreNotEnabled => writer.u8(7),
            Self::CredentialNotIssued => writer.u8(8),
            Self::CredentialNotMined => writer.u8(9),
            Self::AccountDoesNotExist => writer.u8(10),
            Self::UnauthorizedAuthenticator => writer.u8(11),
            Self::AuthenticatorError { error } => {
                writer.u8(12);
                writer.string(&error)?;
            }
            Self::UnfulfillableRequest => writer.u8(13),
            Self::ResponseValidation(error) => {
                writer.u8(14);
                writer.string(&error)?;
            }
            Self::NullifierReplay => writer.u8(15),
            Self::InvalidRpSignature => writer.u8(16),
            Self::DuplicateNonce => writer.u8(17),
            Self::UnknownRp => writer.u8(18),
            Self::InactiveRp => writer.u8(19),
            Self::TimestampTooOld => writer.u8(20),
            Self::TimestampTooFarInFuture => writer.u8(21),
            Self::InvalidTimestamp => writer.u8(22),
            Self::RpSignatureExpired => writer.u8(23),
            Self::Groth16MaterialCacheInvalid { path, error } => {
                writer.u8(24);
                writer.string(&path)?;
                writer.string(&error)?;
            }
            Self::Groth16MaterialEmbeddedLoad { error } => {
                writer.u8(25);
                writer.string(&error)?;
            }
            Self::Generic { error } => {
                writer.u8(26);
                writer.string(&error)?;
            }
            Self::RecoveryBindingDoesNotExist => writer.u8(27),
            Self::SessionIdMismatch => writer.u8(28),
            Self::NfcNonRetryable { error_code } => {
                writer.u8(29);
                writer.string(&error_code)?;
            }
            Self::DebugReportNotFound => writer.u8(30),
            Self::IdentityNotFound => writer.u8(31),
            Self::NoSuccessfulCaptureFound => writer.u8(32),
            Self::NotEligibleForRecovery => writer.u8(33),
            Self::OhttpError { error } => {
                writer.u8(34);
                writer.string(&error)?;
            }
            Self::InvalidActionSession => writer.u8(35),
        }
        Ok(())
    }
}

impl Encode for StorageError {
    fn encode(self, writer: &mut Writer) -> Result<()> {
        let message = |writer: &mut Writer, index, message: String| {
            writer.u8(index);
            writer.string(&message)
        };
        match self {
            Self::Keystore(error) => message(writer, 0, error),
            Self::BlobStore(error) => message(writer, 1, error),
            Self::Lock(error) => message(writer, 2, error),
            Self::Serialization(error) => message(writer, 3, error),
            Self::Crypto(error) => message(writer, 4, error),
            Self::InvalidEnvelope(error) => message(writer, 5, error),
            Self::InvalidInput(error) => message(writer, 6, error),
            Self::UnsupportedEnvelopeVersion(version) => {
                writer.u8(7);
                writer.u32(version);
                Ok(())
            }
            Self::VaultDb(error) => message(writer, 8, error),
            Self::CacheDb(error) => message(writer, 9, error),
            Self::PersistentStorage(error) => message(writer, 10, error),
            Self::InvalidLeafIndex { expected, provided } => {
                writer.u8(11);
                writer.u64(expected);
                writer.u64(provided);
                Ok(())
            }
            Self::CorruptedVault(error) => message(writer, 12, error),
            Self::NotInitialized => {
                writer.u8(13);
                Ok(())
            }
            Self::NullifierAlreadyDisclosed => {
                writer.u8(14);
                Ok(())
            }
            Self::CredentialNotFound => {
                writer.u8(15);
                Ok(())
            }
            Self::CredentialIdNotFound { credential_id } => {
                writer.u8(16);
                writer.u64(credential_id);
                Ok(())
            }
            Self::CorruptedCacheEntry { key_prefix } => {
                writer.u8(17);
                writer.u8(key_prefix);
                Ok(())
            }
            Self::ActivityDb(error) => message(writer, 18, error),
            Self::ActivityInvalidRecord(error) => message(writer, 19, error),
            Self::Callback(error) => message(writer, 20, error),
        }
    }
}

/// Host callbacks report storage failures in this encoding.
impl Decode for StorageError {
    fn decode(reader: &mut Reader<'_>) -> Result<Self> {
        Ok(match reader.tag()? {
            0 => Self::Keystore(reader.string()?),
            1 => Self::BlobStore(reader.string()?),
            2 => Self::Lock(reader.string()?),
            3 => Self::Serialization(reader.string()?),
            4 => Self::Crypto(reader.string()?),
            5 => Self::InvalidEnvelope(reader.string()?),
            6 => Self::InvalidInput(reader.string()?),
            7 => Self::UnsupportedEnvelopeVersion(reader.u32()?),
            8 => Self::VaultDb(reader.string()?),
            9 => Self::CacheDb(reader.string()?),
            10 => Self::PersistentStorage(reader.string()?),
            11 => Self::InvalidLeafIndex {
                expected: reader.u64()?,
                provided: reader.u64()?,
            },
            12 => Self::CorruptedVault(reader.string()?),
            13 => Self::NotInitialized,
            14 => Self::NullifierAlreadyDisclosed,
            15 => Self::CredentialNotFound,
            16 => Self::CredentialIdNotFound {
                credential_id: reader.u64()?,
            },
            17 => Self::CorruptedCacheEntry {
                key_prefix: reader.u8()?,
            },
            18 => Self::ActivityDb(reader.string()?),
            19 => Self::ActivityInvalidRecord(reader.string()?),
            20 => Self::Callback(reader.string()?),
            _ => return Err(NativeError::invalid_input()),
        })
    }
}

impl Encode for FlamingoError {
    fn encode(self, writer: &mut Writer) -> Result<()> {
        match self {
            Self::InvalidInput {
                attribute,
                reason,
                kind,
                limit_bytes,
            } => {
                writer.u8(0);
                writer.string(&attribute)?;
                writer.string(&reason)?;
                kind.encode(writer)?;
                limit_bytes.encode(writer)?;
            }
            Self::Configuration(error) => {
                writer.u8(1);
                writer.string(&error)?;
            }
            Self::RequestIntegrity(error) => {
                writer.u8(2);
                error.encode(writer)?;
            }
            Self::Service { code, allow_retry } => {
                writer.u8(3);
                writer.string(&code)?;
                writer.bool(allow_retry);
            }
            Self::Timeout => writer.u8(4),
            Self::Transport { details } => {
                writer.u8(5);
                writer.string(&details)?;
            }
            Self::InvalidResponse { stage } => {
                writer.u8(6);
                stage.encode(writer)?;
            }
            Self::Attestation { details } => {
                writer.u8(7);
                writer.string(&details)?;
            }
            Self::Channel { details } => {
                writer.u8(8);
                writer.string(&details)?;
            }
            Self::InvalidSigningKey => writer.u8(9),
            Self::StatementInvalid => writer.u8(10),
            Self::ReassignmentRequired => writer.u8(11),
        }
        Ok(())
    }
}

impl Encode for CredentialConstraintsCheckError {
    fn encode(self, writer: &mut Writer) -> Result<()> {
        match self {
            Self::Storage(error) => {
                writer.u8(0);
                error.encode(writer)
            }
            Self::ConstraintTooDeep => {
                writer.u8(1);
                Ok(())
            }
            Self::ConstraintTooLarge => {
                writer.u8(2);
                Ok(())
            }
        }
    }
}

/// Frozen encodings shared with the Kotlin (`CodecTest.kt`) and Swift (`CodecTests.swift`)
/// tests. Changing a fixture is a wire-format change.
#[cfg(all(test, feature = "issuers"))]
mod tests {
    use super::*;
    use crate::native::{codec, error::NativeError};
    use std::{collections::HashMap, fmt::Write as _};
    use walletkit_core::{issuers::RecoveryBinding, Uint256};

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().fold(String::new(), |mut hex, byte| {
            write!(hex, "{byte:02x}").unwrap();
            hex
        })
    }

    #[allow(dead_code)]
    fn bytes(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).unwrap())
            .collect()
    }

    fn encoded<T: Encode>(value: T) -> String {
        hex(&codec::encode(value).unwrap().claim())
    }

    fn activity_entries() -> Vec<ActivityEntry> {
        vec![
            ActivityEntry {
                id: Some(1),
                rp_id: u64::MAX,
                app_identifier: "app".into(),
                client_id: "zażółć".into(),
                protocol: ProtocolVersion::V4,
                timestamp: Some(100),
                outcome: ActivityOutcome::Failed,
                issuer_schema_ids: vec![7, u64::MAX],
                failure_reason: Some(ActivityFailureReason::RelyingPartyRejected),
            },
            ActivityEntry {
                id: None,
                rp_id: 2,
                app_identifier: String::new(),
                client_id: "c".into(),
                protocol: ProtocolVersion::V3,
                timestamp: None,
                outcome: ActivityOutcome::Completed,
                issuer_schema_ids: vec![],
                failure_reason: None,
            },
        ]
    }

    #[allow(clippy::too_many_lines, reason = "One entry per frozen fixture.")]
    fn outputs() -> Vec<(&'static str, String)> {
        vec![
            ("ACTIVITY_ENTRIES", encoded(activity_entries())),
            (
                "CREDENTIAL_RECORDS",
                encoded(vec![CredentialRecord {
                    credential_id: 1,
                    issuer_schema_id: u64::MAX,
                    genesis_issued_at: 3,
                    expires_at: 4,
                    is_expired: true,
                }]),
            ),
            (
                "CHECK_RESULT",
                encoded(CredentialConstraintsCheckResult {
                    is_satisfied: false,
                    check_results: vec![CredentialConstraintsCheckItem {
                        identifier: "orb".into(),
                        issuer_schema_id: 9,
                        has_credential: true,
                    }],
                }),
            ),
            (
                "RECOVERY_DATA",
                encoded(RecoveryData {
                    authenticator_address: "0xa".into(),
                    authenticator_pubkey: "pk".into(),
                    offchain_signer_commitment: "c".into(),
                }),
            ),
            (
                "RECOVERY_UPDATE_SIGNATURE",
                encoded(RecoveryUpdateSignature {
                    signature: vec![1, 2, 3],
                    nonce: "0x2a".parse::<Uint256>().unwrap(),
                }),
            ),
            (
                "RECOVERY_BINDING",
                encoded(RecoveryBinding {
                    recovery_agent: Some("a".into()),
                    pending_recovery_agent: None,
                    execute_after: Some("t".into()),
                }),
            ),
            (
                "GATEWAY_SUBMITTED",
                encoded(GatewayRequestStatus::Submitted {
                    tx_hash: "0x1".into(),
                }),
            ),
            (
                "GATEWAY_FAILED",
                encoded(GatewayRequestStatus::Failed {
                    error: "e".into(),
                    error_code: Some("c".into()),
                }),
            ),
            (
                "REGISTRATION_FINALIZED",
                encoded(RegistrationStatus::Finalized),
            ),
            (
                "REGISTRATION_FAILED",
                encoded(RegistrationStatus::Failed {
                    error: "e".into(),
                    error_code: None,
                }),
            ),
            (
                "OUTCOME_IMAGE_REJECTED",
                encoded(FlamingoMatchOutcome::Rejected {
                    reason: FlamingoMatchRejection::ImageRejected {
                        image: FlamingoImageRole::LiveSelfie,
                        reason: FlamingoImageFailureReason::NoisyThermalImage,
                        target: Some(FlamingoValidationTarget::LightGuardPair),
                    },
                    debug_report: FlamingoDebugReport::OmittedTooLarge {
                        original_size_bytes: 5,
                    },
                }),
            ),
            (
                "OUTCOME_INPUT_REJECTED",
                encoded(FlamingoMatchOutcome::Rejected {
                    reason: FlamingoMatchRejection::InputRejected {
                        reason: FlamingoInputFailureReason::TotalImagesTooLarge,
                        image: None,
                        limit_bytes: Some(10),
                    },
                    debug_report: FlamingoDebugReport::Available { json: "{}".into() },
                }),
            ),
            (
                "OPTIONAL_STRINGS",
                encoded(vec![Some("a".to_owned()), None]),
            ),
            ("STRINGS", encoded(vec!["0x01".to_owned()])),
            ("ERROR_CANCELLED", hex(&NativeError::cancelled().encode())),
            (
                "ERROR_NETWORK",
                hex(&NativeError::from(WalletKitError::NetworkError {
                    url: "u".into(),
                    error: "e".into(),
                    status: Some(503),
                })
                .encode()),
            ),
            (
                "ERROR_WALLETKIT_STORAGE",
                hex(&NativeError::from(WalletKitError::Storage(
                    StorageError::InvalidLeafIndex {
                        expected: 1,
                        provided: 2,
                    },
                ))
                .encode()),
            ),
            (
                "ERROR_KEYSTORE",
                hex(&NativeError::from(StorageError::Keystore("denied".into()))
                    .encode()),
            ),
            (
                "ERROR_FLAMINGO_INPUT",
                hex(&NativeError::from(FlamingoError::InvalidInput {
                    attribute: "a".into(),
                    reason: "r".into(),
                    kind: FlamingoInputFailureKind::TooLarge,
                    limit_bytes: Some(9),
                })
                .encode()),
            ),
            (
                "ERROR_FLAMINGO_INTEGRITY",
                hex(&NativeError::from(FlamingoError::RequestIntegrity(
                    RequestIntegrityError::TimedOut,
                ))
                .encode()),
            ),
            (
                "ERROR_CONSTRAINTS",
                hex(&NativeError::from(
                    CredentialConstraintsCheckError::ConstraintTooDeep,
                )
                .encode()),
            ),
        ]
    }

    const FROZEN: &[(&str, &str)] = &[
        ("ACTIVITY_ENTRIES", "02000000010100000000000000ffffffffffffffff030000006170700a0000007a61c5bcc3b3c582c4870101640000000000000003020000000700000000000000ffffffffffffffff01040002000000000000000000000001000000630000000000000000"),
        ("CREDENTIAL_RECORDS", "010000000100000000000000ffffffffffffffff0300000000000000040000000000000001"),
        ("CHECK_RESULT", "0001000000030000006f7262090000000000000001"),
        ("RECOVERY_DATA", "0300000030786102000000706b0100000063"),
        ("RECOVERY_UPDATE_SIGNATURE", "03000000010203000000000000000000000000000000000000000000000000000000000000002a"),
        ("RECOVERY_BINDING", "01010000006100010100000074"),
        ("GATEWAY_SUBMITTED", "0203000000307831"),
        ("GATEWAY_FAILED", "040100000065010100000063"),
        ("REGISTRATION_FINALIZED", "03"),
        ("REGISTRATION_FAILED", "04010000006500"),
        ("OUTCOME_IMAGE_REJECTED", "0106012a0103020500000000000000"),
        ("OUTCOME_INPUT_REJECTED", "01040500010a0000000000000000020000007b7d"),
        ("OPTIONAL_STRINGS", "0200000001010000006100"),
        ("STRINGS", "010000000400000030783031"),
        ("ERROR_CANCELLED", "000900000043616e63656c6c6564"),
        ("ERROR_NETWORK", "01040100000075010000006501f701"),
        ("ERROR_WALLETKIT_STORAGE", "01000b01000000000000000200000000000000"),
        ("ERROR_KEYSTORE", "02000600000064656e696564"),
        ("ERROR_FLAMINGO_INPUT", "03000100000061010000007201010900000000000000"),
        ("ERROR_FLAMINGO_INTEGRITY", "030204"),
        ("ERROR_CONSTRAINTS", "0401"),
    ];

    const ACTIVITY_ENTRY: &str = "010100000000000000ffffffffffffffff030000006170700a0000007a61c5bcc3b3c582c4870101640000000000000003020000000700000000000000ffffffffffffffff0104";
    const STRING_MAP: &str = "01000000010000006b0100000076";
    const MEASUREMENTS: &str = "010000000200000001000000ab";
    const DEEP_FACE_REQUEST: &str =
        "000100000001010100000002010000000301010000000402000000\
                                     7b7d000000000000e03f";
    const GRAY_BADGE_REQUEST: &str = "0100010000000500000000000000000000f03f";
    const HOST_KEYSTORE_ERROR: &str = "000600000064656e696564";

    #[test]
    fn outputs_match_frozen_encodings() {
        let actual = outputs();
        assert_eq!(actual.len(), FROZEN.len());
        for ((name, actual), (frozen_name, frozen)) in actual.iter().zip(FROZEN) {
            assert_eq!(name, frozen_name);
            assert_eq!(actual, frozen, "{name}");
        }
    }

    #[test]
    fn inputs_decode_from_frozen_encodings() {
        let entry: ActivityEntry = codec::decode(&bytes(ACTIVITY_ENTRY)).unwrap();
        assert_eq!(entry, activity_entries().remove(0));

        let map: HashMap<String, String> = codec::decode(&bytes(STRING_MAP)).unwrap();
        assert_eq!(map, HashMap::from([("k".into(), "v".into())]));

        let map: HashMap<u32, Vec<u8>> = codec::decode(&bytes(MEASUREMENTS)).unwrap();
        assert_eq!(map, HashMap::from([(2, vec![0xab])]));

        let request: FlamingoMatchRequest =
            codec::decode(&bytes(DEEP_FACE_REQUEST)).unwrap();
        let FlamingoMatchRequest::DeepFace {
            orb_credential,
            live:
                FlamingoLiveCapture::LightGuard {
                    illuminated,
                    unilluminated,
                    matching_frame: FlamingoMatchingFrame::Unilluminated,
                },
            rtms_challenge,
            hashes_json,
            match_threshold,
        } = request
        else {
            panic!("unexpected request");
        };
        assert_eq!(
            (orb_credential, illuminated, unilluminated, rtms_challenge),
            (vec![1], vec![2], vec![3], vec![4])
        );
        assert_eq!(hashes_json, b"{}");
        assert!((match_threshold - 0.5).abs() < f64::EPSILON);

        let request: FlamingoMatchRequest =
            codec::decode(&bytes(GRAY_BADGE_REQUEST)).unwrap();
        assert!(matches!(
            request,
            FlamingoMatchRequest::GrayBadge {
                live: FlamingoLiveCapture::Vanilla { ref image },
                ref rtms_challenge,
                match_threshold,
            } if image == &[5] && rtms_challenge.is_empty() && (match_threshold - 1.0).abs() < f64::EPSILON
        ));

        let error: StorageError = codec::decode(&bytes(HOST_KEYSTORE_ERROR)).unwrap();
        assert!(
            matches!(error, StorageError::Keystore(message) if message == "denied")
        );
    }

    #[test]
    fn decoders_reject_malformed_input() {
        for bad in [
            "",                         // short
            "000600000064656e696564ff", // trailing byte
            "150000000000",             // unknown variant
            "0002000000c328",           // invalid UTF-8
            "00ffffffff",               // length beyond input
        ] {
            assert!(codec::decode::<StorageError>(&bytes(bad)).is_err(), "{bad}");
        }
        assert!(codec::decode::<Option<u64>>(&bytes("02")).is_err());
        assert!(codec::decode::<bool>(&bytes("02")).is_err());
        assert!(codec::decode::<HashMap<String, String>>(&bytes(
            "02000000010000006b0100000076010000006b0100000076"
        ))
        .is_err());
    }

    #[test]
    fn ordinals_round_trip_and_reject_unknown_values() {
        for ordinal in 0..43 {
            let reason = FlamingoImageFailureReason::from_ordinal(ordinal).unwrap();
            assert_eq!(i64::from(reason.ordinal()), ordinal);
        }
        assert!(FlamingoImageFailureReason::from_ordinal(43).is_none());
        assert!(LogLevel::from_ordinal(-1).is_none());
        assert_eq!(Environment::Production.ordinal(), 1);
        assert!(matches!(Region::from_ordinal(2), Some(Region::Ap)));
    }
}
