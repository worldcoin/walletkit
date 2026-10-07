package org.world.walletkit

sealed class CredentialConstraintsCheckException(
    val variant: String,
) : Exception("CredentialConstraintsCheckException.$variant") {
    final override fun toString(): String = "CredentialConstraintsCheckException.$variant"

    class Storage(
        val value0: StorageException,
    ) : CredentialConstraintsCheckException("Storage")

    class ConstraintTooDeep : CredentialConstraintsCheckException("ConstraintTooDeep")

    class ConstraintTooLarge : CredentialConstraintsCheckException("ConstraintTooLarge")
}

data class CredentialConstraintsCheckItem(
    val identifier: String,
    val issuerSchemaId: ULong,
    val hasCredential: Boolean,
)

data class CredentialConstraintsCheckResult(
    val isSatisfied: Boolean,
    val checkResults: List<CredentialConstraintsCheckItem>,
)

enum class LogLevel { TRACE, DEBUG, INFO, WARN, ERROR }

sealed class WalletKitException(
    val variant: String,
) : Exception("WalletKitException.$variant") {
    /** A diagnostic category without potentially sensitive associated values. */
    fun sanitizedMessage(): String = toString()

    final override fun toString(): String = "WalletKitException.$variant"

    class Storage(
        val value0: StorageException,
    ) : WalletKitException("Storage")

    class InvalidInput(
        val attribute: String,
        val reason: String,
    ) : WalletKitException("InvalidInput")

    class InvalidNumber : WalletKitException("InvalidNumber")

    class SerializationError(
        val error: String,
    ) : WalletKitException("SerializationError")

    class NetworkError(
        val url: String,
        val error: String,
        val status: UShort?,
    ) : WalletKitException("NetworkError")

    class Reqwest(
        val error: String,
    ) : WalletKitException("Reqwest")

    class ProofGeneration(
        val error: String,
    ) : WalletKitException("ProofGeneration")

    class SemaphoreNotEnabled : WalletKitException("SemaphoreNotEnabled")

    class CredentialNotIssued : WalletKitException("CredentialNotIssued")

    class CredentialNotMined : WalletKitException("CredentialNotMined")

    class AccountDoesNotExist : WalletKitException("AccountDoesNotExist")

    class UnauthorizedAuthenticator : WalletKitException("UnauthorizedAuthenticator")

    class AuthenticatorError(
        val error: String,
    ) : WalletKitException("AuthenticatorError")

    class UnfulfillableRequest : WalletKitException("UnfulfillableRequest")

    class ResponseValidation(
        val value0: String,
    ) : WalletKitException("ResponseValidation")

    class NullifierReplay : WalletKitException("NullifierReplay")

    class InvalidRpSignature : WalletKitException("InvalidRpSignature")

    class DuplicateNonce : WalletKitException("DuplicateNonce")

    class UnknownRp : WalletKitException("UnknownRp")

    class InactiveRp : WalletKitException("InactiveRp")

    class TimestampTooOld : WalletKitException("TimestampTooOld")

    class TimestampTooFarInFuture : WalletKitException("TimestampTooFarInFuture")

    class InvalidTimestamp : WalletKitException("InvalidTimestamp")

    class RpSignatureExpired : WalletKitException("RpSignatureExpired")

    class Groth16MaterialCacheInvalid(
        val path: String,
        val error: String,
    ) : WalletKitException("Groth16MaterialCacheInvalid")

    class Groth16MaterialEmbeddedLoad(
        val error: String,
    ) : WalletKitException("Groth16MaterialEmbeddedLoad")

    class Generic(
        val error: String,
    ) : WalletKitException("Generic")

    class RecoveryBindingDoesNotExist : WalletKitException("RecoveryBindingDoesNotExist")

    class SessionIdMismatch : WalletKitException("SessionIdMismatch")

    class NfcNonRetryable(
        val errorCode: String,
    ) : WalletKitException("NfcNonRetryable")

    class DebugReportNotFound : WalletKitException("DebugReportNotFound")

    class IdentityNotFound : WalletKitException("IdentityNotFound")

    class NoSuccessfulCaptureFound : WalletKitException("NoSuccessfulCaptureFound")

    class NotEligibleForRecovery : WalletKitException("NotEligibleForRecovery")

    class OhttpError(
        val error: String,
    ) : WalletKitException("OhttpError")

    class InvalidActionSession : WalletKitException("InvalidActionSession")
}

enum class Environment { STAGING, PRODUCTION }

enum class Region { US, EU, AP }

enum class BlobKind { CREDENTIAL_BLOB, ASSOCIATED_DATA }

data class CredentialRecord(
    val credentialId: ULong,
    val issuerSchemaId: ULong,
    val genesisIssuedAt: ULong,
    val expiresAt: ULong,
    val isExpired: Boolean,
)

enum class ReplayGuardKind { FRESH, REPLAY }

data class ReplayGuardResult(
    val kind: ReplayGuardKind,
    val bytes: ByteArray,
)

enum class ProtocolVersion { V3, V4 }

enum class ActivityOutcome { COMPLETED, DECLINED, CANCELLED, FAILED, INCOMPLETE }

enum class ActivityFailureReason {
    NETWORK_ERROR,
    TIMEOUT,
    DEVICE_AUTHENTICATION_FAILED,
    PROOF_GENERATION_FAILED,
    RELYING_PARTY_REJECTED,
}

data class ActivityEntry(
    val id: ULong?,
    val rpId: ULong,
    val appIdentifier: String,
    val clientId: String,
    val protocol: ProtocolVersion,
    val timestamp: ULong?,
    val outcome: ActivityOutcome,
    val issuerSchemaIds: List<ULong>,
    val failureReason: ActivityFailureReason?,
)

data class ActivityMetadata(
    val totalCount: ULong,
)

/** Immutable activity filters; builder methods return a new value. */
data class ActivityQuery(
    val issuerSchemaId: ULong? = null,
) {
    fun withIssuerSchemaId(issuerSchemaId: ULong): ActivityQuery = copy(issuerSchemaId = issuerSchemaId)
}

sealed class StorageException(
    val variant: String,
) : Exception("StorageException.$variant") {
    final override fun toString(): String = "StorageException.$variant"

    class Keystore(
        val value0: String,
    ) : StorageException("Keystore")

    class BlobStore(
        val value0: String,
    ) : StorageException("BlobStore")

    class Lock(
        val value0: String,
    ) : StorageException("Lock")

    class Serialization(
        val value0: String,
    ) : StorageException("Serialization")

    class Crypto(
        val value0: String,
    ) : StorageException("Crypto")

    class InvalidEnvelope(
        val value0: String,
    ) : StorageException("InvalidEnvelope")

    class InvalidInput(
        val value0: String,
    ) : StorageException("InvalidInput")

    class UnsupportedEnvelopeVersion(
        val value0: UInt,
    ) : StorageException("UnsupportedEnvelopeVersion")

    class VaultDb(
        val value0: String,
    ) : StorageException("VaultDb")

    class CacheDb(
        val value0: String,
    ) : StorageException("CacheDb")

    class PersistentStorage(
        val value0: String,
    ) : StorageException("PersistentStorage")

    class InvalidLeafIndex(
        val expected: ULong,
        val provided: ULong,
    ) : StorageException("InvalidLeafIndex")

    class CorruptedVault(
        val value0: String,
    ) : StorageException("CorruptedVault")

    class NotInitialized : StorageException("NotInitialized")

    class NullifierAlreadyDisclosed : StorageException("NullifierAlreadyDisclosed")

    class CredentialNotFound : StorageException("CredentialNotFound")

    class CredentialIdNotFound(
        val credentialId: ULong,
    ) : StorageException("CredentialIdNotFound")

    class CorruptedCacheEntry(
        val keyPrefix: UByte,
    ) : StorageException("CorruptedCacheEntry")

    class ActivityDb(
        val value0: String,
    ) : StorageException("ActivityDb")

    class ActivityInvalidRecord(
        val value0: String,
    ) : StorageException("ActivityInvalidRecord")

    class Callback(
        val value0: String,
    ) : StorageException("Callback")
}

enum class CredentialType { ORB, DOCUMENT, SECURE_DOCUMENT, DEVICE }

data class RecoveryBinding(
    val recoveryAgent: String?,
    val pendingRecoveryAgent: String?,
    val executeAfter: String?,
)

sealed interface RegistrationStatus {
    object Queued : RegistrationStatus

    object Batching : RegistrationStatus

    object Submitted : RegistrationStatus

    object Finalized : RegistrationStatus

    data class Failed(
        val error: String,
        val errorCode: String?,
    ) : RegistrationStatus
}

sealed interface GatewayRequestStatus {
    object Queued : GatewayRequestStatus

    object Batching : GatewayRequestStatus

    data class Submitted(
        val txHash: String,
    ) : GatewayRequestStatus

    data class Finalized(
        val txHash: String,
    ) : GatewayRequestStatus

    data class Failed(
        val error: String,
        val errorCode: String?,
    ) : GatewayRequestStatus
}

data class RecoveryUpdateSignature(
    val signature: ByteArray,
    val nonce: Uint256,
)

data class RecoveryData(
    val authenticatorAddress: String,
    val authenticatorPubkey: String,
    val offchainSignerCommitment: String,
)

sealed interface FlamingoMatchRequest {
    data class DeepFace(
        val orbCredential: ByteArray,
        val live: FlamingoLiveCapture,
        val rtmsChallenge: ByteArray,
        val hashesJson: ByteArray,
        val matchThreshold: Double,
    ) : FlamingoMatchRequest

    data class GrayBadge(
        val live: FlamingoLiveCapture,
        val rtmsChallenge: ByteArray,
        val matchThreshold: Double,
    ) : FlamingoMatchRequest
}

sealed interface FlamingoLiveCapture {
    data class Vanilla(
        val image: ByteArray,
    ) : FlamingoLiveCapture

    data class LightGuard(
        val illuminated: ByteArray,
        val unilluminated: ByteArray,
        val matchingFrame: FlamingoMatchingFrame,
    ) : FlamingoLiveCapture
}

enum class FlamingoMatchingFrame { ILLUMINATED, UNILLUMINATED }

sealed interface FlamingoMatchOutcome {
    data class Matched(
        val token: VerifiedMatchToken,
        val debugReport: FlamingoDebugReport,
    ) : FlamingoMatchOutcome

    data class Rejected(
        val reason: FlamingoMatchRejection,
        val debugReport: FlamingoDebugReport,
    ) : FlamingoMatchOutcome
}

sealed interface FlamingoDebugReport {
    data class Available(
        val json: String,
    ) : FlamingoDebugReport

    object NotProduced : FlamingoDebugReport

    data class OmittedTooLarge(
        val originalSizeBytes: ULong,
    ) : FlamingoDebugReport
}

sealed interface FlamingoMatchRejection {
    object MalformedInputs : FlamingoMatchRejection

    object InvalidHashesJson : FlamingoMatchRejection

    object ThumbnailHashMismatch : FlamingoMatchRejection

    object InvalidThreshold : FlamingoMatchRejection

    data class InputRejected(
        val reason: FlamingoInputFailureReason,
        val image: FlamingoImageRole?,
        val limitBytes: ULong?,
    ) : FlamingoMatchRejection

    data class MatchBelowThreshold(
        val comparison: FlamingoComparison,
    ) : FlamingoMatchRejection

    data class ImageRejected(
        val image: FlamingoImageRole,
        val reason: FlamingoImageFailureReason,
        val target: FlamingoValidationTarget?,
    ) : FlamingoMatchRejection

    data class MatchingFailed(
        val comparison: FlamingoComparison,
    ) : FlamingoMatchRejection

    object Internal : FlamingoMatchRejection
}

enum class FlamingoComparison { ORB_SELFIE, ORB_CHALLENGE, SELFIE_CHALLENGE }

enum class FlamingoImageRole { ORB_CREDENTIAL, LIVE_SELFIE, RTMS_CHALLENGE }

sealed class FlamingoException(
    val variant: String,
) : Exception("FlamingoException.$variant") {
    final override fun toString(): String = "FlamingoException.$variant"

    class InvalidInput(
        val attribute: String,
        val reason: String,
        val kind: FlamingoInputFailureKind,
        val limitBytes: ULong?,
    ) : FlamingoException("InvalidInput")

    class Configuration(
        val value0: String,
    ) : FlamingoException("Configuration")

    class RequestIntegrity(
        val value0: RequestIntegrityException,
    ) : FlamingoException("RequestIntegrity")

    class Service(
        val code: String,
        val allowRetry: Boolean,
    ) : FlamingoException("Service")

    class Timeout : FlamingoException("Timeout")

    class Transport(
        val details: String,
    ) : FlamingoException("Transport")

    class InvalidResponse(
        val stage: FlamingoResponseStage,
    ) : FlamingoException("InvalidResponse")

    class Attestation(
        val details: String,
    ) : FlamingoException("Attestation")

    class Channel(
        val details: String,
    ) : FlamingoException("Channel")

    class InvalidSigningKey : FlamingoException("InvalidSigningKey")

    class StatementInvalid : FlamingoException("StatementInvalid")

    class ReassignmentRequired : FlamingoException("ReassignmentRequired")
}

enum class FlamingoImageFailureReason {
    INVALID_IMAGE,
    TEMPLATE_FAILED,
    TOO_MANY_FACES,
    IMAGE_TOO_DARK,
    IMAGE_TOO_BRIGHT,
    ILLUMINATION_VARIANCE,
    FACE_TOO_SMALL,
    FACE_TOO_BIG,
    FACE_RESOLUTION_TOO_LOW,
    FACE_TOO_HIGH,
    FACE_TOO_LOW,
    FACE_TOO_FAR_LEFT,
    FACE_TOO_FAR_RIGHT,
    HEAD_POSE_YAW,
    HEAD_POSE_PITCH_TOO_HIGH,
    HEAD_POSE_PITCH_TOO_LOW,
    HEAD_POSE_ROLL,
    LOW_QUALITY,
    SUNGLASSES_OCCLUSION_DETECTED,
    GLASSES_OCCLUSION_DETECTED,
    MASK_OCCLUSION_DETECTED,
    OTHER_OCCLUSION_DETECTED,
    HAIR_OCCLUSION_DETECTED,
    FAS_OCCLUSION_DETECTED,
    SPOOF_DETECTED,
    DEPTH_SPOOF_DETECTED,
    THERMAL_SPOOF_DETECTED,
    AGE_BELOW_THRESHOLD,
    NO_FACE_DETECTED,
    EYES_CLOSED,
    NON_NEUTRAL_EXPRESSION,
    LANDMARKS_ALIGNMENT,
    FACE_OVEREXPOSED,
    FACE_UNDEREXPOSED,
    SEGMENTATION_OCCLUSION_PROPORTION,
    BRIGHT_ARTIFACTS,
    LIGHT_GUARD_SCORE_TOO_LOW,
    LOW_CONTRAST,
    MESH_EXPRESSION_SCORE,
    HIGH_COLOR_DISTORTION,
    UNEVEN_LIGHTING,
    BLURRY_FACE,
    NOISY_THERMAL_IMAGE,
}

enum class FlamingoValidationTarget {
    IMAGE,
    ILLUMINATED_FRAME,
    UNILLUMINATED_FRAME,
    LIGHT_GUARD_PAIR,
}

enum class FlamingoInputFailureReason {
    MISSING_IMAGE,
    MISSING_SOURCE,
    INVALID_MATCHING_FRAME,
    EMPTY_IMAGE,
    IMAGE_TOO_LARGE,
    TOTAL_IMAGES_TOO_LARGE,
}

enum class FlamingoInputFailureKind { EMPTY, TOO_LARGE, TOTAL_TOO_LARGE, INVALID_THRESHOLD }

enum class FlamingoResponseStage { ASSIGNMENT, HOST_MESSAGE, MATCH_RESULT }

/** The encoding a [RequestDigestSigner] produces. */
enum class RequestIntegrityPlatform { IOS, ANDROID }

/** Request-integrity failures without token, key, or native diagnostic contents. */
sealed class RequestIntegrityException(
    val variant: String,
) : Exception("RequestIntegrityException.$variant") {
    final override fun toString(): String = "RequestIntegrityException.$variant"

    class Unavailable : RequestIntegrityException("Unavailable")

    class InvalidSession : RequestIntegrityException("InvalidSession")

    class SigningFailed : RequestIntegrityException("SigningFailed")

    class CallbackFailed : RequestIntegrityException("CallbackFailed")

    class TimedOut : RequestIntegrityException("TimedOut")
}

/** A token and the signer pinned to the exact key certified by that token. */
data class RequestIntegritySession(
    val token: String,
    val platform: RequestIntegrityPlatform,
    val signer: RequestDigestSigner,
)
