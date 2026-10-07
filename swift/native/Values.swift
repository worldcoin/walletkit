import Foundation

public enum CredentialConstraintsCheckError: Sendable, Error, CustomStringConvertible {
  case storage(value0: StorageError)
  case constraintTooDeep
  case constraintTooLarge
  public var description: String {
    switch self {
    case .storage: return "CredentialConstraintsCheckError.Storage"
    case .constraintTooDeep: return "CredentialConstraintsCheckError.ConstraintTooDeep"
    case .constraintTooLarge: return "CredentialConstraintsCheckError.ConstraintTooLarge"
    }
  }
}

public struct CredentialConstraintsCheckItem: Sendable {
  public var identifier: String
  public var issuerSchemaId: UInt64
  public var hasCredential: Bool
  public init(identifier: String, issuerSchemaId: UInt64, hasCredential: Bool) {
    self.identifier = identifier
    self.issuerSchemaId = issuerSchemaId
    self.hasCredential = hasCredential
  }
}

public struct CredentialConstraintsCheckResult: Sendable {
  public var isSatisfied: Bool
  public var checkResults: [CredentialConstraintsCheckItem]
  public init(isSatisfied: Bool, checkResults: [CredentialConstraintsCheckItem]) {
    self.isSatisfied = isSatisfied
    self.checkResults = checkResults
  }
}

public enum LogLevel: Sendable {
  case trace
  case debug
  case info
  case warn
  case error
}

public enum WalletKitError: Sendable, Error, CustomStringConvertible {
  /// A stable diagnostic category without potentially sensitive associated values.
  public func sanitizedMessage() -> String { description }

  case storage(value0: StorageError)
  case invalidInput(attribute: String, reason: String)
  case invalidNumber
  case serializationError(error: String)
  case networkError(url: String, error: String, status: UInt16?)
  case reqwest(error: String)
  case proofGeneration(error: String)
  case semaphoreNotEnabled
  case credentialNotIssued
  case credentialNotMined
  case accountDoesNotExist
  case unauthorizedAuthenticator
  case authenticatorError(error: String)
  case unfulfillableRequest
  case responseValidation(value0: String)
  case nullifierReplay
  case invalidRpSignature
  case duplicateNonce
  case unknownRp
  case inactiveRp
  case timestampTooOld
  case timestampTooFarInFuture
  case invalidTimestamp
  case rpSignatureExpired
  case groth16MaterialCacheInvalid(path: String, error: String)
  case groth16MaterialEmbeddedLoad(error: String)
  case generic(error: String)
  case recoveryBindingDoesNotExist
  case sessionIdMismatch
  case nfcNonRetryable(errorCode: String)
  case debugReportNotFound
  case identityNotFound
  case noSuccessfulCaptureFound
  case notEligibleForRecovery
  case ohttpError(error: String)
  case invalidActionSession
  public var description: String {
    switch self {
    case .storage: return "WalletKitError.Storage"
    case .invalidInput: return "WalletKitError.InvalidInput"
    case .invalidNumber: return "WalletKitError.InvalidNumber"
    case .serializationError: return "WalletKitError.SerializationError"
    case .networkError: return "WalletKitError.NetworkError"
    case .reqwest: return "WalletKitError.Reqwest"
    case .proofGeneration: return "WalletKitError.ProofGeneration"
    case .semaphoreNotEnabled: return "WalletKitError.SemaphoreNotEnabled"
    case .credentialNotIssued: return "WalletKitError.CredentialNotIssued"
    case .credentialNotMined: return "WalletKitError.CredentialNotMined"
    case .accountDoesNotExist: return "WalletKitError.AccountDoesNotExist"
    case .unauthorizedAuthenticator: return "WalletKitError.UnauthorizedAuthenticator"
    case .authenticatorError: return "WalletKitError.AuthenticatorError"
    case .unfulfillableRequest: return "WalletKitError.UnfulfillableRequest"
    case .responseValidation: return "WalletKitError.ResponseValidation"
    case .nullifierReplay: return "WalletKitError.NullifierReplay"
    case .invalidRpSignature: return "WalletKitError.InvalidRpSignature"
    case .duplicateNonce: return "WalletKitError.DuplicateNonce"
    case .unknownRp: return "WalletKitError.UnknownRp"
    case .inactiveRp: return "WalletKitError.InactiveRp"
    case .timestampTooOld: return "WalletKitError.TimestampTooOld"
    case .timestampTooFarInFuture: return "WalletKitError.TimestampTooFarInFuture"
    case .invalidTimestamp: return "WalletKitError.InvalidTimestamp"
    case .rpSignatureExpired: return "WalletKitError.RpSignatureExpired"
    case .groth16MaterialCacheInvalid: return "WalletKitError.Groth16MaterialCacheInvalid"
    case .groth16MaterialEmbeddedLoad: return "WalletKitError.Groth16MaterialEmbeddedLoad"
    case .generic: return "WalletKitError.Generic"
    case .recoveryBindingDoesNotExist: return "WalletKitError.RecoveryBindingDoesNotExist"
    case .sessionIdMismatch: return "WalletKitError.SessionIdMismatch"
    case .nfcNonRetryable: return "WalletKitError.NfcNonRetryable"
    case .debugReportNotFound: return "WalletKitError.DebugReportNotFound"
    case .identityNotFound: return "WalletKitError.IdentityNotFound"
    case .noSuccessfulCaptureFound: return "WalletKitError.NoSuccessfulCaptureFound"
    case .notEligibleForRecovery: return "WalletKitError.NotEligibleForRecovery"
    case .ohttpError: return "WalletKitError.OhttpError"
    case .invalidActionSession: return "WalletKitError.InvalidActionSession"
    }
  }
}

public enum Environment: Sendable {
  case staging
  case production
}

public enum Region: Sendable {
  case us
  case eu
  case ap
}

public enum BlobKind: Sendable {
  case credentialBlob
  case associatedData
}

public struct CredentialRecord: Sendable {
  public var credentialId: UInt64
  public var issuerSchemaId: UInt64
  public var genesisIssuedAt: UInt64
  public var expiresAt: UInt64
  public var isExpired: Bool
  public init(
    credentialId: UInt64, issuerSchemaId: UInt64, genesisIssuedAt: UInt64, expiresAt: UInt64,
    isExpired: Bool
  ) {
    self.credentialId = credentialId
    self.issuerSchemaId = issuerSchemaId
    self.genesisIssuedAt = genesisIssuedAt
    self.expiresAt = expiresAt
    self.isExpired = isExpired
  }
}

public enum ReplayGuardKind: Sendable {
  case fresh
  case replay
}

public struct ReplayGuardResult: Sendable {
  public var kind: ReplayGuardKind
  public var bytes: Data
  public init(kind: ReplayGuardKind, bytes: Data) {
    self.kind = kind
    self.bytes = bytes
  }
}

public enum ProtocolVersion: Sendable {
  case v3
  case v4
}

public enum ActivityOutcome: Sendable {
  case completed
  case declined
  case cancelled
  case failed
  case incomplete
}

public enum ActivityFailureReason: Sendable {
  case networkError
  case timeout
  case deviceAuthenticationFailed
  case proofGenerationFailed
  case relyingPartyRejected
}

public struct ActivityEntry: Sendable {
  public var id: UInt64?
  public var rpId: UInt64
  public var appIdentifier: String
  public var clientId: String
  public var `protocol`: ProtocolVersion
  public var timestamp: UInt64?
  public var outcome: ActivityOutcome
  public var issuerSchemaIds: [UInt64]
  public var failureReason: ActivityFailureReason?
  public init(
    id: UInt64?, rpId: UInt64, appIdentifier: String, clientId: String, protocol: ProtocolVersion,
    timestamp: UInt64?, outcome: ActivityOutcome, issuerSchemaIds: [UInt64],
    failureReason: ActivityFailureReason?
  ) {
    self.id = id
    self.rpId = rpId
    self.appIdentifier = appIdentifier
    self.clientId = clientId
    self.`protocol` = `protocol`
    self.timestamp = timestamp
    self.outcome = outcome
    self.issuerSchemaIds = issuerSchemaIds
    self.failureReason = failureReason
  }
}

public struct ActivityMetadata: Sendable {
  public var totalCount: UInt64
  public init(totalCount: UInt64) {
    self.totalCount = totalCount
  }
}

/// Immutable activity filters; builder methods return a new value.
public struct ActivityQuery: Sendable {
  public let issuerSchemaId: UInt64?
  public init(issuerSchemaId: UInt64? = nil) { self.issuerSchemaId = issuerSchemaId }
  public func withIssuerSchemaId(issuerSchemaId: UInt64) -> Self {
    Self(issuerSchemaId: issuerSchemaId)
  }
}

public enum StorageError: Sendable, Error, CustomStringConvertible {
  case keystore(value0: String)
  case blobStore(value0: String)
  case lock(value0: String)
  case serialization(value0: String)
  case crypto(value0: String)
  case invalidEnvelope(value0: String)
  case invalidInput(value0: String)
  case unsupportedEnvelopeVersion(value0: UInt32)
  case vaultDb(value0: String)
  case cacheDb(value0: String)
  case persistentStorage(value0: String)
  case invalidLeafIndex(expected: UInt64, provided: UInt64)
  case corruptedVault(value0: String)
  case notInitialized
  case nullifierAlreadyDisclosed
  case credentialNotFound
  case credentialIdNotFound(credentialId: UInt64)
  case corruptedCacheEntry(keyPrefix: UInt8)
  case activityDb(value0: String)
  case activityInvalidRecord(value0: String)
  case callback(value0: String)
  public var description: String {
    switch self {
    case .keystore: return "StorageError.Keystore"
    case .blobStore: return "StorageError.BlobStore"
    case .lock: return "StorageError.Lock"
    case .serialization: return "StorageError.Serialization"
    case .crypto: return "StorageError.Crypto"
    case .invalidEnvelope: return "StorageError.InvalidEnvelope"
    case .invalidInput: return "StorageError.InvalidInput"
    case .unsupportedEnvelopeVersion: return "StorageError.UnsupportedEnvelopeVersion"
    case .vaultDb: return "StorageError.VaultDb"
    case .cacheDb: return "StorageError.CacheDb"
    case .persistentStorage: return "StorageError.PersistentStorage"
    case .invalidLeafIndex: return "StorageError.InvalidLeafIndex"
    case .corruptedVault: return "StorageError.CorruptedVault"
    case .notInitialized: return "StorageError.NotInitialized"
    case .nullifierAlreadyDisclosed: return "StorageError.NullifierAlreadyDisclosed"
    case .credentialNotFound: return "StorageError.CredentialNotFound"
    case .credentialIdNotFound: return "StorageError.CredentialIdNotFound"
    case .corruptedCacheEntry: return "StorageError.CorruptedCacheEntry"
    case .activityDb: return "StorageError.ActivityDb"
    case .activityInvalidRecord: return "StorageError.ActivityInvalidRecord"
    case .callback: return "StorageError.Callback"
    }
  }
}

public enum CredentialType: Sendable {
  case orb
  case document
  case secureDocument
  case device
}

public struct RecoveryBinding: Sendable {
  public var recoveryAgent: String?
  public var pendingRecoveryAgent: String?
  public var executeAfter: String?
  public init(recoveryAgent: String?, pendingRecoveryAgent: String?, executeAfter: String?) {
    self.recoveryAgent = recoveryAgent
    self.pendingRecoveryAgent = pendingRecoveryAgent
    self.executeAfter = executeAfter
  }
}

public enum RegistrationStatus: Sendable {
  case queued
  case batching
  case submitted
  case finalized
  case failed(error: String, errorCode: String?)
}

public enum GatewayRequestStatus: Sendable {
  case queued
  case batching
  case submitted(txHash: String)
  case finalized(txHash: String)
  case failed(error: String, errorCode: String?)
}

public struct RecoveryUpdateSignature: Sendable {
  public var signature: Data
  public var nonce: Uint256
  public init(signature: Data, nonce: Uint256) {
    self.signature = signature
    self.nonce = nonce
  }
}

public struct RecoveryData: Sendable {
  public var authenticatorAddress: String
  public var authenticatorPubkey: String
  public var offchainSignerCommitment: String
  public init(
    authenticatorAddress: String, authenticatorPubkey: String, offchainSignerCommitment: String
  ) {
    self.authenticatorAddress = authenticatorAddress
    self.authenticatorPubkey = authenticatorPubkey
    self.offchainSignerCommitment = offchainSignerCommitment
  }
}

public enum FlamingoMatchRequest: Sendable {
  case deepFace(
    orbCredential: Data, live: FlamingoLiveCapture, rtmsChallenge: Data, hashesJson: Data,
    matchThreshold: Double)
  case grayBadge(live: FlamingoLiveCapture, rtmsChallenge: Data, matchThreshold: Double)
}

public enum FlamingoLiveCapture: Sendable {
  case vanilla(image: Data)
  case lightGuard(illuminated: Data, unilluminated: Data, matchingFrame: FlamingoMatchingFrame)
}

public enum FlamingoMatchingFrame: Sendable {
  case illuminated
  case unilluminated
}

public enum FlamingoMatchOutcome: Sendable {
  case matched(token: VerifiedMatchToken, debugReport: FlamingoDebugReport)
  case rejected(reason: FlamingoMatchRejection, debugReport: FlamingoDebugReport)
}

public enum FlamingoDebugReport: Sendable {
  case available(json: String)
  case notProduced
  case omittedTooLarge(originalSizeBytes: UInt64)
}

public enum FlamingoMatchRejection: Sendable {
  case malformedInputs
  case invalidHashesJson
  case thumbnailHashMismatch
  case invalidThreshold
  case inputRejected(
    reason: FlamingoInputFailureReason, image: FlamingoImageRole?, limitBytes: UInt64?)
  case matchBelowThreshold(comparison: FlamingoComparison)
  case imageRejected(
    image: FlamingoImageRole, reason: FlamingoImageFailureReason, target: FlamingoValidationTarget?)
  case matchingFailed(comparison: FlamingoComparison)
  case `internal`
}

public enum FlamingoComparison: Sendable {
  case orbSelfie
  case orbChallenge
  case selfieChallenge
}

public enum FlamingoImageRole: Sendable {
  case orbCredential
  case liveSelfie
  case rtmsChallenge
}

public enum FlamingoError: Sendable, Error, CustomStringConvertible {
  case invalidInput(
    attribute: String, reason: String, kind: FlamingoInputFailureKind, limitBytes: UInt64?)
  case configuration(value0: String)
  case requestIntegrity(value0: RequestIntegrityError)
  case service(code: String, allowRetry: Bool)
  case timeout
  case transport(details: String)
  case invalidResponse(stage: FlamingoResponseStage)
  case attestation(details: String)
  case channel(details: String)
  case invalidSigningKey
  case statementInvalid
  case reassignmentRequired
  public var description: String {
    switch self {
    case .invalidInput: return "FlamingoError.InvalidInput"
    case .configuration: return "FlamingoError.Configuration"
    case .requestIntegrity: return "FlamingoError.RequestIntegrity"
    case .service: return "FlamingoError.Service"
    case .timeout: return "FlamingoError.Timeout"
    case .transport: return "FlamingoError.Transport"
    case .invalidResponse: return "FlamingoError.InvalidResponse"
    case .attestation: return "FlamingoError.Attestation"
    case .channel: return "FlamingoError.Channel"
    case .invalidSigningKey: return "FlamingoError.InvalidSigningKey"
    case .statementInvalid: return "FlamingoError.StatementInvalid"
    case .reassignmentRequired: return "FlamingoError.ReassignmentRequired"
    }
  }
}

public enum FlamingoImageFailureReason: Sendable {
  case invalidImage
  case templateFailed
  case tooManyFaces
  case imageTooDark
  case imageTooBright
  case illuminationVariance
  case faceTooSmall
  case faceTooBig
  case faceResolutionTooLow
  case faceTooHigh
  case faceTooLow
  case faceTooFarLeft
  case faceTooFarRight
  case headPoseYaw
  case headPosePitchTooHigh
  case headPosePitchTooLow
  case headPoseRoll
  case lowQuality
  case sunglassesOcclusionDetected
  case glassesOcclusionDetected
  case maskOcclusionDetected
  case otherOcclusionDetected
  case hairOcclusionDetected
  case fasOcclusionDetected
  case spoofDetected
  case depthSpoofDetected
  case thermalSpoofDetected
  case ageBelowThreshold
  case noFaceDetected
  case eyesClosed
  case nonNeutralExpression
  case landmarksAlignment
  case faceOverexposed
  case faceUnderexposed
  case segmentationOcclusionProportion
  case brightArtifacts
  case lightGuardScoreTooLow
  case lowContrast
  case meshExpressionScore
  case highColorDistortion
  case unevenLighting
  case blurryFace
  case noisyThermalImage
}

public enum FlamingoValidationTarget: Sendable {
  case image
  case illuminatedFrame
  case unilluminatedFrame
  case lightGuardPair
}

public enum FlamingoInputFailureReason: Sendable {
  case missingImage
  case missingSource
  case invalidMatchingFrame
  case emptyImage
  case imageTooLarge
  case totalImagesTooLarge
}

public enum FlamingoInputFailureKind: Sendable {
  case empty
  case tooLarge
  case totalTooLarge
  case invalidThreshold
}

public enum FlamingoResponseStage: Sendable {
  case assignment
  case hostMessage
  case matchResult
}

/// The encoding a ``RequestDigestSigner`` produces.
public enum RequestIntegrityPlatform: Sendable {
  case ios
  case android
}

/// Request-integrity failures without token, key, or native diagnostic contents.
public enum RequestIntegrityError: Sendable, Error, CustomStringConvertible {
  case unavailable
  case invalidSession
  case signingFailed
  case callbackFailed
  case timedOut
  public var description: String {
    switch self {
    case .unavailable: return "RequestIntegrityError.Unavailable"
    case .invalidSession: return "RequestIntegrityError.InvalidSession"
    case .signingFailed: return "RequestIntegrityError.SigningFailed"
    case .callbackFailed: return "RequestIntegrityError.CallbackFailed"
    case .timedOut: return "RequestIntegrityError.TimedOut"
    }
  }
}

/// A token and the signer pinned to the exact key certified by that token.
public struct RequestIntegritySession: Sendable {
  public var token: String
  public var platform: RequestIntegrityPlatform
  public var signer: any RequestDigestSigner
  public init(token: String, platform: RequestIntegrityPlatform, signer: any RequestDigestSigner) {
    self.token = token
    self.platform = platform
    self.signer = signer
  }
}
