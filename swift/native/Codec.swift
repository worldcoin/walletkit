import Foundation

// Binary values exchanged with Rust; the layout is specified in crates/walletkit/src/native/codec.rs
// and the ordinals and variant indices in native/values.rs. Frozen-byte tests: CodecTests.swift.

/// Reads values written by Rust. Handles read before a decoding failure are released by ARC.
struct ByteReader {
  private let input: [UInt8]
  private var offset = 0

  /// Decodes a complete value, rejecting short input and trailing bytes.
  static func decode<T>(_ data: Data, _ read: (inout ByteReader) throws -> T) throws -> T {
    var reader = ByteReader(input: [UInt8](data))
    let value = try read(&reader)
    guard reader.offset == reader.input.count else { throw invalid }
    return value
  }

  private init(input: [UInt8]) { self.input = input }

  private mutating func take(_ count: Int) throws -> ArraySlice<UInt8> {
    guard count >= 0, count <= input.count - offset else { throw invalid }
    defer { offset += count }
    return input[offset..<offset + count]
  }
  private mutating func integer<T: FixedWidthInteger>(_: T.Type) throws -> T {
    try take(MemoryLayout<T>.size).reversed().reduce(0) { $0 << 8 | T($1) }
  }
  mutating func u8() throws -> UInt8 { try integer(UInt8.self) }
  mutating func u16() throws -> UInt16 { try integer(UInt16.self) }
  mutating func u32() throws -> UInt32 { try integer(UInt32.self) }
  mutating func u64() throws -> UInt64 { try integer(UInt64.self) }
  mutating func f32() throws -> Float { Float(bitPattern: try u32()) }
  mutating func f64() throws -> Double { Double(bitPattern: try u64()) }
  mutating func bool() throws -> Bool {
    switch try u8() {
    case 0: return false
    case 1: return true
    default: throw invalid
    }
  }
  mutating func bytes() throws -> Data { Data(try take(Int(try u32()))) }
  // Rust strings are valid UTF-8, so decoding does not need validation.
  mutating func string() throws -> String {
    String(decoding: try take(Int(try u32())), as: UTF8.self)
  }
  mutating func uint256() throws -> Uint256 { try Uint256(bytes: Data(try take(32))) }
  mutating func handle() throws -> NativeHandle { NativeHandle(try u64()) }
  mutating func optional<T>(_ read: (inout ByteReader) throws -> T) throws -> T? {
    switch try u8() {
    case 0: return nil
    case 1: return try read(&self)
    default: throw invalid
    }
  }
  mutating func list<T>(_ read: (inout ByteReader) throws -> T) throws -> [T] {
    let count = Int(try u32())
    guard count <= input.count - offset else { throw invalid }
    return try (0..<count).map { _ in try read(&self) }
  }
  mutating func element<T>(_ values: [T]) throws -> T {
    let index = Int(try u8())
    guard index < values.count else { throw invalid }
    return values[index]
  }
}

private let invalid = WalletKitBridgeError(code: "InvalidResponse")

/// Writes values for Rust to read.
struct ByteWriter {
  private(set) var data = Data()

  static func encode(_ write: (inout ByteWriter) throws -> Void) rethrows -> Data {
    var writer = ByteWriter()
    try write(&writer)
    return writer.data
  }

  mutating func u8(_ value: UInt8) { data.append(value) }
  mutating func u32(_ value: UInt32) {
    withUnsafeBytes(of: value.littleEndian) { data.append(contentsOf: $0) }
  }
  mutating func u64(_ value: UInt64) {
    withUnsafeBytes(of: value.littleEndian) { data.append(contentsOf: $0) }
  }
  mutating func f64(_ value: Double) { u64(value.bitPattern) }
  mutating func bytes(_ value: Data) {
    u32(UInt32(value.count))
    data.append(value)
  }
  mutating func string(_ value: String) { bytes(Data(value.utf8)) }
  mutating func optional<T>(_ value: T?, _ write: (inout ByteWriter, T) -> Void) {
    guard let value else { return u8(0) }
    u8(1)
    write(&self, value)
  }
  mutating func list<T>(_ values: [T], _ write: (inout ByteWriter, T) -> Void) {
    u32(UInt32(values.count))
    for value in values { write(&self, value) }
  }
  mutating func ordinal<T: Equatable>(_ value: T, in values: [T]) {
    u8(UInt8(values.firstIndex(of: value)!))
  }
}

// Fieldless enumerations in their frozen ordinal order.
extension LogLevel { static let ordinals: [Self] = [.trace, .debug, .info, .warn, .error] }
extension Environment { static let ordinals: [Self] = [.staging, .production] }
extension Region { static let ordinals: [Self] = [.us, .eu, .ap] }
extension CredentialType {
  static let ordinals: [Self] = [.orb, .document, .secureDocument, .device]
}
extension ProtocolVersion { static let ordinals: [Self] = [.v3, .v4] }
extension ActivityOutcome {
  static let ordinals: [Self] = [.completed, .declined, .cancelled, .failed, .incomplete]
}
extension ActivityFailureReason {
  static let ordinals: [Self] = [
    .networkError, .timeout, .deviceAuthenticationFailed, .proofGenerationFailed,
    .relyingPartyRejected,
  ]
}
extension FlamingoMatchingFrame { static let ordinals: [Self] = [.illuminated, .unilluminated] }
extension FlamingoComparison {
  static let ordinals: [Self] = [.orbSelfie, .orbChallenge, .selfieChallenge]
}
extension FlamingoImageRole {
  static let ordinals: [Self] = [.orbCredential, .liveSelfie, .rtmsChallenge]
}
extension FlamingoImageFailureReason {
  static let ordinals: [Self] = [
    .invalidImage, .templateFailed, .tooManyFaces, .imageTooDark, .imageTooBright,
    .illuminationVariance, .faceTooSmall, .faceTooBig, .faceResolutionTooLow, .faceTooHigh,
    .faceTooLow, .faceTooFarLeft, .faceTooFarRight, .headPoseYaw, .headPosePitchTooHigh,
    .headPosePitchTooLow, .headPoseRoll, .lowQuality, .sunglassesOcclusionDetected,
    .glassesOcclusionDetected, .maskOcclusionDetected, .otherOcclusionDetected,
    .hairOcclusionDetected, .fasOcclusionDetected, .spoofDetected, .depthSpoofDetected,
    .thermalSpoofDetected, .ageBelowThreshold, .noFaceDetected, .eyesClosed,
    .nonNeutralExpression, .landmarksAlignment, .faceOverexposed, .faceUnderexposed,
    .segmentationOcclusionProportion, .brightArtifacts, .lightGuardScoreTooLow, .lowContrast,
    .meshExpressionScore, .highColorDistortion, .unevenLighting, .blurryFace,
    .noisyThermalImage,
  ]
}
extension FlamingoValidationTarget {
  static let ordinals: [Self] = [
    .image, .illuminatedFrame, .unilluminatedFrame, .lightGuardPair,
  ]
}
extension FlamingoInputFailureReason {
  static let ordinals: [Self] = [
    .missingImage, .missingSource, .invalidMatchingFrame, .emptyImage, .imageTooLarge,
    .totalImagesTooLarge,
  ]
}
extension FlamingoInputFailureKind {
  static let ordinals: [Self] = [.empty, .tooLarge, .totalTooLarge, .invalidThreshold]
}
extension FlamingoResponseStage {
  static let ordinals: [Self] = [.assignment, .hostMessage, .matchResult]
}
extension RequestIntegrityPlatform { static let ordinals: [Self] = [.ios, .android] }
extension RequestIntegrityError {
  static let ordinals: [Self] = [
    .unavailable, .invalidSession, .signingFailed, .callbackFailed, .timedOut,
  ]
}

/// The ordinal of a fieldless enumeration value.
func ordinal<T: Equatable>(_ value: T, in values: [T]) -> UInt8 {
  UInt8(values.firstIndex(of: value)!)
}

/// The value of an ordinal returned by Rust.
func element<T>(_ ordinal: UInt8, of values: [T]) throws -> T {
  guard Int(ordinal) < values.count else { throw invalid }
  return values[Int(ordinal)]
}

func decodeNativeError(_ data: Data) throws -> any Error {
  try ByteReader.decode(data) { reader -> any Error in
    switch try reader.u8() {
    case 0:
      let code = try reader.string()
      return code == "Cancelled" ? CancellationError() : WalletKitBridgeError(code: code)
    case 1: return try WalletKitError.read(&reader)
    case 2: return try StorageError.read(&reader)
    case 3: return try FlamingoError.read(&reader)
    case 4: return try CredentialConstraintsCheckError.read(&reader)
    default: return WalletKitBridgeError(code: "UnknownErrorDomain")
    }
  }
}

extension CredentialConstraintsCheckResult {
  static func read(_ reader: inout ByteReader) throws -> Self {
    Self(
      isSatisfied: try reader.bool(),
      checkResults: try reader.list {
        CredentialConstraintsCheckItem(
          identifier: try $0.string(), issuerSchemaId: try $0.u64(), hasCredential: try $0.bool())
      })
  }
}

extension CredentialRecord {
  static func read(_ reader: inout ByteReader) throws -> Self {
    Self(
      credentialId: try reader.u64(), issuerSchemaId: try reader.u64(),
      genesisIssuedAt: try reader.u64(), expiresAt: try reader.u64(), isExpired: try reader.bool())
  }
}

extension ActivityEntry {
  static func read(_ reader: inout ByteReader) throws -> Self {
    Self(
      id: try reader.optional { try $0.u64() },
      rpId: try reader.u64(),
      appIdentifier: try reader.string(),
      clientId: try reader.string(),
      protocol: try reader.element(ProtocolVersion.ordinals),
      timestamp: try reader.optional { try $0.u64() },
      outcome: try reader.element(ActivityOutcome.ordinals),
      issuerSchemaIds: try reader.list { try $0.u64() },
      failureReason: try reader.optional { try $0.element(ActivityFailureReason.ordinals) })
  }

  func write(_ writer: inout ByteWriter) {
    writer.optional(id) { $0.u64($1) }
    writer.u64(rpId)
    writer.string(appIdentifier)
    writer.string(clientId)
    writer.ordinal(self.protocol, in: ProtocolVersion.ordinals)
    writer.optional(timestamp) { $0.u64($1) }
    writer.ordinal(outcome, in: ActivityOutcome.ordinals)
    writer.list(issuerSchemaIds) { $0.u64($1) }
    writer.optional(failureReason) { $0.ordinal($1, in: ActivityFailureReason.ordinals) }
  }
}

extension RecoveryBinding {
  static func read(_ reader: inout ByteReader) throws -> Self {
    Self(
      recoveryAgent: try reader.optional { try $0.string() },
      pendingRecoveryAgent: try reader.optional { try $0.string() },
      executeAfter: try reader.optional { try $0.string() })
  }
}

extension RecoveryUpdateSignature {
  static func read(_ reader: inout ByteReader) throws -> Self {
    Self(signature: try reader.bytes(), nonce: try reader.uint256())
  }
}

extension RecoveryData {
  static func read(_ reader: inout ByteReader) throws -> Self {
    Self(
      authenticatorAddress: try reader.string(), authenticatorPubkey: try reader.string(),
      offchainSignerCommitment: try reader.string())
  }
}

extension RegistrationStatus {
  static func read(_ reader: inout ByteReader) throws -> Self {
    switch try reader.u8() {
    case 0: return .queued
    case 1: return .batching
    case 2: return .submitted
    case 3: return .finalized
    case 4:
      return .failed(error: try reader.string(), errorCode: try reader.optional { try $0.string() })
    default: throw invalid
    }
  }
}

extension GatewayRequestStatus {
  static func read(_ reader: inout ByteReader) throws -> Self {
    switch try reader.u8() {
    case 0: return .queued
    case 1: return .batching
    case 2: return .submitted(txHash: try reader.string())
    case 3: return .finalized(txHash: try reader.string())
    case 4:
      return .failed(error: try reader.string(), errorCode: try reader.optional { try $0.string() })
    default: throw invalid
    }
  }
}

extension FlamingoMatchRequest {
  func write(_ writer: inout ByteWriter) {
    switch self {
    case .deepFace(let orbCredential, let live, let rtmsChallenge, let hashesJson, let threshold):
      writer.u8(0)
      writer.bytes(orbCredential)
      live.write(&writer)
      writer.bytes(rtmsChallenge)
      writer.bytes(hashesJson)
      writer.f64(threshold)
    case .grayBadge(let live, let rtmsChallenge, let threshold):
      writer.u8(1)
      live.write(&writer)
      writer.bytes(rtmsChallenge)
      writer.f64(threshold)
    }
  }
}

extension FlamingoLiveCapture {
  func write(_ writer: inout ByteWriter) {
    switch self {
    case .vanilla(let image):
      writer.u8(0)
      writer.bytes(image)
    case .lightGuard(let illuminated, let unilluminated, let matchingFrame):
      writer.u8(1)
      writer.bytes(illuminated)
      writer.bytes(unilluminated)
      writer.ordinal(matchingFrame, in: FlamingoMatchingFrame.ordinals)
    }
  }
}

func writeStringMap(_ values: [String: String], _ writer: inout ByteWriter) {
  writer.u32(UInt32(values.count))
  for (key, value) in values {
    writer.string(key)
    writer.string(value)
  }
}

func writeMeasurements(_ values: [UInt32: Data], _ writer: inout ByteWriter) {
  writer.u32(UInt32(values.count))
  for (key, value) in values {
    writer.u32(key)
    writer.bytes(value)
  }
}

extension FlamingoMatchOutcome {
  static func read(_ reader: inout ByteReader) throws -> Self {
    switch try reader.u8() {
    case 0:
      return .matched(
        token: VerifiedMatchToken(handle: try reader.handle()),
        debugReport: try FlamingoDebugReport.read(&reader))
    case 1:
      return .rejected(
        reason: try FlamingoMatchRejection.read(&reader),
        debugReport: try FlamingoDebugReport.read(&reader))
    default: throw invalid
    }
  }
}

extension FlamingoDebugReport {
  static func read(_ reader: inout ByteReader) throws -> Self {
    switch try reader.u8() {
    case 0: return .available(json: try reader.string())
    case 1: return .notProduced
    case 2: return .omittedTooLarge(originalSizeBytes: try reader.u64())
    default: throw invalid
    }
  }
}

extension FlamingoMatchRejection {
  static func read(_ reader: inout ByteReader) throws -> Self {
    switch try reader.u8() {
    case 0: return .malformedInputs
    case 1: return .invalidHashesJson
    case 2: return .thumbnailHashMismatch
    case 3: return .invalidThreshold
    case 4:
      return .inputRejected(
        reason: try reader.element(FlamingoInputFailureReason.ordinals),
        image: try reader.optional { try $0.element(FlamingoImageRole.ordinals) },
        limitBytes: try reader.optional { try $0.u64() })
    case 5: return .matchBelowThreshold(comparison: try reader.element(FlamingoComparison.ordinals))
    case 6:
      return .imageRejected(
        image: try reader.element(FlamingoImageRole.ordinals),
        reason: try reader.element(FlamingoImageFailureReason.ordinals),
        target: try reader.optional { try $0.element(FlamingoValidationTarget.ordinals) })
    case 7: return .matchingFailed(comparison: try reader.element(FlamingoComparison.ordinals))
    case 8: return .internal
    default: throw invalid
    }
  }
}

extension WalletKitError {
  // One case per frozen variant index.
  // swiftlint:disable:next cyclomatic_complexity function_body_length
  static func read(_ reader: inout ByteReader) throws -> Self {
    switch try reader.u8() {
    case 0: return .storage(value0: try StorageError.read(&reader))
    case 1: return .invalidInput(attribute: try reader.string(), reason: try reader.string())
    case 2: return .invalidNumber
    case 3: return .serializationError(error: try reader.string())
    case 4:
      return .networkError(
        url: try reader.string(), error: try reader.string(),
        status: try reader.optional { try $0.u16() })
    case 5: return .reqwest(error: try reader.string())
    case 6: return .proofGeneration(error: try reader.string())
    case 7: return .semaphoreNotEnabled
    case 8: return .credentialNotIssued
    case 9: return .credentialNotMined
    case 10: return .accountDoesNotExist
    case 11: return .unauthorizedAuthenticator
    case 12: return .authenticatorError(error: try reader.string())
    case 13: return .unfulfillableRequest
    case 14: return .responseValidation(value0: try reader.string())
    case 15: return .nullifierReplay
    case 16: return .invalidRpSignature
    case 17: return .duplicateNonce
    case 18: return .unknownRp
    case 19: return .inactiveRp
    case 20: return .timestampTooOld
    case 21: return .timestampTooFarInFuture
    case 22: return .invalidTimestamp
    case 23: return .rpSignatureExpired
    case 24:
      return .groth16MaterialCacheInvalid(path: try reader.string(), error: try reader.string())
    case 25: return .groth16MaterialEmbeddedLoad(error: try reader.string())
    case 26: return .generic(error: try reader.string())
    case 27: return .recoveryBindingDoesNotExist
    case 28: return .sessionIdMismatch
    case 29: return .nfcNonRetryable(errorCode: try reader.string())
    case 30: return .debugReportNotFound
    case 31: return .identityNotFound
    case 32: return .noSuccessfulCaptureFound
    case 33: return .notEligibleForRecovery
    case 34: return .ohttpError(error: try reader.string())
    case 35: return .invalidActionSession
    default: throw invalid
    }
  }
}

extension StorageError {
  // swiftlint:disable:next cyclomatic_complexity
  static func read(_ reader: inout ByteReader) throws -> Self {
    switch try reader.u8() {
    case 0: return .keystore(value0: try reader.string())
    case 1: return .blobStore(value0: try reader.string())
    case 2: return .lock(value0: try reader.string())
    case 3: return .serialization(value0: try reader.string())
    case 4: return .crypto(value0: try reader.string())
    case 5: return .invalidEnvelope(value0: try reader.string())
    case 6: return .invalidInput(value0: try reader.string())
    case 7: return .unsupportedEnvelopeVersion(value0: try reader.u32())
    case 8: return .vaultDb(value0: try reader.string())
    case 9: return .cacheDb(value0: try reader.string())
    case 10: return .persistentStorage(value0: try reader.string())
    case 11: return .invalidLeafIndex(expected: try reader.u64(), provided: try reader.u64())
    case 12: return .corruptedVault(value0: try reader.string())
    case 13: return .notInitialized
    case 14: return .nullifierAlreadyDisclosed
    case 15: return .credentialNotFound
    case 16: return .credentialIdNotFound(credentialId: try reader.u64())
    case 17: return .corruptedCacheEntry(keyPrefix: try reader.u8())
    case 18: return .activityDb(value0: try reader.string())
    case 19: return .activityInvalidRecord(value0: try reader.string())
    case 20: return .callback(value0: try reader.string())
    default: throw invalid
    }
  }

  /// Host callbacks report storage failures to Rust in the same encoding.
  // swiftlint:disable:next cyclomatic_complexity
  func write(_ writer: inout ByteWriter) {
    func message(_ index: UInt8, _ value: String) {
      writer.u8(index)
      writer.string(value)
    }
    switch self {
    case .keystore(let value): message(0, value)
    case .blobStore(let value): message(1, value)
    case .lock(let value): message(2, value)
    case .serialization(let value): message(3, value)
    case .crypto(let value): message(4, value)
    case .invalidEnvelope(let value): message(5, value)
    case .invalidInput(let value): message(6, value)
    case .unsupportedEnvelopeVersion(let version):
      writer.u8(7)
      writer.u32(version)
    case .vaultDb(let value): message(8, value)
    case .cacheDb(let value): message(9, value)
    case .persistentStorage(let value): message(10, value)
    case .invalidLeafIndex(let expected, let provided):
      writer.u8(11)
      writer.u64(expected)
      writer.u64(provided)
    case .corruptedVault(let value): message(12, value)
    case .notInitialized: writer.u8(13)
    case .nullifierAlreadyDisclosed: writer.u8(14)
    case .credentialNotFound: writer.u8(15)
    case .credentialIdNotFound(let credentialId):
      writer.u8(16)
      writer.u64(credentialId)
    case .corruptedCacheEntry(let keyPrefix):
      writer.u8(17)
      writer.u8(keyPrefix)
    case .activityDb(let value): message(18, value)
    case .activityInvalidRecord(let value): message(19, value)
    case .callback(let value): message(20, value)
    }
  }
}

extension FlamingoError {
  static func read(_ reader: inout ByteReader) throws -> Self {
    switch try reader.u8() {
    case 0:
      return .invalidInput(
        attribute: try reader.string(), reason: try reader.string(),
        kind: try reader.element(FlamingoInputFailureKind.ordinals),
        limitBytes: try reader.optional { try $0.u64() })
    case 1: return .configuration(value0: try reader.string())
    case 2: return .requestIntegrity(value0: try reader.element(RequestIntegrityError.ordinals))
    case 3: return .service(code: try reader.string(), allowRetry: try reader.bool())
    case 4: return .timeout
    case 5: return .transport(details: try reader.string())
    case 6: return .invalidResponse(stage: try reader.element(FlamingoResponseStage.ordinals))
    case 7: return .attestation(details: try reader.string())
    case 8: return .channel(details: try reader.string())
    case 9: return .invalidSigningKey
    case 10: return .statementInvalid
    case 11: return .reassignmentRequired
    default: throw invalid
    }
  }
}

extension CredentialConstraintsCheckError {
  static func read(_ reader: inout ByteReader) throws -> Self {
    switch try reader.u8() {
    case 0: return .storage(value0: try StorageError.read(&reader))
    case 1: return .constraintTooDeep
    case 2: return .constraintTooLarge
    default: throw invalid
    }
  }
}
